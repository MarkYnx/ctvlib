use lazy_static::lazy_static;
use std::clone;
use std::str::FromStr;

use bitcoin::script::Builder;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::{self, LeafVersion, TaprootBuilder, TaprootSpendInfo};
use bitcoin::{
    key::{Keypair, Secp256k1},
    secp256k1::{All, Message, SecretKey},
    Address, EcdsaSighashType, PrivateKey, PublicKey, SegwitV0Sighash, XOnlyPublicKey,
};
use bitcoin::{
    opcodes::all::OP_NOP4, script::PushBytesBuf, transaction::Version, Amount, ScriptBuf,
    Transaction, TxOut,
};
use bitcoin::{Network, OutPoint, TxIn, Txid, Witness};
use secp256k1::{rand, SECP256K1};

use crate::bitcoin_sdk::UTXO;
use crate::{Error, TemplateHash};

pub struct Params {
    pub depoist_amt: Amount,
    pub stake_amt: Amount,
    pub gas_amt: Amount,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            depoist_amt: Amount::from_btc(2.0).expect(""),
            stake_amt: Amount::from_btc(1.0).expect(""),
            gas_amt: Amount::from_sat(1500),
        }
    }
}

lazy_static! {
    pub static ref UNSPENDABLE_TAPROOT_PUBLIC_KEY: XOnlyPublicKey = XOnlyPublicKey::from_str(
        "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51"
    )
    .unwrap();
}

#[derive(Clone)]
pub struct TaprootInfo {
    pub address: Address,
    pub scripts: Vec<ScriptBuf>,
    pub taproot_spend_info: TaprootSpendInfo,
}

pub fn build_taptree_with_script(
    scripts: Vec<ScriptBuf>,
    network: Network,
) -> Result<TaprootInfo, Error> {
    let n = scripts.len();
    let taproot_builder = if n > 1 {
        let m: u8 = ((n - 1).ilog2() + 1) as u8; // m = ceil(log(n))
        let k = 2_usize.pow(m.into()) - n;
        (0..n).fold(TaprootBuilder::new(), |acc, i| {
            acc.add_leaf(m - ((i >= n - k) as u8), scripts[i].clone()).unwrap()
        })
    } else {
        TaprootBuilder::new().add_leaf(0, scripts[0].clone()).unwrap()
    };
    let taproot_spend_info = taproot_builder
        .finalize(SECP256K1, *UNSPENDABLE_TAPROOT_PUBLIC_KEY)
        .expect("msg");

    let secp: Secp256k1<All> = Secp256k1::new();
    let address = Address::p2tr(
        &secp,
        *UNSPENDABLE_TAPROOT_PUBLIC_KEY,
        taproot_spend_info.merkle_root(),
        network,
    );

    Ok(TaprootInfo {
        address: address.clone(),
        scripts,
        taproot_spend_info,
    })
}

fn taproot_spend_info(
    locking_scripts: Vec<ScriptBuf>,
    index: usize,
    internal_key: XOnlyPublicKey,
) -> Result<TaprootSpendInfo, Error> {
    let n = locking_scripts.len();
    let m: u8 = ((n - 1).ilog2() + 1) as u8; // m = ceil(log(n))
    let k = 2_usize.pow(m.into()) - n;
    TaprootBuilder::new()
        .add_leaf(m - ((index >= n - k) as u8), locking_scripts[index].clone())?
        .finalize(SECP256K1, internal_key)
        .map_err(|e|  {
            println!("{:?}", e);
            Error::UnknownError("Taproot not finalizable".into())})
}

pub struct TransactionGraph {
    kickoff: Transaction,
    happy_take: Transaction,

    challenge: Transaction,
    assert: Transaction,
    disprove: Transaction,

    taproot_info: TaprootInfo,
}

impl TransactionGraph {
    fn dummy_utxo() -> UTXO {
        UTXO {
            outpoint: OutPoint {
                txid: Txid::from_str(
                    "defc8c2634291f74cf42dc16508b091d4a1ce1fb27f5a6861fe922e42a3c898b",
                )
                .expect(""),
                vout: 0,
            },
            amount: Amount::ZERO,
        }
    }
    fn dummy_input() -> TxIn {
        TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(
                    "defc8c2634291f74cf42dc16508b091d4a1ce1fb27f5a6861fe922e42a3c898b",
                )
                .expect(""),
                vout: 0,
            },
            sequence: bitcoin::Sequence(0xFFFFFFFF),
            script_sig: Builder::new().into_script(),
            witness: Witness::new(),
        }
    }

    pub fn create_btc_tx(ins: &Vec<UTXO>, outs: Vec<(ScriptBuf, Amount)>) -> Transaction {
        let input = ins
            .into_iter()
            .map(|i| TxIn {
                previous_output: i.outpoint,
                sequence: bitcoin::Sequence(0xFFFFFFFF),
                script_sig: Builder::new().into_script(),
                witness: Witness::new(),
            })
            .collect();

        let output = outs
            .into_iter()
            .map(|o| TxOut {
                script_pubkey: o.0,
                value: o.1,
            })
            .collect();

        Transaction {
            version: Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input,
            output,
        }
    }
    fn calc_locking_script(tmplhash: Vec<u8>) -> Result<ScriptBuf, Error> {
        let mut pbf = PushBytesBuf::new();
        pbf.extend_from_slice(&tmplhash)?;
        Ok(bitcoin::script::Builder::new()
            .push_slice(pbf)
            .push_opcode(OP_NOP4)
            .into_script())
    }

    pub fn new(operator: &Address, params: &Params) -> Self {
        let happy_take_output = TxOut {
            value: params.depoist_amt + params.stake_amt
                - params.gas_amt
                - params.gas_amt
                - params.gas_amt, // for pegin, kickoff, happytake
            script_pubkey: operator.script_pubkey(),
        };
        let happy_take = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Self::dummy_input()], // it should be modified on demand
            output: vec![happy_take_output],
        };

        let happy_take_ctv_hash = happy_take.template_hash(0).expect("calc ctv hash");
        let lock_script_for_happy_take_input0 =
            Self::calc_locking_script(happy_take_ctv_hash).expect("calc lock script");

        let disprove = {
            let value = params.depoist_amt.to_sat() + params.stake_amt.to_sat()
                - params.gas_amt.to_sat() * 5;
            let ins = vec![TransactionGraph::dummy_utxo()];
            let anchor_script_pubkey = ScriptBuf::from_hex("51024e73")
                    .expect("statically valid script");
            let outs = vec![(anchor_script_pubkey.clone(), Amount::from_sat(value/2)), (anchor_script_pubkey, Amount::from_sat(value-value/2))];
            TransactionGraph::create_btc_tx(&ins, outs)
        };

        let assert = {
            let value = params.depoist_amt.to_sat() + params.stake_amt.to_sat()
                - params.gas_amt.to_sat() * 4;
            let ins = vec![TransactionGraph::dummy_utxo()];
            let disprove_ctv_hash = disprove.template_hash(0).expect("calc ctv hash");
            let lock_script =
                Self::calc_locking_script(disprove_ctv_hash).expect("calc lock script");
            let outs = vec![(lock_script, Amount::from_sat(value))];
            TransactionGraph::create_btc_tx(&ins, outs)
        };

        let challenge = {
            let value = params.depoist_amt.to_sat() + params.stake_amt.to_sat()
                - params.gas_amt.to_sat() * 3;
            let ins = vec![TransactionGraph::dummy_utxo()];
            let assert_ctv_hash = assert.template_hash(0).expect("calc ctv hash");
            let lock_script = Self::calc_locking_script(assert_ctv_hash).expect("calc lock script");
            let outs = vec![(lock_script, Amount::from_sat(value))];
            TransactionGraph::create_btc_tx(&ins, outs)
        };

        let challenge_ctv_hash = challenge.template_hash(0).expect("calc ctv hash");
        let lock_script_for_challenge_input0 =
            Self::calc_locking_script(challenge_ctv_hash).expect("calc lock script");

        let taproot_info = build_taptree_with_script(
            vec![
                lock_script_for_happy_take_input0.clone(),
                lock_script_for_challenge_input0,
            ],
            Network::Regtest,
        )
        .expect("build success");

        let kickoff_output = TxOut {
            value: params.depoist_amt + params.stake_amt - params.gas_amt - params.gas_amt, // for pegin, kickoff
            script_pubkey: taproot_info.address.script_pubkey(),
            // script_pubkey: lock_script_for_happy_take_input0
        };

        let kickoff = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![Self::dummy_input(), Self::dummy_input()], // it should be modified on demand
            output: vec![kickoff_output],
        };
        Self {
            kickoff,
            happy_take,

            challenge,
            assert,
            disprove,
            taproot_info
        }
    }

    pub fn get_first_script(&self) -> Result<ScriptBuf, Error> {
        let kickoff_ctv_hash = self
            .kickoff
            .template_hash(0)
            .expect("calc kickoff ctv hash");
        Self::calc_locking_script(kickoff_ctv_hash)
    }

    pub fn get_kickoff_tx(
        &self,
        pegin_utxo: UTXO,
        stake_utxo: UTXO,
        signer: &SignerInfo,
    ) -> Transaction {
        let mut tx = self.kickoff.clone();
        // replace input
        tx.input[0].previous_output = pegin_utxo.outpoint;
        tx.input[1].previous_output = stake_utxo.outpoint;

        let hash_tx = tx.clone();
        let mut sighash_cache = SighashCache::new(&hash_tx);
        let utxos = vec![pegin_utxo, stake_utxo];
        for input_index in 1..2 {
            let sighash = sighash_cache
                .p2wpkh_signature_hash(
                    input_index,
                    &signer.address.script_pubkey(),
                    utxos[input_index].amount,
                    bitcoin::sighash::EcdsaSighashType::All,
                )
                .unwrap();

            let signature = signer.sign_ecdsa(sighash, bitcoin::sighash::EcdsaSighashType::All);
            let mut witness = Witness::new();
            witness.push(signature);
            witness.push(signer.get_pk());

            tx.input[input_index].witness = witness;
        }

        tx
    }

    pub fn get_happy_take_tx(&self, kickoff_utxo: UTXO) -> Transaction {
        let mut tx = self.happy_take.clone();
        // replace input
        tx.input[0].previous_output = kickoff_utxo.outpoint;

        let happy_take_script = self.taproot_info.scripts[0].clone();
        let tsi = self.taproot_info.clone();
        let cb = tsi 
            .taproot_spend_info.control_block(&(happy_take_script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| Error::UnknownError("Taproot construction error".into())).expect("get control block");
        tx.input[0].witness.push(happy_take_script);
        tx.input[0].witness.push(cb.serialize());

        tx
    }

    pub fn get_challenge_tx(&self, kickoff_utxo: UTXO) -> Transaction {
        let mut tx = self.challenge.clone();
        // replace input
        tx.input[0].previous_output = kickoff_utxo.outpoint;

        let challenge_script = self.taproot_info.scripts[1].clone();
        let tsi = self.taproot_info.clone();
        let cb = tsi 
            .taproot_spend_info.control_block(&(challenge_script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| Error::UnknownError("Taproot construction error".into())).expect("get control block");
        tx.input[0].witness.push(challenge_script);
        tx.input[0].witness.push(cb.serialize());

        tx
    }

    pub fn get_assert_tx(&self, kickoff_utxo: UTXO) -> Transaction {
        let mut tx = self.assert.clone();
        // replace input
        tx.input[0].previous_output = kickoff_utxo.outpoint;

        tx
    }

    pub fn get_disprove_tx(&self, kickoff_utxo: UTXO, receiver: &SignerInfo) -> (Transaction, Transaction) {
        let mut tx = self.disprove.clone();
        // replace input
        tx.input[0].previous_output = kickoff_utxo.outpoint;

        let params = Params::default();
        let amount = tx.output[0].value + tx.output[1].value - params.gas_amt;
        let anchor_utxo = UTXO {
            outpoint: OutPoint {
                txid: tx.txid(),
                vout: 0,
            },
            amount: tx.output[0].value
        };
        let anchor_utxo1 = UTXO {
            outpoint: OutPoint {
                txid: tx.txid(),
                vout: 1,
            },
            amount: tx.output[1].value,
        };
        let ins = vec![anchor_utxo, anchor_utxo1];
        let reward_tx = Self::create_btc_tx(&ins, vec![(receiver.address.script_pubkey(), amount)]);

        (tx, reward_tx)
    }
}

#[derive(Clone)]
pub struct SignerInfo {
    pub secp: Secp256k1<All>,
    pub pk: PublicKey,
    pub sk: SecretKey,
    pub keypair: Keypair,
    pub address: Address,
    pub xonly_pk: XOnlyPublicKey,
}

impl SignerInfo {
    fn generate_signer_info(
        sk: SecretKey,
        secp: Secp256k1<All>,
        network: bitcoin::Network,
    ) -> Self {
        let private_key = PrivateKey::new(sk, network);
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly_pk, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let pubkey = PublicKey::from_private_key(&secp, &private_key);
        let address = Address::p2wpkh(&pubkey, network).expect("msg");
        SignerInfo {
            pk: private_key.public_key(&secp),
            secp,
            sk,
            keypair,
            address,
            xonly_pk,
        }
    }
    pub fn new(network: bitcoin::Network) -> Self {
        let secp: Secp256k1<All> = Secp256k1::new();
        let (sk, _) = secp.generate_keypair(&mut rand::thread_rng());

        Self::generate_signer_info(sk, secp, network)
    }

    fn get_pk(&self) -> Vec<u8> {
        self.pk.to_bytes().clone()
    }

    fn sign_ecdsa(&self, hash: SegwitV0Sighash, sign_type: EcdsaSighashType) -> Vec<u8> {
        let msg = Message::from_digest_slice(&hash[..]).expect("should be SegwitV0Sighash");
        let signature = self.secp.sign_ecdsa(&msg, &self.sk);
        let mut vec = signature.serialize_der().to_vec();
        vec.push(sign_type.to_u32() as u8);
        vec
    }
}

pub struct Pegin {
    previous_output: OutPoint,
    amt: Amount,

    pegin: Transaction,
}

impl Pegin {
    pub fn new(
        previous_output: OutPoint,
        amt: Amount,
        first_script: ScriptBuf,
        params: &Params,
    ) -> Self {
        let input = TxIn {
            previous_output: previous_output.clone(),
            sequence: bitcoin::Sequence(0xFFFFFFFF),
            script_sig: Builder::new().into_script(),
            witness: Witness::new(),
        };
        let output = TxOut {
            script_pubkey: first_script,
            value: amt - params.gas_amt,
        };
        let pegin = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![input.clone()], // it should be modified on demand
            output: vec![output],
        };

        Self {
            previous_output,
            amt,
            pegin,
        }
    }

    pub fn sign(&self, signer: &SignerInfo) -> Transaction {
        let mut tx = self.pegin.clone();
        let mut sighash_cache = SighashCache::new(&tx);
        let mut input_index = 0 as usize;
        let sighash = sighash_cache
            .p2wpkh_signature_hash(
                input_index,
                &signer.address.script_pubkey(),
                self.amt,
                bitcoin::sighash::EcdsaSighashType::All,
            )
            .unwrap();

        let signature = signer.sign_ecdsa(sighash, bitcoin::sighash::EcdsaSighashType::All);
        let mut witness = Witness::new();
        witness.push(signature);
        witness.push(signer.get_pk());

        tx.input[input_index].witness = witness;
        tx
    }
}

mod test {
    use bitcoin::{
        transaction::{self, Version},
        Amount, Network, OutPoint, Transaction, TxIn,
    };
    use local_ip_address::local_ip;

    use crate::bitcoin_sdk::{RPCClient, UTXO};

    use super::{Params, Pegin, SignerInfo, TransactionGraph};

    // pegin -> kickoff -> happytake
    #[test]
    fn test_transaction_graph_happy_path() {
        let params = Params::default();
        let operator_siggner = SignerInfo::new(bitcoin::Network::Regtest);
        let transaction_graph = TransactionGraph::new(&operator_siggner.address, &params);
        let kickoff_script = transaction_graph
            .get_first_script()
            .expect("get first script");

        let url = format!("{}:18443", local_ip().expect("find one").to_string());
        let user = "admin".to_string();
        let password = "admin".to_string();

        let client = RPCClient::new(&url, &user, &password);
        let params = Params::default();
        let utxo = client.prepare_utxo_for_address(params.depoist_amt, &operator_siggner.address);
        let pegin = Pegin::new(utxo.outpoint, utxo.amount, kickoff_script, &params);
        let pegin_tx = pegin.sign(&operator_siggner);
        let pegin_txid = client.send_transaction(&pegin_tx).expect("success");
        println!("pegin txid: {}", pegin_txid);
        let pegin_utxo = UTXO {
            outpoint: OutPoint {
                txid: pegin_txid,
                vout: 0,
            },
            amount: pegin_tx.output[0].value,
        };
        let stake_utxo =
            client.prepare_utxo_for_address(params.stake_amt, &operator_siggner.address);
        let kickoff_tx =
            transaction_graph.get_kickoff_tx(pegin_utxo, stake_utxo, &operator_siggner);
        let kickoff_txid = client.send_transaction(&kickoff_tx).expect("");
        println!("kickoff txid: {}", kickoff_txid);
        let kickoff_utxo = UTXO {
            outpoint: OutPoint {
                txid: kickoff_txid,
                vout: 0,
            },
            amount: kickoff_tx.output[0].value,
        };

        let happy_take_txid = client
            .send_transaction(&transaction_graph.get_happy_take_tx(kickoff_utxo))
            .expect("");
        println!("happy take txid: {}", happy_take_txid);
    }

    // pegin -> kickoff -> challenge -> assert -> disprove+reward
    #[test]
    fn test_transaction_graph_unhappy_path() {
        let params = Params::default();
        let operator_siggner = SignerInfo::new(bitcoin::Network::Regtest);
        let transaction_graph = TransactionGraph::new(&operator_siggner.address, &params);
        let kickoff_script = transaction_graph
            .get_first_script()
            .expect("get first script");

        let url = format!("{}:18443", local_ip().expect("find one").to_string());
        let user = "admin".to_string();
        let password = "admin".to_string();

        let client = RPCClient::new(&url, &user, &password);
        let params = Params::default();
        let utxo = client.prepare_utxo_for_address(params.depoist_amt, &operator_siggner.address);
        let pegin = Pegin::new(utxo.outpoint, utxo.amount, kickoff_script, &params);
        let pegin_tx = pegin.sign(&operator_siggner);
        let pegin_txid = client.send_transaction(&pegin_tx).expect("success");
        println!("pegin txid: {}", pegin_txid);
        let pegin_utxo = UTXO {
            outpoint: OutPoint {
                txid: pegin_txid,
                vout: 0,
            },
            amount: pegin_tx.output[0].value,
        };
        let stake_utxo =
            client.prepare_utxo_for_address(params.stake_amt, &operator_siggner.address);
        let kickoff_tx =
            transaction_graph.get_kickoff_tx(pegin_utxo, stake_utxo, &operator_siggner);
        let kickoff_txid = client.send_transaction(&kickoff_tx).expect("");
        println!("kickoff txid: {}", kickoff_txid);
        let kickoff_utxo = UTXO {
            outpoint: OutPoint {
                txid: kickoff_txid,
                vout: 0,
            },
            amount: kickoff_tx.output[0].value,
        };

        let challenge_tx= transaction_graph.get_challenge_tx(kickoff_utxo);
        let challenge_txid = client
            .send_transaction(&challenge_tx)
            .expect("");
        println!("challenge txid: {}", challenge_txid);

        let challenge_utxo = UTXO {
            outpoint: OutPoint{
                txid: challenge_txid,
                vout: 0
            },
            amount: challenge_tx.output[0].value
        };
        let assert_tx= &transaction_graph.get_assert_tx(challenge_utxo);
        let assert_txid = client
        .send_transaction(&assert_tx)
        .expect("");
        println!("assert txid: {}", assert_txid);

        let assert_utxo = UTXO {
            outpoint: OutPoint{
                txid: assert_txid,
                vout: 0
            },
            amount: assert_tx.output[0].value
        };

        let receiver = SignerInfo::new(Network::Regtest);
        let (disprove_tx, reward_tx)= transaction_graph.get_disprove_tx(assert_utxo, &receiver);
        let disprove_txid = client
        .send_transaction(&disprove_tx)
        .expect("");
        println!("disprove txid: {}", disprove_txid);

        let reward_txid = client
        .send_transaction(&reward_tx)
        .expect("");
        println!("reward txid: {}, amt: {}", reward_txid, reward_tx.output[0].value);
    }

    #[test]
    fn test_transaction_graph1() {
        let params = Params::default();
        let operator_siggner = SignerInfo::new(bitcoin::Network::Regtest);
        let transaction_graph = TransactionGraph::new(&operator_siggner.address, &params);
        let kickoff_script = transaction_graph
            .get_first_script()
            .expect("get first script");

        let url = format!("{}:18443", local_ip().expect("find one").to_string());
        let user = "admin".to_string();
        let password = "admin".to_string();

        let client = RPCClient::new(&url, &user, &password);
        let params = Params::default();
        let utxo = client.prepare_utxo_for_address(params.depoist_amt, &operator_siggner.address);
        let pegin = Pegin::new(utxo.outpoint, utxo.amount, kickoff_script, &params);
        let pegin_tx = pegin.sign(&operator_siggner);
        let pegin_txid = client.send_transaction(&pegin_tx).expect("success");
        println!("pegin txid: {}", pegin_txid);
        let pegin_utxo = UTXO {
            outpoint: OutPoint {
                txid: pegin_txid,
                vout: 0,
            },
            amount: pegin_tx.output[0].value,
        };
        let stake_utxo =
            client.prepare_utxo_for_address(params.stake_amt, &operator_siggner.address);
        // let kickoff_tx =
        //     transaction_graph.get_kickoff_tx(pegin_utxo, stake_utxo, &operator_siggner);
        let ins = vec![pegin_utxo, stake_utxo];
        let cheater_signer = SignerInfo::new(Network::Regtest);
        let outs = vec![(
            cheater_signer.address.script_pubkey(),
            params.depoist_amt - params.gas_amt - params.gas_amt,
        )];
        let fake_kickoff = TransactionGraph::create_btc_tx(&ins, outs);
        let res = client.send_transaction(&fake_kickoff);
        println!("result: {:?}", res);
        assert_eq!(true, client.send_transaction(&fake_kickoff).is_err());
    }
}
