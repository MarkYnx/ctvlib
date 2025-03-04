use std::str::FromStr;

use bitcoin::script::Builder;
use bitcoin::sighash::SighashCache;
use bitcoin::{
    key::{Keypair, Secp256k1},
    secp256k1::{All, Message, SecretKey},
    Address, EcdsaSighashType, PrivateKey, PublicKey, SegwitV0Sighash, XOnlyPublicKey,
};
use bitcoin::{
    opcodes::all::OP_NOP4, script::PushBytesBuf, transaction::Version, Amount, ScriptBuf,
    Transaction, TxOut,
};
use bitcoin::{OutPoint, TxIn, Txid, Witness};
use secp256k1::rand;

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

pub struct TransactionGraph {
    kickoff: Transaction,
    happy_take: Transaction,
}

impl TransactionGraph {
    pub fn dummy_input() -> TxIn {
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
        let input = ins.into_iter().map(|i| {
            TxIn    {
            previous_output: i.outpoint,
            sequence: bitcoin::Sequence(0xFFFFFFFF),
            script_sig: Builder::new().into_script(),
            witness: Witness::new(),
        }
        }).collect();

        let output = outs.into_iter().map(|o| {
            TxOut {
                script_pubkey: o.0,
                value: o.1
            }
        }).collect();

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
        let kickoff_output = TxOut {
            value: params.depoist_amt + params.stake_amt - params.gas_amt - params.gas_amt, // for pegin, kickoff
            script_pubkey: lock_script_for_happy_take_input0,
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

    pub fn get_happy_take_tx(&self, kickoff_utxo: UTXO, signer: &SignerInfo) -> Transaction {
        let mut tx = self.happy_take.clone();
        // replace input
        tx.input[0].previous_output = kickoff_utxo.outpoint;

        tx
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
    use bitcoin::{transaction::{self, Version}, Amount, Network, OutPoint, Transaction, TxIn};
    use local_ip_address::local_ip;

    use crate::bitcoin_sdk::{RPCClient, UTXO};

    use super::{Params, Pegin, SignerInfo, TransactionGraph};

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
            .send_transaction(&transaction_graph.get_happy_take_tx(kickoff_utxo, &operator_siggner))
            .expect("");
        println!("happy take txid: {}", happy_take_txid);
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
        let outs = vec![(cheater_signer.address.script_pubkey(), params.depoist_amt - params.gas_amt - params.gas_amt)];
        let fake_kickoff = TransactionGraph::create_btc_tx(&ins, outs); 
        let res = client.send_transaction(&fake_kickoff);
        println!("result: {:?}", res);
        assert_eq!(true, client.send_transaction(&fake_kickoff).is_err());
    
        
    }
}
