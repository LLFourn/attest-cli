#![allow(non_snake_case)]
use schnorr_fun::{ fun::{XOnly, Scalar, derive_nonce, nonce, marker::*, G, s, hash::{AddTag, HashAdd}} , Schnorr, MessageKind, KeyPair};
use structopt::StructOpt;
use sha2::{Digest, Sha256};
use core::str::FromStr;

#[derive(Debug, StructOpt)]
#[structopt(name = "basic")]
struct Opt {
    #[structopt(short, long, name = "secp256k1 hex encoded secret key")]
    secret_key: String,
    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(Debug, StructOpt)]
pub enum Command {
    PublicKey,
    Announce { event: String },
    Attest { event: String, outcome: String }
}

pub fn generate_nonce(keypair: &KeyPair, event: &str) -> (Scalar, XOnly) {
    let (x,X) = keypair.as_tuple();
    let mut r = derive_nonce! {
        nonce_gen => nonce::Deterministic::<sha2::Sha256>::default().add_protocol_tag("BIP340"),
        secret => x,
        public => [ X, event.as_bytes() ]
    };

    let R = XOnly::from_scalar_mul(G, &mut r);
    (r, R)
}


pub fn attest(schnorr: &Schnorr<Sha256,()>, keypair: &KeyPair, (r,R): (Scalar, XOnly), outcome_hash: &[u8;32]) -> Scalar<Public, Zero> {
    let (x,X) = keypair.as_tuple();
    let c = schnorr.challenge(&R, X, outcome_hash[..].mark::<Public>());
    s!(r + c * x).mark::<(Public,Zero)>()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();
    let schnorr = Schnorr::verify_only(MessageKind::Prehashed);
    let secret_key = Scalar::from_str(&opt.secret_key).map_err(|_| "invalid hex encoded secret key")?;
    let keypair = schnorr.new_keypair(secret_key);
    println!("{}", run_cmd(opt.cmd,&schnorr, &keypair));
    Ok(())
}

fn run_cmd(cmd: Command, schnorr: &Schnorr<Sha256,()>, keypair: &KeyPair) -> String {
    match cmd {
        Command::PublicKey => {
           format!("Public key: {}", keypair.public_key())
        },
        Command::Announce { event } => {
            let (_r ,R) = generate_nonce(&keypair, &event);
            format!("Public key: {}\nNonce: {}", keypair.public_key(),R)
        },
        Command::Attest { event, outcome } => {
            let (r, R) = generate_nonce(&keypair, &event);
            let outcome_hash: [u8;32] = Sha256::default().add(outcome.as_bytes()).finalize().into();
            let attestation = attest(schnorr,keypair, (r.clone(),R.clone()), &outcome_hash);
            format!("Public key: {}\nNonce: {}\nAttestation: {}", keypair.public_key(), R, attestation)
        }
    }
}

#[cfg(test)]
mod test {
    use schnorr_fun::*;
    use schnorr_fun::fun::*;
    use serde_json::json;
    use super::*;

    #[test]
    fn exhaustive() {
        let secret_key = Scalar::from_str("4242424242424242424242424242424242424242424242424242424242424242").unwrap();
        let schnorr = Schnorr::verify_only(MessageKind::Prehashed);
        let keypair = schnorr.new_keypair(secret_key);
        let event = "the_event".to_string();
        let outcome = "the_outcome".to_string();
        let outcome_hash: [u8;32] = Sha256::default().add(outcome.as_bytes()).finalize().into();
        let (r, R) = generate_nonce(&keypair, &event);
        let  s = attest(&schnorr, &keypair, (r,R.clone()), &outcome_hash);
        let schnorr = Schnorr::<Sha256>::verify_only(MessageKind::Prehashed);
        let signature = Signature { R, s };
        assert!(schnorr.verify(&keypair.verification_key(), (&outcome_hash[..]).mark::<Public>(), &signature));
    }

    #[test]
    fn json_spectest() {
        #[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
        struct Inputs {
            privKey: Scalar,
            privNonce: Scalar,
            msgHash: Scalar,
        }

        #[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
        struct Test {
            inputs: Inputs,
            pubKey: XOnly,
            signature: Signature,
            sigPoint: Point,
        }

        let test_json = json! {
            [ {
                "inputs" : {
                    "privKey" : "5376a94490ff9b07387511351fdf9fb56d0f704effaa9e55218ac82f712f8a26",
                    "privNonce" : "f32827363379a82bedd1724197ebbae0b0e58719d3014dacc353f0c45109830e",
                    "msgHash" : "b27019d1912cb97b679eee4c01f9203e00da8443767173df076a529a66e707cf"
                },
                "pubKey" : "ce9a3088688eecd98db77c90637c25e6801fc56b0436e7e0103cee82ec63d508",
                "pubNonce" : "0273ebfee82296afd16b9a6c7cf2485ef83b0cba1b6b66dc7edfbfb1071e8317",
                "signature" : "0273ebfee82296afd16b9a6c7cf2485ef83b0cba1b6b66dc7edfbfb1071e8317ee2b16e43e08393bcbe087c792b30c902ff136775323877fc832f64bf5935781",
                "sigPoint" : "020dddc643adbc3c8d745f6e9c028bf4abf22cfc97568b60e4c3419cbb72502690"
            }, {
                "inputs" : {
                    "privKey" : "b339569c68f2de370ba4774203c2d01cfbe2af1a23958accaaa227e64cae4e5f",
                    "privNonce" : "467a0383c6116b9c65ddc8aa2d3577a0f597027b07163f5ea9e891d068c9545a",
                    "msgHash" : "ecc549855e17ce7dbce3759ff9ffd224ba34e40befe3df69d6b7a5450c82fc07"
                },
                "pubKey" : "639fd0e002f476a1ba3dd3bb40d007544cf9e09ff1a23bd8c66d1cb8980fed8c",
                "pubNonce" : "1e90814df446c16b854494aac8b1f05771611228b52ddd6b1eb1dd29dab973b7",
                "signature" : "1e90814df446c16b854494aac8b1f05771611228b52ddd6b1eb1dd29dab973b7cfadd5b1004918214713cc052b84821f675eccd12388008b25dc18b6596aa132",
                "sigPoint" : "02987faf504b29c90ffa0e83f9c9c9919d7c56ad5564c0b7eaa63d92b7cf3e51ca"
            }, {
                "inputs" : {
                    "privKey" : "a6080050e59f3b7ebbd14a3d058f44978ece37bb896543c789b89ca86dabc74d",
                    "privNonce" : "84e9e4edfcd67a92f326f4d96f48d311793e96c2b542e96e5738fe987820d5e4",
                    "msgHash" : "6744b92461c47f4a7f7b785c6bb38daa40b7c1d9e532b5480e5b73c6c0096011"
                },
                "pubKey" : "4c2a9fd1473302f23d28c398d54e4bef5f3d6d01341387bac5872796b89a0ef9",
                "pubNonce" : "7fa3a59374116c93b1ea0d2c9408b40768e99e43562f9bd7205986e567e961b5",
                "signature" : "7fa3a59374116c93b1ea0d2c9408b40768e99e43562f9bd7205986e567e961b59dd00ba70a497851153afc5faf774f8ed3f8b6b2b421c94121f7c85dab3d6225",
                "sigPoint" : "03b6e6aee8ef20a761bc9bbb227d0a49c1eea80a0e6df62a79c576b5f08ad88ec5"
            }, {
                "inputs" : {
                    "privKey" : "cfe7c7ed47b0ce4885838a53cb6b102ae09b37b2705147607d886e62988190be",
                    "privNonce" : "a0d084b608e5d1b218901212ed3fa15a8692de99c37c6cae6648285156a5feda",
                    "msgHash" : "143bc33b165b4f7e66a2d997e1f20e4d880416be6d7aaa0d8d385d1ab9482470"
                },
                "pubKey" : "43766d34751895463a0a9a3979b8ebc300132c3117ef20de0a209ffc1e5d06cb",
                "pubNonce" : "53c53d2f7eae94c4766ec322c018be27f65fb65478212f4983b08b8f40765018",
                "signature" : "53c53d2f7eae94c4766ec322c018be27f65fb65478212f4983b08b8f407650188a01c30884bcd27157191fa4046944c6fc035a69765fd09dccd7a02816143a84",
                "sigPoint" : "035041aedc6a8fb0c911507af5cdfe5393761361a28e88d5f4f4197f39a495b6ab"
            }, {
                "inputs" : {
                    "privKey" : "7582012d1fa17f723754927109828c71c5d7dd3fadcc8f20d6a79dde27fc985f",
                    "privNonce" : "dd1d13c185e27172e83fd615f6ace25b89e7360ca74888b15b7ac4b639d9edb8",
                    "msgHash" : "1c2aedbbbd3d8a425fc688730a00c8da2e5b0f0be90eee1f90a2099cac5edb50"
                },
                "pubKey" : "d0816bd521ce59ae060eb43cd6e8d0fc8047f338a23f0038a986b92f77a038fe",
                "pubNonce" : "dae00f16a8c375fb8f0848e96ddfb77ea57b2c6c6f499ffbe6534ba53d6193ae",
                "signature" : "dae00f16a8c375fb8f0848e96ddfb77ea57b2c6c6f499ffbe6534ba53d6193aef8c6936867b1addd66517eaf933e92fb5f6299975ffcf09901439a012ad2ad83",
                "sigPoint" : "020ddbf600b1cef6cb9f9cdabdb1951c42f1a6b7fa7dee0ef9fb3bdda258e5b2c6"
            } ]
        };

        let tests = serde_json::from_value::<Vec<Test>>(test_json).unwrap();
        let schnorr = Schnorr::<Sha256>::verify_only(MessageKind::Prehashed);

        for test in tests {
            let keypair = schnorr.new_keypair(test.inputs.privKey);
            let nonce_pair = schnorr.new_keypair(test.inputs.privNonce);
            let scalar = attest(&schnorr, &keypair, nonce_pair.into(), &test.inputs.msgHash.to_bytes());
            assert_eq!(scalar, test.signature.s);
        }

    }
}
