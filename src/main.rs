#![allow(non_snake_case)]
use secp256kfun::{XOnly, Scalar, derive_nonce, nonce, marker::*, G, s, hash::{Tagged, AddTag, HashAdd}};
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

pub fn generate_nonce(secret_key: &Scalar, public_key: &XOnly<EvenY>, event: &str) -> (Scalar, XOnly<SquareY>) {
    let mut r = derive_nonce! {
        nonce_gen => nonce::Deterministic::<sha2::Sha256>::default().add_protocol_tag("BIP340"),
        secret => secret_key,
        public => [ public_key, event.as_bytes() ]
    };

    let R =  XOnly::<SquareY>::from_scalar_mul(G, &mut r);
    if !EvenY::norm_point_matches(&R.to_point()) {
        // we want to make sure the point is both EvenY and SquareY since BIP340 is changing
        generate_nonce(secret_key, public_key, &format!("{}Z", event))
    } else {
        (r, R)
    }

}


pub fn attest(secret_key: &Scalar, public_key: &XOnly<EvenY>, event: &str, outcome: &str) -> Scalar<Public, Zero> {
    let outcome_hash = Sha256::default().add(outcome.as_bytes()).finalize();
    let (r, R) = generate_nonce(&secret_key, &public_key, &event);
    let bip340_challenge = Sha256::default().tagged(b"BIP340/challenge");
    let c = Scalar::from_hash(bip340_challenge.add(&R).add(public_key).add(&outcome_hash[..])).mark::<Public>();
    s!(r + c * secret_key).mark::<(Public,Zero)>()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();
    let mut secret_key = Scalar::from_str(&opt.secret_key).map_err(|_| "invalid hex encoded secret key")?;
    let public_key = XOnly::<EvenY>::from_scalar_mul(G, &mut secret_key);
    println!("{}", run_cmd(opt.cmd, &secret_key, &public_key));
    Ok(())
}

fn run_cmd(cmd: Command, secret_key: &Scalar, public_key: &XOnly<EvenY>) -> String {
    match cmd {
        Command::PublicKey => {
           format!("Public key: {}", public_key)
        },
        Command::Announce { event } => {
            let (_r ,R) = generate_nonce(&secret_key, &public_key, &event);
            format!("Nonce: {}", R)
        },
        Command::Attest { event, outcome } => {
            let secret_key = attest(secret_key, public_key, &event, &outcome);
            format!("Attestation: {}", secret_key)
        }
    }
}

#[cfg(test)]
mod test {
    use schnorr_fun::*;
    use super::*;

    #[test]
    fn exhaustive() {
        let mut secret_key = Scalar::from_str("4242424242424242424242424242424242424242424242424242424242424242").unwrap();
        let public_key = XOnly::<EvenY>::from_scalar_mul(G, &mut secret_key);
        let event = "the_event".to_string();
        let outcome = "the_outcome".to_string();
        let (_, R) = generate_nonce(&secret_key, &public_key, &event);
        let s = attest(&secret_key, &public_key, &event, &outcome);
        let schnorr = Schnorr::<Sha256>::verify_only(MessageKind::Prehashed);
        let signature = Signature { R, s };
        let outcome_hash = Sha256::default().add(outcome.as_bytes()).finalize();
        assert!(schnorr.verify(&public_key.to_point(), (&outcome_hash[..]).mark::<Public>(), &signature));
    }
}
