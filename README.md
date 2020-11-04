Basic CLI to attest to events in "Discreet Log Contract" style using BIP-340

```
// public key
$ cargo run -- --secret-key=6c20bf779da91f82da3311b1d9e0a3a513409a15c66f25201280751177dad24c public-key
// nonce for an event
$ cargo run -- --secret-key=6c20bf779da91f82da3311b1d9e0a3a513409a15c66f25201280751177dad24c announce "2020_presidential_election"
// attestation for the event 
$ cargo run -- --secret-key=6c20bf779da91f82da3311b1d9e0a3a513409a15c66f25201280751177dad24c attest "2020_presidential_election" "Trump_win"
```
