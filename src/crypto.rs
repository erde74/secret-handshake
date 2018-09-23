use sodiumoxide::crypto::auth::{authenticate, verify, Key, Tag};
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::scalarmult::curve25519::{
    scalarmult, GroupElement, Scalar, GROUPELEMENTBYTES,
};
use sodiumoxide::crypto::sign::{gen_keypair, PublicKey, SecretKey};

pub trait AsRef {
    fn as_ref(&self) -> &[u8];
}

// impl Copy for SecretKey {}

impl AsRef for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self[..]
    }
}

impl AsRef for GroupElement {
    fn as_ref(&self) -> &[u8] {
        &self[..]
    }
}

pub const CHALLENGE_LENGTH: usize = 64;
pub const CLIENT_AUTH_LENGTH: usize = 16 + 32 + 64;
pub const SERVER_AUTH_LENGTH: usize = 16 + 64;
pub const MAC_LENGTH: usize = 16;

// struct Keypair {}

#[derive(Debug, Clone)]
pub struct Sbox {
    pub kx_pk: PublicKey,
    pub kx_sk: SecretKey,
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
    pub app_mac: Tag,
}

#[derive(Debug, Clone)]
pub struct State {
    pub local: Option<Box<Sbox>>,
    pub remote: Option<Box<Sbox>>,
    pub secret: GroupElement,
    pub shash: sha256::Digest,
    pub app_key: Key,
}

pub fn assert_length(buf: &[u8], name: &str, length: usize) {
    if buf.len() != length {
        panic!(format!(
            "expected {} to have length {} but was: {}",
            name,
            length,
            buf.len()
        ));
    }
}

pub fn initialize(state: &mut State) -> State {
    let (pk, sk) = gen_keypair();
    let l: Sbox = Sbox {
        kx_pk: pk,
        kx_sk: sk.clone(),
        public_key: pk,
        secret_key: sk.clone(),
        app_mac: authenticate(pk.as_ref(), &state.app_key),
    };
    state.local = Option::Some(Box::new(l));
    state.clone()
}

pub fn create_challenge(state: &State) -> [u8; CHALLENGE_LENGTH] {
    let mut c: [u8; CHALLENGE_LENGTH] = [0; CHALLENGE_LENGTH];

    match state.local {
        Some(ref l) => {
            c[0..32].clone_from_slice(&l.app_mac.as_ref()[0..32]);
            c[32..64].clone_from_slice(&l.kx_pk.as_ref()[0..32]);
            c
        }
        None => c,
    }
}

pub fn verify_challenge(mut state: State, challenge: &[u8; 64]) -> State {
    assert_length(challenge, "challenge", CHALLENGE_LENGTH);

    let mac = Tag::from_slice(&challenge[0..32]).unwrap();
    let remote_pk = &challenge[32..64];

    if !verify(&mac, &remote_pk, &state.app_key) {
        return state;
    }

    if let Some(ref l) = state.local {
        if let Some(ref mut r) = state.remote {
                    r.kx_pk = PublicKey::from_slice(remote_pk).unwrap();
                    r.app_mac = mac;
                    state.secret = scalarmult(
                        &Scalar::from_slice(&l.kx_sk.as_ref()[0..32]).unwrap(),
                        &GroupElement::from_slice(r.kx_pk.as_ref()).unwrap(),
                    ).unwrap();
                    state.shash = sha256::hash(state.secret.as_ref());
                }
        }
    state
}

pub fn clean(mut state: State) -> Option<State> {
    let empty: [u8; GROUPELEMENTBYTES] = [0; GROUPELEMENTBYTES];

    state.shash = sha256::hash(b"");

    state.secret = GroupElement(empty);
    Some(state)
}

#[test]
fn assert_length_test() {
    use std::panic;

    let buf = vec![0, 0, 0, 0, 0, 0, 0, 0];
    let res1 = panic::catch_unwind(|| {
        assert_length(&buf, "buffer", 8);
    });
    assert!(res1.is_err() == false);

    let res2 = panic::catch_unwind(|| {
        assert_length(&buf, "buffer", 9);
    });
    assert!(res2.is_err());
}

#[test]
fn initalize_test() {
    use base64;
    use std::cmp::Ordering;

    let app_key = "1KHLiKZvAvjbY1ziZEHMXawbCEIM6qwjCDm3VYRan/s=";

    let mut s: State = State {
        local: None,
        remote: None,
        app_key: Key::from_slice(&base64::decode(&app_key).unwrap()).unwrap(),
        secret: GroupElement::from_slice(&[0; 32]).unwrap(),
        shash: sha256::Digest::from_slice(&[0; 32]).unwrap(),
    };

    s = initialize(&mut s);

    match s.local {
        Some(ref l) => {
            assert_length(l.kx_pk.as_ref(), "pk", 32);
        }
        None => {
            assert!(false);
        }
    }

    let (pk, sk) = gen_keypair();
    let r: Sbox = Sbox {
        kx_pk: pk,
        kx_sk: sk.clone(),
        public_key: pk,
        secret_key: sk.clone(),
        app_mac: authenticate(pk.as_ref(), &s.app_key),
    };

    s.remote = Some(Box::new(r));

    let ch = create_challenge(&s);
    assert!(ch.cmp(&[0; CHALLENGE_LENGTH]) != Ordering::Equal);
    s = verify_challenge(s, &ch);
    println!("{:?}", s.app_key);
}
