use bls_binary_rust::*;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::mem;

fn secret_key_deserialize_hex_str(x: &str) -> SecretKey {
    SecretKey::from_serialized(&hex::decode(x).unwrap()).unwrap()
}

fn public_key_deserialize_hex_str(x: &str) -> G2 {
    G2::from_serialized(&hex::decode(x).unwrap()).unwrap()
}

fn signature_deserialize_hex_str(x: &str) -> G1 {
    G1::from_serialized(&hex::decode(x).unwrap()).unwrap()
}

fn signature_serialize_to_hex_str(x: &G1) -> String {
    hex::encode(x.serialize())
}

#[test]
fn test_are_all_msg_different() {
    assert!(are_all_msg_different("abcdefgh".as_bytes(), 2));
    assert!(!are_all_msg_different("abcdabgh".as_bytes(), 2));
}

macro_rules! serialize_test {
    ($t:ty, $x:expr) => {
        let buf = $x.serialize();
        let mut y: $t = <$t>::uninit();
        assert!(y.deserialize(&buf));
        assert_eq!($x, y);

        let z = <$t>::from_serialized(&buf);
        assert_eq!($x, z.unwrap());
    };
}

#[test]
fn test_sign_serialize() {
    assert_eq!(mem::size_of::<SecretKey>(), 32);
    assert_eq!(mem::size_of::<G1>(), 48 * 3);
    assert_eq!(mem::size_of::<G2>(), 48 * 2 * 3);

    let msg = "abc".as_bytes();
    let mut sk = SecretKey::uninit();
    sk.set_by_csprng();
    let pk = sk.get_public_key();
    let sig = sk.sign(msg);

    assert!(sig.verify(pk, msg));
    serialize_test! {SecretKey, sk};
    serialize_test! {G2, pk};
    serialize_test! {G1, sig};
}

#[test]
#[ignore = "aggregate not implemented"]
fn test_eth_aggregate() {
    let f = File::open("tests/aggregate.txt").unwrap();
    let file = BufReader::new(&f);
    let mut sigs: Vec<G1> = Vec::new();

    for s in file.lines() {
        let line = s.unwrap();
        let v: Vec<&str> = line.split(' ').collect();
        match v[0] {
            "sig" => sigs.push(signature_deserialize_hex_str(v[1])),
            "out" => {
                let out = signature_deserialize_hex_str(v[1]);
                let mut agg = G1::uninit();
                agg.aggregate(&sigs);
                sigs.clear();
                assert_eq!(agg, out);
            }
            _ => (),
        }
    }
}

fn one_test_sign(sk_hex: &str, msg: &str, sig_hex: &str) {
    let sk = secret_key_deserialize_hex_str(sk_hex);
    let pk = sk.get_public_key();
    let msg = msg.as_bytes();
    let sig = sk.sign(msg);

    assert!(sig.verify(pk, msg));
    assert_eq!(signature_serialize_to_hex_str(&sig), sig_hex);
}

#[test]
fn test_sign() {
    let f = File::open("tests/sign.txt").unwrap();
    let file = BufReader::new(&f);
    let mut sk_hex = "".to_string();
    let mut msg = "".to_string();
    let mut sig_hex;

    for s in file.lines() {
        let line = s.unwrap();
        let v: Vec<&str> = line.split(' ').collect();
        match v[0] {
            "sec" => sk_hex = v[1].to_string(),
            "msg" => msg = v[1].to_string(),
            "out" => {
                sig_hex = v[1].to_string();
                one_test_sign(&sk_hex, &msg, &sig_hex);
            }
            _ => (),
        }
    }
}

#[test]
#[ignore = "aggregate not implemented"]
fn test_eth_aggregate_verify_no_check1() {
    let f = File::open("tests/aggregate_verify.txt").unwrap();
    let file = BufReader::new(&f);
    let mut pubs: Vec<G2> = Vec::new();
    let mut msg: Vec<u8> = Vec::new();
    let mut sig = G1::uninit();
    let mut valid = false;

    let mut i = 0;
    for s in file.lines() {
        let line = s.unwrap();
        let v: Vec<&str> = line.split(' ').collect();
        match v[0] {
            "pub" => pubs.push(public_key_deserialize_hex_str(v[1])),
            "msg" => {
                let vv = hex::decode(v[1]).unwrap();
                msg.append(&mut vv.clone());
            }
            "sig" => {
                valid = sig.deserialize(&hex::decode(v[1]).unwrap());
                if !valid {
                    println!("bad signature {:?}", &v[1]);
                }
            }
            "out" => {
                println!("i={:?}", i);
                if valid {
                    let out = v[1] == "true";
                    assert_eq!(sig.aggregate_verify_no_check(&pubs, &msg), out);
                }
                pubs.truncate(0);
                msg.truncate(0);
                i += 1;
            }
            _ => (),
        }
    }
}

#[test]
#[ignore = "aggregate not implemented"]
fn test_fast_aggregate_verify() {
    let f = File::open("tests/fast_aggregate_verify.txt").unwrap();
    let file = BufReader::new(&f);
    let mut pubs: Vec<G2> = Vec::new();
    let mut sig = G1::uninit();
    let mut msg: Vec<u8> = Vec::new();
    let mut valid = false;

    let mut i = 0;
    for s in file.lines() {
        let line = s.unwrap();
        let v: Vec<&str> = line.split(' ').collect();
        match v[0] {
            "pub" => pubs.push(public_key_deserialize_hex_str(v[1])),
            "msg" => {
                let vv = &hex::decode(v[1]).unwrap();
                msg = vv.clone();
            }
            "sig" => {
                valid = sig.deserialize(&hex::decode(v[1]).unwrap());
                if !valid {
                    println!("bad signature {:?}", &v[1]);
                }
            }
            "out" => {
                println!("i={:?}", i);
                if valid {
                    let out = v[1] == "true";
                    assert_eq!(sig.fast_aggregate_verify(&pubs, &msg), out);
                }
                pubs.truncate(0);
                i += 1;
            }
            _ => (),
        }
    }
}

fn make_multi_sig(n: usize, msg_size: usize) -> (Vec<G2>, Vec<G1>, Vec<u8>) {
    let mut pubs: Vec<G2> = Vec::new();
    let mut sigs: Vec<G1> = Vec::new();
    let mut msgs: Vec<u8> = Vec::new();
    msgs.resize_with(n * msg_size, Default::default);
    for i in 0..n {
        let mut sec: SecretKey = SecretKey::uninit();
        sec.set_by_csprng();
        pubs.push(sec.get_public_key());
        msgs[msg_size * i] = i as u8;
        let sig = sec.sign(&msgs[i * msg_size..(i + 1) * msg_size]);
        sigs.push(sig);
    }
    (pubs, sigs, msgs)
}

fn one_test_eth_aggregate_verify_no_check(n: usize) {
    const MSG_SIZE: usize = 32;
    let (pubs, sigs, mut msgs) = make_multi_sig(n, MSG_SIZE);
    assert!(are_all_msg_different(&msgs, MSG_SIZE));
    let mut agg_sig = G1::uninit();
    agg_sig.aggregate(&sigs);
    if n == 0 {
        assert!(!agg_sig.aggregate_verify_no_check(&pubs, &msgs));
    } else {
        assert!(agg_sig.aggregate_verify_no_check(&pubs, &msgs));
        msgs[1] = 1;
        assert!(!agg_sig.aggregate_verify_no_check(&pubs, &msgs));
    }
}

#[test]
#[ignore = "aggregate not implemented"]
fn test_eth_aggregate_verify_no_check2() {
    let tbl = [0, 1, 2, 15, 16, 17, 50];
    for i in tbl {
        one_test_eth_aggregate_verify_no_check(tbl[i]);
    }
}

#[test]
#[ignore = "aggregate not implemented"]
fn test_signature_with_dummy_key() {
    let sk = SecretKey::from_hex_str("1").unwrap();
    let sig = sk.sign("asdf".as_bytes());

    let sig_hex = "283ae6bd67b23ee056888f2b119beac4224b6bece92553913a03a8fec53b68c37fae3d9315b58468d2cdae05bf236298";
    assert_eq!(signature_serialize_to_hex_str(&sig), sig_hex);
}

fn test_multi_verify_one(n: usize) {
    const MSG_SIZE: usize = 32;
    let (_pubs, _sigs, mut msgs) = make_multi_sig(n, MSG_SIZE);
    // assert!(multi_verify(&sigs, &pubs, &msgs));
    msgs[1] = 1;
    // assert!(!multi_verify(&sigs, &pubs, &msgs));
}

#[test]
#[ignore]
fn test_multi_verify() {
    for n in [1, 2, 3, 15, 40, 400].iter() {
        test_multi_verify_one(*n);
    }
}
