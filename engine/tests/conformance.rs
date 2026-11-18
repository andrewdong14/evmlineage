// tests/conformance.rs — the Rust engine must reproduce, byte for byte, the
// vectors written by the Python reference
// (python3 agent/evm_lineage.py --vectors testvectors/conformance.json).

use lineage_engine::{
    decode_blob, encode_blob, sentinel_leaf, sha256, skip_level, verify_query, Codec, Epsl,
    MerkleTree, QueryKind, QueryProof, VertexHash, L_MAX,
};
use serde_json::Value;

fn hx(v: &Value) -> VertexHash {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}
fn hxs(v: &Value) -> Vec<VertexHash> { v.as_array().unwrap().iter().map(hx).collect() }

fn load() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testvectors/conformance.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("vector file")).unwrap()
}

#[test]
fn constants_and_levels() {
    let v = load();
    assert_eq!(v["format"], 2);
    assert_eq!(hx(&v["sentinel_leaf"]), sentinel_leaf());
    assert_eq!(v["l_max"].as_u64().unwrap(), L_MAX as u64);
    for l in v["levels"].as_array().unwrap() {
        assert_eq!(skip_level(&hx(&l["h"])) as u64, l["level"].as_u64().unwrap());
    }
}

#[test]
fn roots_proofs_and_queries_match_python() {
    let v = load();
    let epsl = Epsl::default();
    let mut roots = Vec::new();
    for ep in v["epochs"].as_array().unwrap() {
        for ev in ep["events"].as_array().unwrap() {
            epsl.insert(&hxs(&ev["s"]), &hxs(&ev["t"]));
        }
        let er = epsl.seal();
        assert_eq!(er.epoch, ep["epoch"].as_u64().unwrap());
        assert_eq!(er.root, hx(&ep["root"]), "root of epoch {}", er.epoch);
        assert_eq!(er.new_vertices as u64, ep["new_vertices"].as_u64().unwrap());
        assert_eq!(er.touched as u64, ep["touched"].as_u64().unwrap());
        roots.push(er.root);
    }
    for m in v["membership"].as_array().unwrap() {
        let e = m["epoch"].as_u64().unwrap();
        let mp = epsl.membership(&hx(&m["h"]), Some(e)).expect("vertex exists");
        assert_eq!(mp.digest, hx(&m["digest"]));
        assert_eq!(mp.leaf, hx(&m["leaf"]));
        assert_eq!(mp.path, hxs(&m["path"]));
        assert_eq!(mp.root, hx(&m["root"]));
        assert!(mp.verify(&roots[e as usize]));
    }
    for q in v["queries"].as_array().unwrap() {
        let kind = QueryKind::parse(q["kind"].as_str().unwrap()).unwrap();
        let e = q["epoch"].as_u64().unwrap();
        let depth = q["max_depth"].as_u64().map(|d| d as u32);
        let res = epsl.query(&hx(&q["origin"]), kind, Some(e), depth, true).unwrap();
        assert_eq!(res.hashes, hxs(&q["result"]));
        let proof = res.proof.unwrap();
        let want = hex::decode(q["proof"].as_str().unwrap()).unwrap();
        assert_eq!(proof.to_bytes(), want, "proof bytes of {kind:?} at epoch {e}");
        let parsed = QueryProof::from_bytes(&want).unwrap();
        assert_eq!(verify_query(&parsed, &roots[e as usize]), Some(res.hashes));
    }
}

#[test]
fn payload_and_prune_log_match_python() {
    let v = load();
    let p = &v["payload"];
    let raw = hex::decode(p["raw"].as_str().unwrap()).unwrap();
    let (epoch, root, events) = decode_blob(&raw).unwrap();
    assert_eq!(epoch, p["epoch"].as_u64().unwrap());
    assert_eq!(encode_blob(epoch, &root, &events, Codec::Raw), raw);
    assert_eq!(sha256(&raw), hx(&p["data_hash"]));
    let zl = hex::decode(p["zlib"].as_str().unwrap()).unwrap();
    assert_eq!(decode_blob(&zl).unwrap(), (epoch, root, events));

    let pr = &v["prune"];
    let leaves: Vec<VertexHash> = pr["entries"].as_array().unwrap().iter()
        .map(|e| lineage_engine::keccak256(&hex::decode(e.as_str().unwrap()).unwrap()))
        .collect();
    let tree = MerkleTree::from_leaves(&leaves);
    assert_eq!(tree.root(), hx(&pr["root"]));
    let mp = tree.proof(3).unwrap();
    assert_eq!(mp.leaf, hx(&pr["proof"]["leaf"]));
    assert_eq!(mp.path, hxs(&pr["proof"]["path"]));
}
