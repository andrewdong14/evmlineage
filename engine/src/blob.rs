// src/blob.rs — epoch payloads (EIP-4844 blobs)
//
// The payload of an epoch carries the committed events themselves, so that
// anyone holding it can rebuild the index and recompute the anchored root.
//
//   header (64 B): epoch be64 | root 32 | n_events be32 | body_len be32 |
//                  codec u8 | version u8 | reserved 14
//   body:          varint n_dict | n_dict x 32-byte hashes (first-use order) |
//                  per event: varint |S|, varint |T|, |S|+|T| varint indices
//   codec 0 = body as is, codec 1 = zlib (DEFLATE) over the body
//
// A blob holds 4096 field elements of 32 bytes; 31 bytes of each are usable
// for arbitrary data, and every blob is charged 2^17 blob gas whatever its
// fill level (EIP-4844).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::Mutex;

use crate::epsl::EpochRoot;
use crate::sha256;
use crate::store::{Epoch, VertexHash};

pub const BLOB_HEADER_SIZE:  usize = 64;
pub const BLOB_USABLE_BYTES: usize = 4096 * 31;      // 126 976
pub const BLOB_GAS_PER_BLOB: u64   = 1 << 17;        // 131 072
/// Blobs that one transaction may carry since the Fusaka upgrade (EIP-7594).
pub const MAX_BLOBS_PER_TX:  usize = 6;
pub const PAYLOAD_VERSION:   u8    = 2;

/// A committed lineage event: (sources, targets).
pub type Event = (Vec<VertexHash>, Vec<VertexHash>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec { Raw = 0, Zlib = 1 }

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8 & 0x7F) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn get_varint(raw: &[u8], pos: &mut usize) -> Result<u64, String> {
    let (mut v, mut shift) = (0u64, 0u32);
    loop {
        let b = *raw.get(*pos).ok_or("truncated varint")?;
        *pos += 1;
        v |= ((b & 0x7F) as u64) << shift;
        if b < 0x80 { return Ok(v); }
        shift += 7;
        if shift > 63 { return Err("varint too long".into()); }
    }
}

/// Dictionary-code a batch of events: every distinct hash is stored once
/// and events refer to hashes by index.
pub fn encode_events(events: &[Event]) -> Vec<u8> {
    let mut index: HashMap<VertexHash, u64> = HashMap::new();
    let mut table: Vec<VertexHash> = Vec::new();
    let mut refs: Vec<u8> = Vec::new();
    for (sources, targets) in events {
        put_varint(&mut refs, sources.len() as u64);
        put_varint(&mut refs, targets.len() as u64);
        for h in sources.iter().chain(targets.iter()) {
            let i = *index.entry(*h).or_insert_with(|| {
                table.push(*h);
                table.len() as u64 - 1
            });
            put_varint(&mut refs, i);
        }
    }
    let mut out = Vec::with_capacity(10 + 32 * table.len() + refs.len());
    put_varint(&mut out, table.len() as u64);
    for h in &table { out.extend_from_slice(h); }
    out.extend_from_slice(&refs);
    out
}

pub fn decode_events(body: &[u8], n_events: usize) -> Result<Vec<Event>, String> {
    let mut pos = 0usize;
    let n_dict = get_varint(body, &mut pos)? as usize;
    if pos + 32 * n_dict > body.len() { return Err("truncated dictionary".into()); }
    let table: Vec<VertexHash> = (0..n_dict)
        .map(|i| body[pos + 32 * i..pos + 32 * (i + 1)].try_into().unwrap())
        .collect();
    pos += 32 * n_dict;
    let mut events = Vec::with_capacity(n_events);
    for _ in 0..n_events {
        let ns = get_varint(body, &mut pos)? as usize;
        let nt = get_varint(body, &mut pos)? as usize;
        let mut hs = Vec::with_capacity(ns + nt);
        for _ in 0..ns + nt {
            let i = get_varint(body, &mut pos)? as usize;
            hs.push(*table.get(i).ok_or("dictionary index out of range")?);
        }
        let t = hs.split_off(ns);
        events.push((hs, t));
    }
    if pos != body.len() { return Err("trailing bytes in event body".into()); }
    Ok(events)
}

/// Size of the events without dictionary coding: 4 B of counts plus 32 B
/// per referenced hash.
pub fn raw_event_bytes(events: &[Event]) -> usize {
    events.iter().map(|(s, t)| 4 + 32 * (s.len() + t.len())).sum()
}

/// Encode an epoch payload (header + event body).
pub fn encode_blob(epoch: Epoch, root: &VertexHash, events: &[Event], codec: Codec) -> Vec<u8> {
    let mut body = encode_events(events);
    if codec == Codec::Zlib {
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
        enc.write_all(&body).expect("in-memory write");
        body = enc.finish().expect("in-memory write");
    }
    let mut out = vec![0u8; BLOB_HEADER_SIZE];
    out[0..8].copy_from_slice(&epoch.to_be_bytes());
    out[8..40].copy_from_slice(root);
    out[40..44].copy_from_slice(&(events.len() as u32).to_be_bytes());
    out[44..48].copy_from_slice(&(body.len() as u32).to_be_bytes());
    out[48] = codec as u8;
    out[49] = PAYLOAD_VERSION;
    out.extend_from_slice(&body);
    out
}

/// Decode an epoch payload -> (epoch, root, events).
pub fn decode_blob(raw: &[u8]) -> Result<(Epoch, VertexHash, Vec<Event>), String> {
    if raw.len() < BLOB_HEADER_SIZE { return Err(format!("payload too short: {} B", raw.len())); }
    let epoch = u64::from_be_bytes(raw[0..8].try_into().unwrap());
    let root: VertexHash = raw[8..40].try_into().unwrap();
    let n_events = u32::from_be_bytes(raw[40..44].try_into().unwrap()) as usize;
    let body_len = u32::from_be_bytes(raw[44..48].try_into().unwrap()) as usize;
    if raw[49] != PAYLOAD_VERSION { return Err(format!("unsupported payload version {}", raw[49])); }
    if raw.len() != BLOB_HEADER_SIZE + body_len { return Err("payload length mismatch".into()); }
    let body = &raw[BLOB_HEADER_SIZE..];
    let events = match raw[48] {
        0 => decode_events(body, n_events)?,
        1 => {
            let mut plain = Vec::new();
            flate2::read::ZlibDecoder::new(body).read_to_end(&mut plain)
                .map_err(|e| e.to_string())?;
            decode_events(&plain, n_events)?
        }
        c => return Err(format!("unknown codec {c}")),
    };
    Ok((epoch, root, events))
}

/// Number of EIP-4844 blobs a payload of this size occupies.
pub fn blobs_needed(payload_bytes: usize) -> usize {
    payload_bytes.div_ceil(BLOB_USABLE_BYTES).max(1)
}

/// True if the payload fits the blobs that one transaction may carry.
/// commitRoot binds a root to the blobs of its own transaction, so a larger
/// epoch has to be split or sealed earlier.
pub fn fits_one_transaction(payload_bytes: usize) -> bool {
    blobs_needed(payload_bytes) <= MAX_BLOBS_PER_TX
}

#[derive(Debug, Clone)]
pub struct Submission {
    pub epoch:     Epoch,
    pub data_hash: VertexHash,
    pub bytes:     usize,
    pub raw_bytes: usize,
    pub blobs:     usize,
    pub events:    usize,
    /// The payload fits the blobs of one transaction.
    pub one_tx:    bool,
}

/// Publishes epoch payloads. This engine only has the dry-run mode: the
/// payload is encoded, its size recorded, and SHA-256(payload) returned as
/// the data commitment. A live deployment sends the payload as the blobs
/// of the commitRoot transaction.
pub struct BlobPipeline {
    codec:         Codec,
    keep_payloads: bool,
    submissions:   Mutex<Vec<Submission>>,
    payloads:      Mutex<HashMap<Epoch, Vec<u8>>>,
}

impl BlobPipeline {
    pub fn new_dry() -> Self { Self::with(Codec::Raw, false) }

    pub fn with(codec: Codec, keep_payloads: bool) -> Self {
        BlobPipeline { codec, keep_payloads,
                       submissions: Mutex::new(Vec::new()),
                       payloads: Mutex::new(HashMap::new()) }
    }

    pub fn submit(&self, root: &EpochRoot, events: &[Event]) -> Submission {
        let payload = encode_blob(root.epoch, &root.root, events, self.codec);
        let sub = Submission {
            epoch: root.epoch, data_hash: sha256(&payload), bytes: payload.len(),
            raw_bytes: raw_event_bytes(events), blobs: blobs_needed(payload.len()),
            events: events.len(), one_tx: fits_one_transaction(payload.len()),
        };
        self.submissions.lock().unwrap().push(sub.clone());
        if self.keep_payloads {
            self.payloads.lock().unwrap().insert(root.epoch, payload);
        }
        sub
    }

    pub fn submissions(&self) -> Vec<Submission> { self.submissions.lock().unwrap().clone() }
    pub fn payload(&self, epoch: Epoch) -> Option<Vec<u8>> {
        self.payloads.lock().unwrap().get(&epoch).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> VertexHash { sha256(s.as_bytes()) }

    #[test]
    fn payload_roundtrip_both_codecs() {
        let (a, b, c) = (h("a"), h("b"), h("c"));
        let events: Vec<Event> = vec![(vec![a, b], vec![c]), (vec![c], vec![h("d"), h("e")]),
                                      (vec![], vec![h("f")]), (vec![a], vec![c])];
        for codec in [Codec::Raw, Codec::Zlib] {
            let raw = encode_blob(7, &h("root"), &events, codec);
            let (e, root, back) = decode_blob(&raw).unwrap();
            assert_eq!((e, root), (7, h("root")));
            assert_eq!(back, events);
        }
        let raw = encode_blob(7, &h("root"), &events, Codec::Raw);
        assert!(decode_blob(&raw[..10]).is_err());
        let mut extra = raw.clone(); extra.push(0);
        assert!(decode_blob(&extra).is_err());
    }

    #[test]
    fn dictionary_coding_and_blob_count() {
        let shared: Vec<_> = (0..4).map(|i| h(&format!("s{i}"))).collect();
        let events: Vec<Event> = (0..100).map(|i| (shared.clone(), vec![h(&format!("t{i}"))])).collect();
        assert!(encode_events(&events).len() < raw_event_bytes(&events) / 3);
        assert_eq!(blobs_needed(1), 1);
        assert_eq!(blobs_needed(BLOB_USABLE_BYTES), 1);
        assert_eq!(blobs_needed(BLOB_USABLE_BYTES + 1), 2);
        assert_eq!((BLOB_USABLE_BYTES, BLOB_GAS_PER_BLOB), (126_976, 131_072));
        assert!(fits_one_transaction(MAX_BLOBS_PER_TX * BLOB_USABLE_BYTES));
        assert!(!fits_one_transaction(MAX_BLOBS_PER_TX * BLOB_USABLE_BYTES + 1));
    }

    #[test]
    fn pipeline_records_submissions() {
        let bp = BlobPipeline::with(Codec::Raw, true);
        let er = EpochRoot { epoch: 0, root: h("r"), new_vertices: 2, touched: 2 };
        let sub = bp.submit(&er, &[(vec![h("x")], vec![h("y")])]);
        assert_eq!(sub.data_hash, sha256(&bp.payload(0).unwrap()));
        assert_eq!((sub.blobs, sub.events), (1, 1));
        assert!(sub.one_tx);
    }
}
