import fs from 'node:fs';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const w = require('../pkg-node/wasm.js');
const ROOT = new URL('../..', import.meta.url).pathname;

const rnd = () => crypto.randomBytes(32);
const u64le = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const u128le = (n) => { const b = Buffer.alloc(16); b.writeBigUInt64LE(BigInt(n) & ((1n<<64n)-1n)); b.writeBigUInt64LE(BigInt(n) >> 64n, 8); return b; };
const lo = (n) => BigInt(n) & ((1n<<64n)-1n), hi = (n) => BigInt(n) >> 64n;
const hexToBuf = (h) => Buffer.from(h.slice(2), 'hex');

const t0 = Date.now();
const alice = new w.WasmKeypair(Buffer.from('alice wallet signature bytes...'));
const bob = new w.WasmKeypair(Buffer.from('bob'));
const auditor = new w.WasmKeypair(Buffer.from('auditor'));
const aliceSk = alice.secret_key(), alicePk = alice.public_key();
console.log('keys ok; alice pk', Buffer.from(alicePk).toString('hex').slice(0, 16), '...');
// restore from secret must give same pk
if (Buffer.compare(Buffer.from(w.WasmKeypair.from_secret(aliceSk).public_key()), Buffer.from(alicePk)) !== 0) throw new Error('from_secret mismatch');

// two deposits into the tree for alice: 600 + 400 of asset 1
const tree = new w.WasmMerkleTree(0);
const inputs = [];
for (const amt of [600n, 400n]) {
  const blind = w.generate_random_blind(rnd());
  const comm = w.compute_commitment(1n, lo(amt), hi(amt), alicePk, blind);
  const memo = w.owner_memo_encrypt(1n, lo(amt), hi(amt), alicePk, blind, rnd());
  // receiver-side scan: decrypt memo
  const dec = Buffer.from(w.owner_memo_decrypt(aliceSk, comm, memo));
  if (dec.readBigUInt64LE(0) !== 1n || dec.readBigUInt64LE(8) !== amt) throw new Error('memo decrypt mismatch');
  let bad = false; try { w.owner_memo_decrypt(bob.secret_key(), comm, memo); } catch { bad = true; }
  if (!bad) throw new Error('bob decrypted alice memo');
  const idx = tree.add_leaf(comm);
  inputs.push({ amt, blind, comm, idx });
}
const version = tree.commit();
console.log('tree: count', tree.count(), 'version', version, 'root(evm)', Buffer.from(tree.root_evm()).toString('hex').slice(0, 16), '...');

const inBlob = Buffer.concat(inputs.map(i => Buffer.concat([u64le(1), u128le(i.amt), Buffer.from(i.blind), Buffer.from(tree.proof(i.idx))])));

// outputs: 700 to bob, 300 back to alice; audit memos for each
const outs = [{ amt: 700n, pk: bob.public_key() }, { amt: 300n, pk: alicePk }].map(o => ({ ...o, blind: w.generate_random_blind(rnd()) }));
const outBlob = Buffer.concat(outs.map(o => Buffer.concat([u64le(1), u128le(o.amt), Buffer.from(o.pk), Buffer.from(o.blind)])));
const auditBlob = Buffer.concat(outs.map(o => Buffer.from(w.audit_memo_encrypt(1n, lo(o.amt), hi(o.amt), o.pk, o.blind, auditor.public_key(), rnd()))));

const pk = fs.readFileSync(`${ROOT}/artifacts/transfer_2x2.pk`);
const vk = fs.readFileSync(`${ROOT}/artifacts/transfer_2x2.vk`);
const t1 = Date.now();
const res = w.transfer_prove(pk, aliceSk, inBlob, outBlob, auditor.public_key(), auditBlob, rnd());
const t2 = Date.now();
console.log(`transfer_prove: ${(t2 - t1)} ms, publics=${res.publics.length}, nullifiers=${res.nullifiers.length}, memos=${res.owner_memos.length}, audit=${res.audit_memos.length}`);

const ok = w.groth16_verify_evm(vk, hexToBuf(res.proof), Buffer.concat(res.publics.map(hexToBuf)));
console.log('groth16_verify_evm:', ok);
// tamper
const bad = res.publics.slice(); bad[0] = '0x' + (BigInt(bad[0]) ^ 1n).toString(16).padStart(64, '0');
console.log('tampered verifies (expect false):', w.groth16_verify_evm(vk, hexToBuf(res.proof), Buffer.concat(bad.map(hexToBuf))));

// root in publics equals local tree root
if (res.merkle_root !== '0x' + Buffer.from(tree.root_evm()).toString('hex')) throw new Error('root mismatch');
// nullifier from helper equals circuit output
const n0 = Buffer.from(w.fr_to_evm(w.compute_nullifier(aliceSk, 1n, lo(600n), hi(600n), inputs[0].blind))).toString('hex');
if (res.nullifiers[0] !== '0x' + n0) throw new Error('nullifier mismatch');
// auditor decrypts output 0
const ad = Buffer.from(w.audit_memo_decrypt(auditor.secret_key(), hexToBuf(res.audit_memos[0])));
if (ad.readBigUInt64LE(8) !== 700n) throw new Error('audit decrypt amount mismatch');
if (Buffer.compare(ad.subarray(24, 88), Buffer.from(bob.public_key())) !== 0) throw new Error('audit owner mismatch');
// bob finds his output via owner memo
const bobDec = Buffer.from(w.owner_memo_decrypt(bob.secret_key(), w.fr_from_evm(hexToBuf(res.commitments[0])), hexToBuf(res.owner_memos[0])));
if (bobDec.readBigUInt64LE(8) !== 700n) throw new Error('bob memo mismatch');
console.log('auditor + receiver decryption ok; total', Date.now() - t0, 'ms');
