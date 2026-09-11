//! Developer tooling for Auditable Privacy Payment.
//!
//! ```text
//! app-tools setup [--seed <hex32>] [--out <dir>] [--sol <dir>] [--fixtures <dir>]
//! ```
//! Generates the Phase 1 circuit keys (deposit+audit, transfer 2x2+audit, withdraw),
//! writes `<out>/<name>.pk|.vk`, renders one Solidity verifier per circuit into `<sol>`,
//! and writes a JSON fixture per circuit (one real proof + its public inputs) into
//! `<fixtures>` for Foundry tests.

use app_payment::{
    Keypair, MemoryStorage, MerkleTree, OpenCommitment, deposit, evm, transfer, withdraw,
};
use ark_bn254::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::{fs, path::Path};

const DEFAULT_SEED: [u8; 32] = *b"APP-testnet-setup-seed-v1-000000";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: app-tools setup [--seed <hex32>] [--out <dir>] [--sol <dir>] [--fixtures <dir>]\n       app-tools poseidon-sol [--sol <dir>] [--fixtures <dir>]");
        std::process::exit(2);
    }
    match args[1].as_str() {
        "setup" => setup(&args[2..]),
        "poseidon-sol" => poseidon_sol(&args[2..]),
        "e2e" => e2e(&args[2..]),
        "keygen" => keygen(&args[2..]),
        other => {
            eprintln!("unknown command {other}");
            std::process::exit(2);
        }
    }
}

fn arg(args: &[String], key: &str, default: &str) -> String {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| default.to_string())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn write_keys<P: CanonicalSerialize, V: CanonicalSerialize>(out: &Path, name: &str, pk: &P, vk: &V) {
    let mut pk_bytes = vec![];
    pk.serialize_compressed(&mut pk_bytes).unwrap();
    let mut vk_bytes = vec![];
    vk.serialize_compressed(&mut vk_bytes).unwrap();
    fs::write(out.join(format!("{name}.pk")), &pk_bytes).unwrap();
    fs::write(out.join(format!("{name}.vk")), &vk_bytes).unwrap();
    println!("{name}: pk {} KB, vk {} B", pk_bytes.len() / 1024, vk_bytes.len());
}

fn write_fixture(dir: &Path, name: &str, proof: &transfer::Proof, publics: &[Fr]) {
    let words: Vec<String> = evm::proof_to_evm(proof)
        .chunks(32)
        .map(hex)
        .collect();
    let inputs: Vec<String> = publics.iter().map(|f| hex(&evm::fr_to_bytes32(f))).collect();
    let json = format!(
        "{{\n  \"proof\": [{}],\n  \"inputs\": [{}]\n}}\n",
        words.iter().map(|w| format!("\"{w}\"")).collect::<Vec<_>>().join(", "),
        inputs.iter().map(|w| format!("\"{w}\"")).collect::<Vec<_>>().join(", ")
    );
    fs::write(dir.join(format!("{name}.json")), json).unwrap();
}

/// Public-input vector in the exact order the circuits allocate them.
fn deposit_publics(d: &deposit::Deposit) -> Vec<Fr> {
    let mut v = vec![Fr::from(d.asset), Fr::from(d.amount), d.commitment];
    if let Some(a) = &d.audit {
        v.push(a.auditor.x);
        v.push(a.auditor.y);
        for bytes in a.memo[64..].chunks(32) {
            v.push(Fr::deserialize_compressed(bytes).unwrap());
        }
    }
    v
}

fn transfer_publics(u: &transfer::Utxo) -> Vec<Fr> {
    let mut v = u.nullifiers.clone();
    v.extend(&u.freezers);
    v.extend(&u.commitments);
    v.push(u.merkle_root);
    if let Some(a) = &u.audit {
        v.push(a.auditor.x);
        v.push(a.auditor.y);
        for memo in &a.memos {
            for bytes in memo[64..].chunks(32) {
                v.push(Fr::deserialize_compressed(bytes).unwrap());
            }
        }
    }
    v
}

fn withdraw_publics(w: &withdraw::Withdraw) -> Vec<Fr> {
    vec![
        Fr::from(w.asset),
        Fr::from(w.amount),
        w.nullifier,
        w.freezer,
        w.merkle_root,
        w.recipient,
        Fr::from(w.fee),
    ]
}

fn setup(args: &[String]) {
    let out = Path::new(&arg(args, "--out", "artifacts")).to_path_buf();
    let sol = Path::new(&arg(args, "--sol", "solidity/src/verifiers")).to_path_buf();
    let fixtures = Path::new(&arg(args, "--fixtures", "solidity/test/fixtures")).to_path_buf();
    for d in [&out, &sol, &fixtures] {
        fs::create_dir_all(d).unwrap();
    }
    let seed: [u8; 32] = {
        let s = arg(args, "--seed", "");
        if s.is_empty() {
            DEFAULT_SEED
        } else {
            let raw = s.trim_start_matches("0x");
            let bytes: Vec<u8> = (0..raw.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).expect("bad hex seed"))
                .collect();
            bytes.try_into().expect("seed must be 32 bytes")
        }
    };
    println!("setup seed: {}", hex(&seed));
    let rng = &mut ChaCha20Rng::from_seed(seed);
    // A separate rng for the sample witnesses so fixtures never touch the setup stream.
    let wrng = &mut ChaCha20Rng::from_seed([0x51u8; 32]);

    // --- deposit (audit on) ---------------------------------------------------
    {
        let (pk, vk) = deposit::setup(true, rng).unwrap();
        write_keys(&out, "deposit", &pk, &vk);
        fs::write(sol.join("DepositVerifier.sol"), evm::vk_to_solidity(&vk, "DepositVerifier")).unwrap();

        let owner = Keypair::generate(wrng);
        let auditor = Keypair::generate(wrng);
        let output = OpenCommitment::generate(wrng, 1, 1_000_000, owner.public);
        let (memo, share) = output.audit_encrypt(wrng, &auditor.public).unwrap();
        let circuit = deposit::DepositCircuit {
            asset: 1,
            amount: 1_000_000,
            output,
            audit: Some(deposit::AuditCircuit { auditor: auditor.public, memo, share }),
        };
        let publics = circuit.deposit(wrng).unwrap();
        let proof = deposit::prove(&pk, circuit, wrng).unwrap();
        deposit::verify(&vk, &publics, &proof).unwrap();
        write_fixture(&fixtures, "deposit", &proof, &deposit_publics(&publics));
    }

    // --- transfer shapes (audit on) -------------------------------------------
    for (n_in, name, contract) in [(2usize, "transfer_2x2", "TransferVerifier"), (1usize, "transfer_1x2", "Transfer1Verifier")] {
        let (pk, vk) = transfer::setup(n_in, 2, true, rng).unwrap();
        write_keys(&out, name, &pk, &vk);
        fs::write(sol.join(format!("{contract}.sol")), evm::vk_to_solidity(&vk, contract)).unwrap();

        let owner = Keypair::generate(wrng);
        let receiver = Keypair::generate(wrng);
        let auditor = Keypair::generate(wrng);
        let mut tree = MerkleTree::new(0, MemoryStorage::default()).unwrap();
        let mut inputs = vec![];
        let mut pending = vec![];
        let amounts: Vec<u128> = if n_in == 2 { vec![600, 400] } else { vec![1000] };
        for amt in amounts {
            let c = OpenCommitment::generate(wrng, 1, amt, owner.public);
            let idx = tree.add_leaf(c.commit()).unwrap();
            pending.push((idx, c));
        }
        tree.commit().unwrap();
        for (idx, c) in pending {
            inputs.push(transfer::UtxoInput { commitment: c, merkle_proof: tree.generate_proof(idx).unwrap() });
        }
        let mut outputs = vec![];
        let mut memos = vec![];
        let mut shares = vec![];
        for (amt, to) in [(700u128, receiver.public), (300u128, owner.public)] {
            let c = OpenCommitment::generate(wrng, 1, amt, to);
            let (m, s) = c.audit_encrypt(wrng, &auditor.public).unwrap();
            outputs.push(transfer::UtxoOutput { commitment: c });
            memos.push(m);
            shares.push(s);
        }
        let circuit = transfer::UtxoCircuit {
            keypair: owner,
            inputs,
            outputs,
            audit: Some(transfer::AuditCircuit { auditor: auditor.public, memos, shares }),
        };
        let publics = circuit.utxo(wrng).unwrap();
        let proof = transfer::prove(&pk, circuit, wrng).unwrap();
        transfer::verify(&vk, &publics, &proof).unwrap();
        write_fixture(&fixtures, name, &proof, &transfer_publics(&publics));
    }

    // --- withdraw --------------------------------------------------------------
    {
        let (pk, vk) = withdraw::setup(rng).unwrap();
        write_keys(&out, "withdraw", &pk, &vk);
        fs::write(sol.join("WithdrawVerifier.sol"), evm::vk_to_solidity(&vk, "WithdrawVerifier")).unwrap();

        let owner = Keypair::generate(wrng);
        let mut tree = MerkleTree::new(0, MemoryStorage::default()).unwrap();
        let c = OpenCommitment::generate(wrng, 1, 250, owner.public);
        let idx = tree.add_leaf(c.commit()).unwrap();
        tree.commit().unwrap();
        let merkle_proof = tree.generate_proof(idx).unwrap();
        // recipient = address(0x1234...) as uint256
        let mut addr = [0u8; 20];
        addr[18] = 0x12;
        addr[19] = 0x34;
        let recipient = ark_ff::PrimeField::from_be_bytes_mod_order(&addr);
        let circuit = withdraw::WithdrawCircuit {
            keypair: owner,
            asset: 1,
            amount: 250,
            recipient,
            fee: 5,
            input: c,
            merkle_proof,
        };
        let publics = circuit.withdraw();
        let proof = withdraw::prove(&pk, circuit, wrng).unwrap();
        withdraw::verify(&vk, &publics, &proof).unwrap();
        write_fixture(&fixtures, "withdraw", &proof, &withdraw_publics(&publics));
    }

    println!("done: keys -> {}, verifiers -> {}, fixtures -> {}", out.display(), sol.display(), fixtures.display());
}

// =============================================================================
// poseidon-sol: render PoseidonT3.sol (arkworks-compatible 2-to-1 hash) + vectors
// =============================================================================

const FR_MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

fn poseidon_sol(args: &[String]) {
    use app_payment::poseidon::{FULL_ROUNDS, MDS, PARTIAL_ROUNDS, ROUND_CONSTANTS, poseidon_merge_hash};
    use ark_std::UniformRand;

    let sol = Path::new(&arg(args, "--sol", "solidity/src")).to_path_buf();
    let fixtures = Path::new(&arg(args, "--fixtures", "solidity/test/fixtures")).to_path_buf();
    fs::create_dir_all(&sol).unwrap();
    fs::create_dir_all(&fixtures).unwrap();

    let dec = |f: &Fr| format!("{f}");
    let m = |i: usize, j: usize| dec(&MDS[i][j]);
    let half = FULL_ROUNDS / 2;
    let total = FULL_ROUNDS + PARTIAL_ROUNDS;

    let mut body = String::new();
    for round in 0..total {
        let full = round < half || round >= half + PARTIAL_ROUNDS;
        body.push_str(&format!(
            "            // round {round} ({})\n            s0 := addmod(s0, {}, Q)\n            s1 := addmod(s1, {}, Q)\n            s2 := addmod(s2, {}, Q)\n",
            if full { "full" } else { "partial" },
            dec(&ROUND_CONSTANTS[round][0]),
            dec(&ROUND_CONSTANTS[round][1]),
            dec(&ROUND_CONSTANTS[round][2]),
        ));
        if full {
            body.push_str("            s0 := sbox(s0)\n            s1 := sbox(s1)\n            s2 := sbox(s2)\n");
        } else {
            body.push_str("            s0 := sbox(s0)\n");
        }
        body.push_str("            s0, s1, s2 := mix(s0, s1, s2)\n");
    }

    let src = format!(
        r#"// SPDX-License-Identifier: MIT
// Generated by `app-tools poseidon-sol`. Do not edit by hand.
pragma solidity ^0.8.20;

/// @title PoseidonT3
/// @notice Bit-exact port of the arkworks `PoseidonSponge` used by app-payment
///         (t = 3, rate = 2, capacity = 1, alpha = {alpha}, {full} full + {partial} partial rounds)
///         restricted to the 2-to-1 hash: absorb(left), absorb(right), squeeze(1).
///         hash(l, r) = permute([0, l, r])[1] over the BN254 scalar field.
library PoseidonT3 {{
    uint256 internal constant Q = {q};

    function hash(uint256 l, uint256 r) internal pure returns (uint256 out) {{
        require(l < Q && r < Q, "PoseidonT3: input not in field");
        assembly {{
            // x^31 = x^16 * x^8 * x^4 * x^2 * x
            function sbox(x) -> y {{
                let x2 := mulmod(x, x, Q)
                let x4 := mulmod(x2, x2, Q)
                let x8 := mulmod(x4, x4, Q)
                let x16 := mulmod(x8, x8, Q)
                y := mulmod(mulmod(mulmod(mulmod(x16, x8, Q), x4, Q), x2, Q), x, Q)
            }}
            // state := MDS * state
            function mix(a0, a1, a2) -> n0, n1, n2 {{
                n0 := addmod(addmod(mulmod(a0, {m00}, Q), mulmod(a1, {m01}, Q), Q), mulmod(a2, {m02}, Q), Q)
                n1 := addmod(addmod(mulmod(a0, {m10}, Q), mulmod(a1, {m11}, Q), Q), mulmod(a2, {m12}, Q), Q)
                n2 := addmod(addmod(mulmod(a0, {m20}, Q), mulmod(a1, {m21}, Q), Q), mulmod(a2, {m22}, Q), Q)
            }}

            let s0 := 0
            let s1 := l
            let s2 := r
{body}
            out := s1
        }}
    }}
}}
"#,
        alpha = app_payment::poseidon::POSEIDON_HASH_BYTES_IN_FIELD,
        full = FULL_ROUNDS,
        partial = PARTIAL_ROUNDS,
        q = FR_MODULUS,
        m00 = m(0, 0), m01 = m(0, 1), m02 = m(0, 2),
        m10 = m(1, 0), m11 = m(1, 1), m12 = m(1, 2),
        m20 = m(2, 0), m21 = m(2, 1), m22 = m(2, 2),
        body = body,
    );
    // Yul functions cannot see Solidity constants; inline the modulus literal.
    let src = src.replace(", Q)", &format!(", {FR_MODULUS})"));
    fs::write(sol.join("PoseidonT3.sol"), src).unwrap();

    // --- vectors ---------------------------------------------------------------
    let rng = &mut ChaCha20Rng::from_seed([0x70u8; 32]);
    let be = |f: &Fr| hex(&evm::fr_to_bytes32(f));
    let mut pairs = vec![(Fr::from(0u64), Fr::from(0u64)), (Fr::from(1u64), Fr::from(2u64))];
    for _ in 0..6 {
        pairs.push((Fr::rand(rng), Fr::rand(rng)));
    }
    let hash_l: Vec<String> = pairs.iter().map(|(l, _)| be(l)).collect();
    let hash_r: Vec<String> = pairs.iter().map(|(_, r)| be(r)).collect();
    let hash_h: Vec<String> = pairs.iter().map(|(l, r)| be(&poseidon_merge_hash(*l, *r))).collect();

    // roots after each of 5 sequential inserts (Rust tree: missing nodes are literal 0)
    let mut tree = MerkleTree::new(0, MemoryStorage::default()).unwrap();
    let mut leaves = vec![];
    let mut roots = vec![];
    for _ in 0..5 {
        let leaf = Fr::rand(rng);
        tree.add_leaf(leaf).unwrap();
        tree.commit().unwrap();
        leaves.push(be(&leaf));
        roots.push(be(&tree.get_root().unwrap()));
    }
    let q = |v: &[String]| v.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(", ");
    let json = format!(
        "{{\n  \"hash_l\": [{}],\n  \"hash_r\": [{}],\n  \"hash_h\": [{}],\n  \"leaves\": [{}],\n  \"roots\": [{}]\n}}\n",
        q(&hash_l),
        q(&hash_r),
        q(&hash_h),
        q(&leaves),
        q(&roots)
    );
    fs::write(fixtures.join("poseidon.json"), json).unwrap();
    println!("wrote {} and {}", sol.join("PoseidonT3.sol").display(), fixtures.join("poseidon.json").display());
}

// =============================================================================
// e2e: coherent deposit -> transfer -> withdraw fixture for the APP contract tests
// =============================================================================

fn e2e(args: &[String]) {
    use ark_ff::PrimeField;

    let keys = Path::new(&arg(args, "--keys", "artifacts")).to_path_buf();
    let fixtures = Path::new(&arg(args, "--fixtures", "solidity/test/fixtures")).to_path_buf();
    fs::create_dir_all(&fixtures).unwrap();
    let load = |name: &str| -> (transfer::ProvingKey, transfer::VerifyingKey) {
        let pk = transfer::ProvingKey::deserialize_compressed(&fs::read(keys.join(format!("{name}.pk"))).unwrap()[..]).unwrap();
        let vk = transfer::VerifyingKey::deserialize_compressed(&fs::read(keys.join(format!("{name}.vk"))).unwrap()[..]).unwrap();
        (pk, vk)
    };
    let (dpk, dvk) = load("deposit");
    let (tpk, tvk) = load("transfer_2x2");
    let (wpk, wvk) = load("withdraw");

    let rng = &mut ChaCha20Rng::from_seed([0xe2u8; 32]);
    let be = |f: &Fr| hex(&evm::fr_to_bytes32(f));
    let words = |p: &transfer::Proof| evm::proof_to_evm(p).chunks(32).map(hex).map(|w| format!("\"{w}\"")).collect::<Vec<_>>().join(", ");
    let strs = |v: &[String]| v.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(", ");

    let alice = Keypair::generate(rng);
    let bob = Keypair::generate(rng);
    let auditor = Keypair::generate(rng);
    let asset = 1u64;
    let mut tree = MerkleTree::new(0, MemoryStorage::default()).unwrap();

    // --- two deposits to alice ---
    let mut deposits_json = vec![];
    let mut alice_utxos = vec![];
    for amt in [600u128, 400u128] {
        let out = OpenCommitment::generate(rng, asset, amt, alice.public);
        let (amemo, share) = out.audit_encrypt(rng, &auditor.public).unwrap();
        let circuit = deposit::DepositCircuit {
            asset,
            amount: amt,
            output: out.clone(),
            audit: Some(deposit::AuditCircuit { auditor: auditor.public, memo: amemo.clone(), share }),
        };
        let publics = circuit.deposit(rng).unwrap();
        let proof = deposit::prove(&dpk, circuit, rng).unwrap();
        deposit::verify(&dvk, &publics, &proof).unwrap();
        let idx = tree.add_leaf(out.commit()).unwrap();
        alice_utxos.push((idx, out));
        deposits_json.push(format!(
            "{{\"asset\": {asset}, \"amount\": {amt}, \"commitment\": \"{}\", \"ownerMemo\": \"{}\", \"auditMemo\": \"{}\", \"proof\": [{}]}}",
            be(&publics.commitment), hex(&publics.memo), hex(&amemo), words(&proof)
        ));
    }
    tree.commit().unwrap();
    let root1 = tree.get_root().unwrap();

    // --- transfer: alice spends 600 + 400 -> 700 bob, 300 alice ---
    let inputs: Vec<transfer::UtxoInput> = alice_utxos
        .iter()
        .map(|(idx, c)| transfer::UtxoInput { commitment: c.clone(), merkle_proof: tree.generate_proof(*idx).unwrap() })
        .collect();
    let out_bob = OpenCommitment::generate(rng, asset, 700, bob.public);
    let out_alice = OpenCommitment::generate(rng, asset, 300, alice.public);
    let mut memos = vec![];
    let mut shares = vec![];
    for c in [&out_bob, &out_alice] {
        let (m, s) = c.audit_encrypt(rng, &auditor.public).unwrap();
        memos.push(m);
        shares.push(s);
    }
    let circuit = transfer::UtxoCircuit {
        keypair: alice.clone(),
        inputs,
        outputs: vec![transfer::UtxoOutput { commitment: out_bob.clone() }, transfer::UtxoOutput { commitment: out_alice.clone() }],
        audit: Some(transfer::AuditCircuit { auditor: auditor.public, memos: memos.clone(), shares }),
    };
    let utxo = circuit.utxo(rng).unwrap();
    assert_eq!(utxo.merkle_root, root1);
    let tproof = transfer::prove(&tpk, circuit, rng).unwrap();
    transfer::verify(&tvk, &utxo, &tproof).unwrap();
    let bob_idx = tree.add_leaf(out_bob.commit()).unwrap();
    tree.add_leaf(out_alice.commit()).unwrap();
    tree.commit().unwrap();
    let root2 = tree.get_root().unwrap();
    let transfer_json = format!(
        "{{\"nullifiers\": [{}], \"freezers\": [{}], \"commitments\": [{}], \"root\": \"{}\", \"ownerMemos\": [{}], \"auditMemos\": [{}], \"proof\": [{}]}}",
        strs(&utxo.nullifiers.iter().map(be).collect::<Vec<_>>()),
        strs(&utxo.freezers.iter().map(be).collect::<Vec<_>>()),
        strs(&utxo.commitments.iter().map(be).collect::<Vec<_>>()),
        be(&root1),
        strs(&utxo.memos.iter().map(|m| hex(m)).collect::<Vec<_>>()),
        strs(&memos.iter().map(|m| hex(m)).collect::<Vec<_>>()),
        words(&tproof)
    );

    // --- withdraw: bob takes 700 to address 0x1234, fee 5 to relayer ---
    let mut addr = [0u8; 20];
    addr[18] = 0x12;
    addr[19] = 0x34;
    let recipient = Fr::from_be_bytes_mod_order(&addr);
    let circuit = withdraw::WithdrawCircuit {
        keypair: bob,
        asset,
        amount: 700,
        recipient,
        fee: 5,
        input: out_bob.clone(),
        merkle_proof: tree.generate_proof(bob_idx).unwrap(),
    };
    let wd = circuit.withdraw();
    assert_eq!(wd.merkle_root, root2);
    let wproof = withdraw::prove(&wpk, circuit, rng).unwrap();
    withdraw::verify(&wvk, &wd, &wproof).unwrap();
    let withdraw_json = format!(
        "{{\"asset\": {asset}, \"amount\": 700, \"nullifier\": \"{}\", \"freezer\": \"{}\", \"root\": \"{}\", \"recipient\": \"{}\", \"fee\": 5, \"proof\": [{}]}}",
        be(&wd.nullifier), be(&wd.freezer), be(&root2), hex(&addr), words(&wproof)
    );

    let json = format!(
        "{{\n  \"auditorX\": \"{}\",\n  \"auditorY\": \"{}\",\n  \"root1\": \"{}\",\n  \"root2\": \"{}\",\n  \"deposits\": [{}],\n  \"transfer\": {},\n  \"withdraw\": {}\n}}\n",
        be(&auditor.public.x), be(&auditor.public.y), be(&root1), be(&root2),
        deposits_json.join(", "), transfer_json, withdraw_json
    );
    fs::write(fixtures.join("e2e.json"), json).unwrap();
    println!("wrote {}", fixtures.join("e2e.json").display());
}

// =============================================================================
// keygen: fresh BabyJubJub keypair (e.g. for the testnet auditor)
// =============================================================================

fn keygen(_args: &[String]) {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("os randomness");
    let kp = Keypair::generate(&mut ChaCha20Rng::from_seed(seed));
    let mut sk = vec![];
    kp.secret.serialize_compressed(&mut sk).unwrap();
    println!("secret (32 bytes LE, keep private): {}", hex(&sk));
    println!("public x (EVM bytes32):             {}", hex(&evm::fr_to_bytes32(&kp.public.x)));
    println!("public y (EVM bytes32):             {}", hex(&evm::fr_to_bytes32(&kp.public.y)));
    let mut pk = vec![];
    kp.public.x.serialize_compressed(&mut pk).unwrap();
    kp.public.y.serialize_compressed(&mut pk).unwrap();
    println!("public (wasm x||y LE, 64 bytes):    {}", hex(&pk));
}
