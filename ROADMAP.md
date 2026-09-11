# APP 测试网路线图（Auditable Privacy Payment）

日期：2026-09-11

## 0. 一句话结论

Rust 电路层已经完整可用（payment 22 个测试全绿，wasm 可编译到 wasm32），但从"能出证明"到"测试网可用的产品"还缺四大块：合约本体（Groth16 验证器、链上 Poseidon Merkle 树、资产与冻结逻辑）、wasm 的另一半 API（transfer 证明、memo 加解密、本地树、EVM 编码）、整个网站，以及 snarkfold 的三处数学 bug。另有一个必须先修的协议漏洞：withdraw 电路没有绑定收款地址。

## 1. 现状盘点

| 模块 | 已有 | 状态 |
| --- | --- | --- |
| `payment/` | Deposit（1 输出，可选审计）、Transfer（UTXO m 进 n 出，同一资产，nullifier + freezer，可选审计）、Withdraw（1 输入）；Poseidon（t=3，α=31，8 全轮 + 57 半轮，自定义常数，arkworks sponge）；BabyJubJub 密钥；深度 20 二叉 Merkle 树（带版本化存储）；owner memo = ECDH + AES-GCM（链下）；audit memo = Poseidon 流密码（电路内证明加密正确性） | 22 tests 通过 |
| `wasm/` | keypair、deposit setup/prove/verify、transfer setup（仅 setup）、withdraw setup/prove/verify、compute_commitment、random blind | wasm32 编译通过，API 缺一半 |
| `solidity/` | `Apa.sol` 骨架：nullifier mapping、commitment 数组、事件；Foundry Counter 模板未清理 | 无验证器、无树、无代币、无冻结 |
| `aggregator/` `auditor/` | Hello world | 空 |
| `../snarkfold` | 折叠 + IVC 骨架，9 个单测（仅随机数据） | 真实证明下 step 1 即报错，见 2.5 |
| 前端 | 本仓库没有；同级 `../website` 是 ZeroPay 落地页（React + Vite + wagmi + viem + Tailwind） | 技术栈可复用，代码不可复用 |

电路规模（无审计，来自 `transfer::tests::test_different_cs_size`）：

| 形状 | 约束数 | 公共输入 | pk 大小 |
| --- | --- | --- | --- |
| 2 进 1 出 | 34,743 | 4 | 7 MB |
| 1 进 2 出 | 21,162 | 4 | 4 MB |
| 1 进 3 出 | 23,104 | 5 | 4 MB |
| 2 进 3 出 | 38,627 | 6 | 7 MB |

开审计后每个输出多约 3.5k 约束（ECDH 标量乘 + keypair 证明 + Poseidon 流密码），公共输入多 2 + 3n 个。vk 约 400 B，证明 128 B（压缩）。

## 2. 缺口与问题清单

### 2.1 协议级，必须先修

- **P1 Withdraw 未绑定收款人。** `Withdraw` 公共输入只有 asset、amount、nullifier、freezer、root。任何人看到 mempool 里的提款交易都能拿同一份证明换成自己的地址重放。需要把 `recipient`（address 转 Fr）和可选的 `fee`/`relayer` 加为公共输入。影响 `withdraw.rs`、wasm、合约。
- **P2 Poseidon 参数非标准。** α=31、arkworks sponge 布局，没有任何现成 Solidity 或 JS 实现能对上。好消息是链上只需要 2-to-1 合并哈希，它恰好是一次 permutation：state = [0, left, right]，permute 后取 state[1]。
  - 方案 A：保留参数，自写 `PoseidonT3.sol`（65 轮，S-box x^31 约 7 次 mulmod），常数和测试向量由 Rust 脚本生成。估算 20–30k gas / hash，插入一个 commitment 约 20 次 hash ≈ 0.5M gas。
  - 方案 B：换成 circomlib 标准参数（α=5），复用 poseidon-solidity 和 circomlibjs。但 circomlib 的 Poseidon 不是 sponge，5 输入 commitment 哈希要重写 `poseidon.rs` 与 gadget，重跑所有电路测试。
  - 推荐 A。电路不动、工作量小、测试网 gas 可接受；主网前再评估 B。
- **P3 Trusted setup。** `setup()` 用种子确定性生成，测试网可接受：单点生成一次，发布 pk/vk，vk 写入合约。主网需要 MPC。
- **P4 `Keypair::from_seed` 会随机失败。** 它用 `from_random_bytes`，32 个随机字节大于群阶时返回 None。改为 hash-to-scalar 再 mod 群阶。
- **P5 memo 长度约定。** owner memo = 32 B 压缩临时公钥 + 56 B 明文 + 16 B GCM tag = 104 B；audit memo = 160 B。合约事件用 `bytes` 而不是现在的 `bytes32[2]`。
- **P6 `merkle_version` 不在公共输入里。** 合约只需维护最近 N 个 root 的历史窗口（建议 128），校验证明用的 root 在窗口内即可。

### 2.2 合约缺口

- `Groth16Verifier.sol`：基于 BN254 预编译（0x06 加、0x07 乘、0x08 配对），每个电路一个 vk，公共输入个数不同。
- `IncrementalMerkleTree.sol`：深度 20，零叶 = 0，父 = PoseidonT3(left, right)，与 Rust `MerkleTree` 逐位对齐；root 历史窗口。
- `APP.sol` 主合约：资产注册（assetId ↔ ERC20 或原生币）、`deposit`（transferFrom）、`transfer`、`withdraw`（转给 recipient）、nullifier 集合、freezer 集合与 auditor 角色的 freeze/unfreeze、事件（commitment 及其 index、ownerMemo、auditMemo、nullifiers）。
- 编码桥接：arkworks 小端 ↔ `uint256` 大端；G2 坐标顺序 (x.c1, x.c0, y.c1, y.c0)；证明 A 点取负以配合配对预编译。
- `TestToken.sol`：可 mint 的测试 ERC20。
- Phase 2 追加：`submitBatch` + operator 角色 + 批量验证。

### 2.3 wasm 缺口

`transfer_prove`；owner memo 加密/解密；audit 加密（输出 memo 和 share）/解密；nullifier、freezer 计算；把 `MerkleTree<MemoryStorage>` 暴露给 JS（add_leaf、commit、root、generate_proof），用链上事件重建；EVM 编码导出（proof calldata、publics `uint256[]`）；从 secret 字节恢复 keypair；后续按需接 wasm-bindgen-rayon 多线程。

### 2.4 网站缺口（全部新建）

`web/`：Vite + React + TypeScript，wagmi/viem 连接钱包，wasm 跑在 Web Worker。页面：密钥（由钱包签名派生或本地生成）、余额与 UTXO（扫描事件、解 memo、IndexedDB 持久化）、存入、转账、提现、审计员视图（解 audit memo、冻结）、活动记录。pk 文件 4–7 MB 用 Cache API 缓存。

### 2.5 snarkfold 缺口

用真实 deposit 证明实测，当前实现无法通过验证方程，三处 bug：

1. `IVCProver::init()` 的 a_vec 长度为 1、μ=1，与真实实例长度不符，step 1 直接报 "Instance vectors must have same length"，自带示例 `basic_aggregation` 同样失败。
2. `GT::zero()` 被当作空的误差项 E（`folding.rs` 与 `ivc.rs` 两处）。GT 是乘法群，单位元应为 `GT::one()`；现在 E 永远为 0，验证永远失败。
3. 交叉项 t 的符号错了：按代码里的关系式（e(S(t), γ) 在右边），应为 `-(μ2·a1 + μ1·a2)`。

修正后（初始累加器取完全松弛的零实例：a=0、μ=0、E=1、R=0、t=0、κ=0、A=B=C=0；实例向量带首项 1），对 8 个真实证明逐步折叠全部通过，篡改公共输入和伪造证明都被拒绝。

更根本的限制：SnarkFold 的 O(1) 验证需要在 GT（Fq12）里比较一个任意元素 E，而 EVM 配对预编译只能判断 ∏e(P,Q) = 1，拿不到 Miller loop 的值。所以**链上无法 O(1) 验证 SnarkFold 证明**。Phase 2 链上采用 Groth16 随机线性组合批验证（n+3 次配对代替 4n 次），SnarkFold 证明用于链下原生验证（审计方、轻客户端、跨链结算）；Phase 3 再研究 decider 电路把它压成一个链上可验的证明。

## 3. 分期方案

### Phase 0 协议修补（已完成 2026-09-11）

| 步骤 | 内容 | 验收 |
| --- | --- | --- |
| 0.1 ✅ | withdraw 加 recipient、fee 公共输入，补测试 | 换 recipient 后证明验证失败 |
| 0.2 ✅ | 固定 Phase 1 电路形状：deposit（审计开）、transfer 2 进 2 出（审计开）、withdraw；固定种子生成 pk/vk；vk 导出为 Solidity 常量；pk 上传静态托管 | vk 常量文件 + pk 下载链接 |
| 0.3 ✅ | wasm 补齐 2.3 全部 API 与 EVM 编码；Rust 端 round-trip 测试；Node 冒烟测试 `wasm/tests/smoke.mjs` | `cargo test` 全绿；wasm 产物 1.4 MB；2×2 审计转账在 Node 单线程出证 20 s |
| 0.4 ✅ | 修 P4 密钥派生（hash-to-scalar） | 1 万随机种子测试通过 |

### Phase 1 浏览器证明，直接上链（进行中，2026-09-11 本地链全流程已通）

| 步骤 | 内容 | 验收 |
| --- | --- | --- |
| 1.1 ✅ | `PoseidonT3.sol` 由 `app-tools poseidon-sol` 生成，与 arkworks sponge 逐位对齐 | forge 对照 Rust 向量通过；80k gas / hash（via-IR 后整笔存入 1.3–1.7M gas） |
| 1.2 ✅ | `IncrementalMerkleTree.sol` + 128 个 root 历史；空节点与 Rust 一样取字面 0 | 连续插入 5 叶后 root 与 Rust 一致 |
| 1.3 ✅ | 三个验证器由 `app-tools setup` 从 vk 生成到 `solidity/src/verifiers/`，forge 用真实证明夹具测试 | 已通过：验证约 245k gas，篡改 commitment / nullifier / recipient 均拒绝 |
| 1.4 ✅ | `APP.sol`（deposit / transfer 2×2 / transfer1 1×2 / withdraw / freeze / 资产注册）+ `TestToken.sol` + `Deploy.s.sol` | 18 个 forge 测试通过；`app-tools e2e` 生成连贯夹具 |
| 1.5 ⏳ | 部署 Base Sepolia（需要一把有测试币的私钥）；本地 anvil 已部署验证 | explorer 可见合约 |
| 1.6 ✅ | `web/`：wagmi 钱包连接、签名派生 zk 密钥、Worker 加载 wasm 与 pk、开发钱包（`?devkey=`） | 待浏览器手动验证 |
| 1.7 ✅ | 链同步：getLogs → wasm 本地树 + 解 memo 得 UTXO 集（内存，15 s 轮询；IndexedDB 后续） | Node 端到端脚本验证本地 root == 链上 root |
| 1.8 ✅ | 存入 / 转账（自动选 1 或 2 个输入）/ 提现 UI，带进度与活动日志 | 逻辑层由 `web/scripts/e2e-anvil.mjs` 全流程验证 |
| 1.9 ✅ | 审计员页：导入审计密钥，解密全部 audit memo，一键 freeze / unfreeze | 端到端脚本：冻结后花费被拒，解冻后成功 |
| 1.10 | 测试网端到端 + 浏览器证明耗时实测；超过 30 秒则上 rayon 多线程 | 两个浏览器账号完成完整链路 |

### Phase 2 聚合器服务（2026-09-11 本地链全流程已通）

| 步骤 | 内容 | 验收 |
| --- | --- | --- |
| 2.1 ✅ | snarkfold 重写：修三处 bug，去掉未实现的电路占位，新 API `Aggregator` / `aggregate` / `verify_aggregated`（重放折叠记录 + 3 次配对） | 13 个测试用真实 Groth16 证明通过；篡改、伪造、换 vk 均拒绝 |
| 2.2 ✅ | 新增 2×3、1×3 电路形状，第三个输出是给聚合器公钥的手续费票据；服务解 owner memo 核对 fee ≥ 报价；withdraw 的 fee 付给 operator | 端到端脚本验证聚合器密钥能解出手续费票据 |
| 2.3 ✅ | `BatchVerifier.sol` 随机线性组合批验证（n + 3·组 次配对，按组合并 IC 标量）+ `_insertMany` 批量插叶 + `APP.submitBatch` + operator 白名单 | 29 个 forge 测试通过；2 转账 + 1 提现一批 2.29M gas，分开发约 3.1M |
| 2.4 ✅ | `aggregator/`：axum + alloy + sqlite；`/info`、`/tx/transfer`、`/tx/withdraw`、`/tx/:id`、`/batch/:id`；本地验证、链上预检、定时/满额打包 | `web/scripts/e2e-aggregator.mjs` 全流程通过 |
| 2.5 ✅ | 每批按电路分组产出 SnarkFold 聚合证明，`/batch/:id/proof/:group` 提供；`app-tools verify-agg` 原生验证 | 两个批次的聚合证明验证通过 |
| 2.6 ✅ | Transfer / Withdraw 页签增加"通过聚合器"开关，显示报价，轮询状态 | 待浏览器手动验证 |

### 追加：审计员服务（2026-09-11 完成，本地链验证）

| 步骤 | 内容 | 验收 |
| --- | --- | --- |
| A.1 ✅ | `payment` 新增 BabyJubJub Schnorr 签名（`Keypair::sign` / `verify_signature`），wasm 暴露 `sign_message` / `verify_message` | 单测通过 |
| A.2 ✅ | `auditor/` 服务：索引 NewCommitment / NewNullifier / FrozenSet，用审计密钥打开所有 audit memo，维护 Merkle 树；`/notes`、`/proof/:index` 需支付密钥签名鉴权；`/nullifiers/check` 公开；`/audit/notes` 管理端 | `web/scripts/e2e-auditor.mjs` 全流程通过，未鉴权与篡改签名被拒 |
| A.3 ✅ | web `RemoteWallet`：服务可达时自动改为从服务取票据与证明，不扫链、不建树；不可达时回退扫链 | 余额卡片显示同步模式 |
| A.4 ✅ | Auditor 页签默认只解密"本页签打开后"新产生的票据，另有"最近 N 张"和"全部"两种范围；仍在浏览器内用审计密钥解密 | 便于演示；管理端接口留作后续 |

### Phase 3 展望

decider 电路（链上 O(1) 验证聚合证明）、多 ledger 与 facilitator（`app.jpg` 的架构）、跨链结算、MPC setup、安全审计。

## 4. 性能实测（2026-09-11，anvil / M 系列 Mac 单线程）

用户侧出证（wasm，Node 单线程；浏览器同量级）：

| 形状 | 直接上链 | 走聚合器（多一个手续费输出） |
| --- | --- | --- |
| deposit | 4.7 s | 同（存入始终直接上链） |
| 1 进 | 1×2：15.8 s | 1×3：19.3 s |
| 2 进 | 2×2：19.8 s | 2×3：25.9 s |
| withdraw | 6.6 s | 6.6 s（只是 fee 字段不同） |

链上 gas：

| 操作 | 直接上链（每笔） | 聚合器（每笔均摊） |
| --- | --- | --- |
| 转账 | 1×2：1.19–1.29M；2×2：1.33M | 1 笔/批 1.53M；2 笔 0.85M；4 笔 0.56M；8 笔 0.40M；边际每笔约 0.24M |
| 提现 | 0.33M | 2 笔/批 0.28M；8 转账 + 2 提现一批均摊 0.37M |
| 其中 Groth16 验证 | 约 245k（4 次配对） | 每证明约 46k（1 次配对 + 2 次 G1 乘），每组另加 3 次配对 |
| 其中 Poseidon 插叶 | 2 叶约 21 次哈希 ≈ 0.95M | 3n + 20 次哈希摊到 n 笔；8 笔时每笔约 5.5 次 ≈ 0.25M |

聚合器侧（原生 Rust）：Groth16 单笔验证 2.8 ms；SnarkFold 折叠 8 笔 25 ms、100 笔 277 ms；验证聚合证明 8 笔 11.6 ms、100 笔 121 ms（逐笔验证 21 ms / 154 ms）；聚合证明约 570–660 B/笔。服务吞吐受链上 gas 限制而非 CPU。

## 5. 需要拍板的决策（括号为默认值）

- **D1 测试网**：Base Sepolia（默认，便宜且快）/ Sepolia / 其他。
- **D2 Poseidon**：方案 A 保留参数自写 Solidity（默认）/ 方案 B 换标准参数。
- **D3 Phase 1 电路形状**：deposit + 审计、transfer 2 进 2 出 + 审计、withdraw（默认）；是否额外要 1 进 2 出无审计版本。
- **D4 审计是否强制**：合约要求每笔 transfer 带 audit memo（默认强制，符合 auditable 定位）。
- **D5 前端位置**：本仓库 `web/`（默认）或独立仓库。

不另行说明则按默认值推进。
