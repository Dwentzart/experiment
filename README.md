# Solidity Security Pipeline

Pipeline analisis keamanan smart contract Solidity berbasis **11 agen CrewAI** (14 task berurutan) dengan **lapisan verifikasi deterministik** (Foundry) sebagai gate terakhir.

Status: **eksperimental**. Belum untuk produksi. Ditujukan hanya untuk repository yang kamu miliki atau kamu punya izin eksplisit untuk diaudit.

---

## Daftar isi

- [Apa ini](#apa-ini)
- [Arsitektur](#arsitektur)
- [Model keamanan](#model-keamanan)
- [Instalasi](#instalasi)
- [Struktur workspace](#struktur-workspace)
- [Struktur kode](#struktur-kode)
- [Penggunaan](#penggunaan)
- [Alur eksekusi](#alur-eksekusi)
- [Agen](#agen)
- [Tools](#tools)
- [Kontrol deterministik](#kontrol-deterministik)
- [Hasil](#hasil)
- [Batasan](#batasan)
- [Etika dan legal](#etika-dan-legal)
- [Roadmap](#roadmap)
- [Kontribusi](#kontribusi)
- [Lisensi](#lisensi)
- [Kredit](#kredit)

---

## Apa ini

Pipeline ini menerima satu repository Foundry yang sudah ada di disk, menjalankan sebelas agen analisis berurutan, kemudian memaksa setiap hipotesis melewati verifikasi deterministik.

Tiga belas task pertama menjalankan analisis (ingest, histori, deep-dive, invariant, kritik, debat, judge, state assumption, validasi lokal, lalu satu ronde follow-up). Task terakhir menulis draf laporan. Setelah crew selesai, Python deterministik mengambil alih: static prepass, modern surface scan, pseudo-test audit, artifact reconciliation, dan **bounty eligibility gate v4** yang fail-closed.

Ini **bukan**:

- scanner pengganti auditor,
- alat auto-submit bug bounty,
- generator exploit otonom (PoC hanya divalidasi secara struktural, bukan dipakai untuk menyerang sistem live),
- alat untuk memindai kontrak pihak ketiga tanpa izin.

Yang dihasilkan: draf laporan Markdown berisi hipotesis yang sudah/belum lolos verifikasi lokal, lengkap dengan bukti artefak, integrity snapshot, verdict patch-differential, dan metadata reproducibility. Laporan **wajib** ditinjau manusia sebelum dipakai (`DRAFT`, `HUMAN_REVIEW_REQUIRED`).

---

## Arsitektur

```
                    ┌──────────────────────┐
                    │      PREFLIGHT       │
                    │  foundry.toml audit  │
                    │  forge + forge-std   │
                    │  path / symlink      │
                    └──────────┬───────────┘
                               │ fail → stop, no LLM tokens burned
                               ▼
        ┌──────────────────────────────────────────────┐
        │        STATIC PREPASS + SURFACE SCAN         │
        │  slither / aderyn  (lead, bukan bukti)       │
        │  modern surface scanner (EIP-1153, 7702, …)  │
        └──────────────────┬───────────────────────────┘
                           ▼
        ┌──────────────────────────────────────────────┐
        │        11 CREWAI AGENTS / 14 TASK (seq)      │
        │                                              │
        │  T1   Scope Ingestor                         │
        │  T2   DeFi Security Historian                │
        │  T3   EVM Deep-Dive Security Analyst         │
        │  T4   Smart Contract Invariant Engineer      │
        │  T5   Adversarial Security Critic            │
        │  T6   Vulnerability Debator                  │
        │  T7   Vulnerability Skeptic                  │
        │  T8   Hypothesis Judge                       │
        │  T9   State Assumption Analyst               │
        │  T10  Local Foundry Validation Engineer      │
        │  T11  Follow-up round — deep-dive #2         │
        │  T12  Follow-up round — invariant #2         │
        │  T13  Follow-up round — validasi #2          │
        │  T14  Security Report Writer                 │
        └──────────────────┬───────────────────────────┘
                           │  tools only, no shell
                           ▼
        ┌──────────────────────────────────────────────┐
        │         DETERMINISTIC CONTROL LAYER          │
        │                                              │
        │  path guard        env guard                 │
        │  write guard       forge guard               │
        │  budgets           duplicate registry        │
        │  integrity         evidence store            │
        │  mutation tester   patch-differential        │
        │  PoC validator     confidence ladder         │
        └──────────────────┬───────────────────────────┘
                           ▼
        ┌──────────────────────────────────────────────┐
        │   BOUNTY ELIGIBILITY GATE (v4, fail-closed)  │
        │  judge verdict · authz scan · role grant     │
        │  patch verdict · artifact reconciliation     │
        └──────────────────┬───────────────────────────┘
                           ▼
                  DRAFT + HUMAN_REVIEW_REQUIRED
```

Agen adalah **satu-satunya** bagian yang menggunakan LLM. Semua kontrol di bawahnya adalah Python deterministik — tidak ada keputusan kelayakan bounty yang diserahkan ke model bahasa.

---

## Model keamanan

### Yang dikunci secara paksa

| Kontrol | Detail |
|---|---|
| Subprocess | `shell=False` dan `start_new_session=True` di semua pemanggilan. Forge hanya dipanggil sebagai `forge test --root <project> --offline --fuzz-runs N -vvv [--match-test …] [--match-path …]`, dan executable-nya di-resolve ke path absolut sekali di awal. |
| Environment | Default-deny. Hanya variabel di allowlist (`PATH`, `HOME`, `LANG`, `LC_*`, `TMPDIR`, `TEMP`, `TMP`, `USER`, `LOGNAME`, `SHELL`, `TERM`, `COLORTERM`, `NO_COLOR`, `FORCE_COLOR`, `SSL_CERT_FILE`, `SSL_CERT_DIR`) yang diteruskan. Substring `RPC`, `API_KEY`, `APIKEY`, `TOKEN`, `SECRET`, `PRIVATE`, `PASSWORD`, `PASSPHRASE`, `MNEMONIC`, `SEED`, `CREDENTIAL`, `AUTH`, `PROXY` diblokir, plus daftar eksplisit (`PRIVATE_KEY`, `OPENAI_API_KEY`, `AWS_*`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK`, dst). |
| FFI | Dipaksa `FOUNDRY_FFI=false`, `FORGE_FFI=false` di env. |
| Path | Semua akses file dibatasi `authorized_root` (`resolve_inside_root`). Symlink di komponen path mana pun ditolak untuk baca, tulis, dan evidence. Segmen `..` / `.` / kosong ditolak. |
| Write | Hanya `.t.sol` baru di bawah `test/security_pipeline/`. Path di luar itu otomatis di-redirect ke sana. Tidak boleh overwrite: file dibuka atomic dengan mode `"x"`. |
| `foundry.toml` | Di-parse dengan `tomllib`. Hard reject: `ffi`, `eth_rpc_url`, `rpc_endpoints`, `etherscan_api_key`, `private_key`, `sender`, `unlocked_accounts`, `fork_url`, `fork_block_number`. `fs_permissions` access `read-write` → reject; `read` pada `/` atau `*` → reject; `read` di dalam project → allow + warning. `solc` divalidasi terhadap pola versi. |
| `forge-std` | Wajib ada. Dicari via `remappings.txt` (termasuk mapping context-scoped) lalu fallback `lib/`, `dependencies/`. Tidak ada → preflight gagal sebelum LLM dipanggil. |
| Budget | Forge runs, test writes, mutation runs, patch runs, dan attempt per hipotesis dibatasi di Python, bukan lewat prompt. Refusal (diff buruk, path tidak aman, target di luar kontrak) tidak memakan budget. |
| Regex | Search pattern dicek terhadap bentuk nested quantifier (`_looks_catastrophic`) dan panjang pattern dibatasi; panjang line yang di-regex dibatasi. |
| Output | stdout/stderr di-truncate (`max_output_chars`), evidence item dibatasi (`max_evidence_items`). |
| Integrity | Snapshot `sha256` (`foundry.toml`, `remappings.txt`, `src/`, `script/`, `test/`; `lib/`, `out/`, `cache/`, `.git/`, `.security_pipeline/` dikecualikan) sebelum dan sesudah setiap forge run. Mismatch → `WORKSPACE_TAMPERED`. Snapshot terpotong (`__truncated__`) diperlakukan sebagai UNVERIFIED, bukan sukses. |
| Mutation | Hanya di sandbox `.security_pipeline/mutation_sandbox/`. Workspace asli tidak pernah disentuh. |
| Patch-differential | Hanya di sandbox copy di dalam `authorized_root`. Project yang diaudit tidak pernah dimodifikasi. |

### Yang tidak dilakukan

- Tidak ada fork testing, tidak ada RPC, tidak ada on-chain state. Semua mock-only (`makeAddr`, `new Contract(...)`).
- Tidak ada clone / fetch repository target (`--repo-url` hanya metadata).
- Tidak ada auto-submit ke Immunefi / Code4rena / Sherlock / platform bounty apa pun.
- Tidak ada klaim severity otomatis: severity di laporan harus cocok dengan severity yang diizinkan bounty spec, kalau tidak → `SEVERITY_NOT_ELIGIBLE` / `SEVERITY_UNVERIFIED`.
- Tidak ada generator exploit untuk sistem live. `EXPLOIT_MUST_SUCCEED` hanya divalidasi struktural (assertion profit, balance before/after, state call nyata) — tidak ada eksekusi di luar `forge test`.

### Differential testing

Differential testing **ada**, tapi sempit dan disengaja: lihat [Patch-differential](#patch-differential-verdict). Pipeline tidak membandingkan dua versi kontrak yang berbeda; ia menjalankan test yang sama pada salinan project dengan **fix minimal** yang diusulkan agen diterapkan, lalu membandingkan hasilnya dengan baseline.

---

## Instalasi

Prasyarat:

- Python **3.11+** (butuh `tomllib`).
- [Foundry](https://book.getfoundry.sh/) (`forge` di `PATH`).
- Repository Foundry target, sudah ada di disk. Pipeline **tidak** melakukan clone atau fetch.
- Opsional: `slither` dan/atau `aderyn` di `PATH` untuk static prepass. Kalau tidak ada, prepass dilewati (pipeline tetap jalan).

```bash
git clone https://github.com/Dwentzart/experiment
cd experiment

python -m venv .venv
source .venv/bin/activate

pip install crewai pydantic
```

### Konfigurasi LLM (environment)

Semua konfigurasi model lewat environment variable:

| Variabel | Default | Fungsi |
|---|---|---|
| `OPENAI_MODEL_NAME` | `openai/gpt-5.6-luna` | Model default untuk semua agen. |
| `HEAVY_MODEL` | ikut `OPENAI_MODEL_NAME` | Model untuk role berat: Deep-Dive Analyst, Adversarial Critic, Skeptic, Judge, Validation Engineer. |
| `FAST_MODEL` | ikut `OPENAI_MODEL_NAME` | Model untuk role ringan lainnya. |
| `OPENAI_BASE_URL` | `https://api.vikey.ai/v1` | Base URL endpoint OpenAI-compatible. |
| `OPENAI_API_KEY` | — | API key. |

Zero-config: kalau `HEAVY_MODEL`/`FAST_MODEL` tidak diisi, semua role memakai `OPENAI_MODEL_NAME`.

Contoh tiering:

```bash
export OPENAI_MODEL_NAME=openai/glm-4.6
export HEAVY_MODEL=openai/glm-4.6
export FAST_MODEL=openai/glm-4.5-air
```

Siapkan workspace target:

```bash
mkdir -p workspace
cd workspace
forge init --no-git --no-commit

# forge-std wajib ada
forge install foundry-rs/forge-std --no-git --no-commit

# ganti src/ dengan kontrak yang mau dianalisis
cd ..
```

---

## Struktur workspace

```
workspace/                     ← authorized_root = project_dir
├── foundry.toml
├── src/                       ← target analisis
├── test/
│   └── security_pipeline/     ← satu-satunya lokasi yang boleh ditulis
├── lib/
│   └── forge-std/
└── .security_pipeline/        ← evidence, registry, log, sandbox
```

File pipeline yang perlu ada di root repo:

```
.
├── README.md                  ← file ini
├── pipeline_final.py          ← pipeline utama
└── .gitignore
```

Direktori yang **wajib** di-ignore (isi `.gitignore` di repo ini belum memuat keduanya — tambahkan):

```
.venv/
__pycache__/
*.pyc
workspace/
.security_pipeline/
.env
```

`workspace/` di-ignore karena berisi repository target dan evidence — bukan bagian dari source pipeline.

---

## Struktur kode

Seluruh pipeline berada di satu file, `pipeline_final.py` (±8.700 baris). Tidak ada package atau modul terpisah. Isinya:

- **43 class**, **46 fungsi top-level**, **20 model pydantic**, **8 tool** (`BaseTool`).
- Blok terbesar: `SoliditySecurityCrew` (definisi agen + task), `SecurityAnalysisServices` (orkestrasi semua layanan deterministik), `AgentLogManager` (log + progress bar), `BountyEligibilityGate`.
- Seksi ditandai banner komentar berurutan: `CONFIG` → `ENVIRONMENT` → `PATH / TEXT HELPERS` → `AUTHZ BOUNDARY DETECTOR` → `ROLE-GRANT-TO-ATTACKER DETECTOR` → `MODERN SURFACE SCANNER` → `BUDGET` → `FOUNDRY CONFIG AUDIT` → `FORGE-STD LOCATOR` → `BOUNTY ELIGIBILITY GATE` → `JUDGE VERDICT PARSER` → `BOUNTY SCOPE ENFORCER` → `TEST SPECIFICATION` → `FINDING CONFIDENCE` → `INTEGRITY` → `EVIDENCE STORE` → `ANTI-PSEUDO TEST VALIDATOR` → `SCOPE / DUPLICATE` → `SOURCE SLICER` → `REPRODUCIBILITY LOCK` → `TEST FILE WRITER` → `FORGE RUNNER` → `MUTATION TESTER` → `PATCH-DIFFERENTIAL VALIDATOR` → `EXPLOIT POC VALIDATOR` → `SERVICES` → `TOOL SCHEMAS` → `AGENT LIMITS` → `PSEUDO DETECTION` → `STATIC ANALYSIS PREPASS` → `AGENT LOG MANAGER` → `CREW` → `MAIN`.
- Entry point: `if __name__ == "__main__"` memakai `argparse`, membangun `PipelineConfig`, lalu `SoliditySecurityCrew(config).preflight()` → `.run()`.

Catatan: komentar patch di dalam file memakai penanda `(v2)` / `(v3)` / `(v4)`. Penanda itu menunjukkan **kapan** sebuah kontrol ditambahkan, bukan nomor rilis — konvensi ini didokumentasikan di docstring kepala file.

---

## Penggunaan

### 1. Preflight (tanpa memanggil LLM)

```bash
python3 pipeline_final.py \
    --authorized-root /abs/path/to/workspace \
    --project-dir /abs/path/to/workspace \
    --repo-url https://github.com/owner/repo \
    --preflight-only
```

Contoh output:

```json
{
  "checks": {
    "project_directory": true,
    "foundry_toml": true,
    "forge": true,
    "forge_std": true
  },
  "config_audit": {
    "safe_to_execute": true,
    "errors": [],
    "warnings": [],
    "found_keys": []
  },
  "forge_std_path": "lib/forge-std/src/Test.sol",
  "ready": true
}
```

Jika ada yang gagal:

- `forge_std: false` → jalankan `forge install foundry-rs/forge-std --no-git --no-commit`
- `forge: false` → Foundry belum terpasang atau tidak ada di `PATH`
- `config_audit.safe_to_execute: false` → `foundry.toml` berisi setting yang ditolak (lihat `errors`)
- `ready: false` → pipeline berhenti **sebelum** menyentuh LLM

### 2. Jalankan penuh

```bash
python3 pipeline_final.py \
    --authorized-root /abs/path/to/workspace \
    --project-dir /abs/path/to/workspace \
    --repo-url https://github.com/owner/repo
```

Semua argumen:

| Argumen | Default | Fungsi |
|---|---|---|
| `--authorized-root` | **wajib** | Root workspace. Batas keras semua akses file. |
| `--project-dir` | **wajib** | Root project Foundry (biasanya sama dengan `--authorized-root`). Harus berada di dalam authorized root. |
| `--repo-url` | **wajib** | Metadata saja. Tidak ada clone/fetch. |
| `--forge-timeout` | `600` | Timeout per forge run (detik). Di-cap 3600. |
| `--mutation-timeout` | `180` | Timeout per mutation run (detik). Di-cap 600. |
| `--fuzz-runs` | `64` | Jumlah fuzz run untuk `forge test`. |
| `--max-forge-runs` | `4` | Budget eksekusi forge (termasuk mutation dan patch). |
| `--max-test-writes` | `2` | Budget penulisan file test. |
| `--max-mutation-runs` | `1` | Budget mutation run. |
| `--max-patch-runs` | `2` | Budget patch-differential run. Di-cap 20. |
| `--max-validation-attempts` | `1` | Attempt per hipotesis. Di-cap 3. |
| `--disable-mutation` | off | Matikan mutation testing. |
| `--preflight-only` | off | Preflight saja, keluar tanpa memanggil LLM. |
| `--focus-contracts` | — | Comma-separated nama kontrak yang diaudit. Di-enforce sebagai whitelist di `write_test`, bukan sekadar teks prompt. |
| `--focus-paths` | — | Comma-separated glob path (mis. `src/margin/**,src/vault/**`). |
| `--focus-note` | — | Hint bebas dari analisis manual sebelumnya. |
| `--exclude-contracts` | — | Comma-separated nama kontrak out-of-scope. Menimpa bounty spec. |
| `--bounty-spec` | — | Path JSON bounty spec (lihat di bawah). |
| `--known-issues-file` | — | Path JSON berisi known issues untuk di-skip. |

Contoh:

```bash
python3 pipeline_final.py \
    --authorized-root "$PWD/workspace" \
    --project-dir "$PWD/workspace" \
    --repo-url https://github.com/target-protocol/defi-vault \
    --focus-contracts MarginBank,LiquidityVault \
    --exclude-contracts MockToken,TestHelper \
    --bounty-spec ./bounty.json \
    --known-issues-file ./known.json \
    --max-forge-runs 8 \
    --max-test-writes 4 \
    --fuzz-runs 128
```

### 3. Bounty spec (opsional)

Kalau diisi, scope dan severity di-enforce secara deterministik. Kalau kosong, pipeline jalan dalam mode audit generik (permissive).

```json
{
  "platform": "sherlock",
  "bounty_id": "2026-01-defi-vault",
  "title": "DeFi Vault contest",
  "scope": {
    "contracts": ["LiquidityVault", "MarginBank"],
    "exclude": ["Mock*", "TestHelper"]
  },
  "severity": ["critical", "high"],
  "known_issues": ["rounding dust in share accounting"],
  "out_of_scope": ["privileged users are out of scope"],
  "audits": [{"auditor": "XYZ", "date": "2025-11"}],
  "rewards": {"critical": 100000, "high": 25000, "currency": "USD"}
}
```

Aturan:

- `scope.contracts` = whitelist; `*` dihormati sebagai glob. Kosong = semua diizinkan.
- `scope.exclude` + `--exclude-contracts` = blacklist (juga mendukung glob).
- `known_issues` dibandingkan dengan fingerprint properti hipotesis (Jaccard ≥ 0.65) → ditolak sebagai `KNOWN_ISSUE`.
- Kontrak di luar scope → `OUT_OF_BOUNTY_SCOPE`.
- `out_of_scope` yang menyebut privileged/admin-only → memicu `PRIVILEGED_ONLY_OUT_OF_SCOPE` di gate.

`--known-issues-file` menerima list of string, atau object dengan key `known_issues`.

`BountySpecReader` juga bisa membaca spec langsung dari URL (LLM-based parsing untuk halaman Immunefi/Sherlock/Cantina/self-hosted) dan menyimpannya sebagai JSON. Jalur URL itu belum diekspos sebagai flag CLI — pakai class-nya atau tulis JSON manual.

---

## Alur eksekusi

1. **Preflight** — cek `project_directory`, `foundry.toml`, `forge`, `forge-std`, audit config, tolak symlink. `ready: false` → berhenti, tidak ada token LLM terpakai. Kalau lolos, `preflight.json` + reproducibility lock ditulis.
2. **Static prepass** — `slither` dan/atau `aderyn` (kalau ada di `PATH`) dijalankan dengan env tersanitasi dan timeout yang membunuh process group. Hasilnya **lead, bukan bukti**, disimpan di `static_prepass.json`. Kegagalan tool dilaporkan di `errors`, bukan diam-diam jadi nol temuan.
3. **Modern surface scan** — regex deterministik atas source untuk permukaan modern (EIP-1153 transient storage, EIP-7702, account abstraction, Uniswap v4 hooks, cross-chain, pull oracle, restaking, Permit2, AI oracle, `selfdestruct`). Hasil disuntikkan ke task deep-dive dan follow-up sebagai lead.
4. **Crew berjalan (14 task, sequential)** — lihat [Agen](#agen). Setiap task dicatat ke log per agen.
5. **Pseudo-test audit** — laporan dipindai; blok kode yang tidak meng-import `forge-std`, tidak inherit `Test`, tidak deploy kontrak nyata, atau memakai angka hardcoded → `PSEUDO_TEST_IN_REPORT`.
6. **Deterministic inputs** — `parse_judge_verdicts` (dari blok ```json:judge-verdicts```), authz map hasil scan source, deteksi `grantRole` ke akun bernama `attacker`, dan patch map.
7. **Artifact reconciliation** — setiap finding `reportable` harus punya test terikat, `forge_result.json` yang benar-benar dieksekusi, dan verdict patch-differential `PATCH_CONFIRMED`. Kalau tidak → `RECONCILIATION_FAILED` dan keputusan dipaksa `NON_REPORTABLE`.
8. **Bounty eligibility gate v4** — keputusan `REPORTABLE` / `NON_REPORTABLE` + reason codes. Inputnya hanya bukti deterministik; klaim LLM (`poc_validated`, `integrity_ok`, `attacker_type`) diperlakukan sebagai klaim yang harus diverifikasi.
9. **Output** — laporan draf + blok gate ditulis ke stdout, artefak ke `.security_pipeline/`.

---

## Agen

11 agen, dijalankan `Process.sequential` lewat 14 task. Semua agen `allow_delegation=False` dan dibatasi `max_iter=4`, `max_rpm=10`, `max_execution_time=900` — kecuali Validation Engineer (`max_iter=30`, `max_execution_time=3600`) karena dia yang menulis dan menjalankan test.

| # | Role | Task | Tools | Tier LLM |
|---|---|---|---|---|
| 1 | Solidity Scope Ingestor | `T1` peta arsitektur dari file nyata | list, read, search | fast |
| 2 | DeFi Security Historian | `T2` pola historis yang relevan (precedent ≠ bukti) | — | fast |
| 3 | EVM Deep-Dive Security Analyst | `T3` buktikan invariant bisa dilanggar dengan caller zero-privilege | list, read, search | heavy |
| 4 | Smart Contract Invariant Engineer | `T4` ubah hipotesis jadi spec Foundry terstruktur | read, search | fast |
| 5 | Adversarial Security Critic | `T5` falsifikasi hipotesis dengan bukti source & reachability | read, search | heavy |
| 6 | Vulnerability Debator | `T6` argumen terkuat bahwa hipotesis itu bug nyata | read, search | fast |
| 7 | Vulnerability Skeptic | `T7` cari semua alasan hipotesis itu bukan bug | read, search | heavy |
| 8 | Hypothesis Judge | `T8` putuskan `BUG_VALIDATED` / `NOT_A_BUG` / `BY_DESIGN` / `INCONCLUSIVE` + blok verdict machine-readable | read, search | heavy |
| 9 | State Assumption Analyst | `T9` enumerasi asumsi deployment, tandai fakta tak tersedia `UNVERIFIED` | read | fast |
| 10 | Local Foundry Validation Engineer | `T10` + `T13` tulis test, jalankan forge, mutation, patch-differential | read, write, forge, mutation, patch, confidence | heavy |
| 11 | Security Report Writer | `T14` draf laporan untuk human review | read, confidence | fast |

Ronde follow-up (`T11`–`T13`) memakai agen 3, 4, dan 10 lagi untuk hipotesis yang bertahan, sehingga temuan ronde kedua juga masuk gate dan reconciliation. `T14` sengaja dijalankan **setelah** ronde follow-up, dan judge menerima analisis by-design dari Critic.

Setiap agen punya log sendiri di `.security_pipeline/logs/agents/` dengan prefix urut: `01_ingestor` … `11_reporter`.

---

## Tools

Delapan tool, semuanya berjalan in-process (tidak ada shell tool):

| Tool | Input | Fungsi |
|---|---|---|
| `Read Authorized Solidity File` | `relative_path` | Baca `.sol` / `foundry.toml` di dalam authorized root. Teks repo = data tidak tepercaya. |
| `List Authorized Files` | `relative_path` | Listing dengan traversal terpangkas, vendor/cache dikecualikan. |
| `Search Authorized Source` | `pattern` | Search terbatas; literal substring kecuali diawali `re:`. Pola berbahaya (nested quantifier) ditolak. |
| `Write Authorized Test` | `hypothesis_id`, `relative_path`, `content`, `test_name`, `target_contract`, `target_function`, `test_mode` | Tulis `.t.sol` baru di `test/security_pipeline/`. Validasi kontrak+fungsi target benar-benar ada di source, cek duplikat, cek scope, cek pseudo-test, cek PoC role-grant — semua **sebelum** budget write dikonsumsi. |
| `Forge Test` | `hypothesis_id`, `match_test` | Jalankan `forge test` terbatas (offline, no ffi) pada test terikat. |
| `Mutation Check` | `hypothesis_id`, `test_file`, `match_test` | Mutation terbatas di sandbox, hanya untuk test yang di-generate pipeline. |
| `Patch Differential Check` | `hypothesis_id`, `patch_diff`, `note` | Jalankan test terikat pada salinan project dengan fix minimal diterapkan. |
| `Finding Confidence` | `hypothesis_id` | Baca status evidence ladder hipotesis. |

`test_mode` menentukan arah hasil positif: `INVARIANT_MUST_HOLD` (positif = `TEST_FAILURE`), `PROPERTY_HOLDS_ON_PASS` (positif = `TEST_PASS`), `EXPLOIT_MUST_SUCCEED` (positif = `TEST_PASS`, plus validasi struktural PoC).

---

## Kontrol deterministik

### Budget

Semua budget ditegakkan di Python (`ValidationBudget`), bukan lewat prompt:

| Budget | Flag CLI | Default CLI | Catatan |
|---|---|---|---|
| Forge runs | `--max-forge-runs` | `4` | Termasuk mutation run dan patch run. |
| Test writes | `--max-test-writes` | `2` | Dikonsumsi setelah semua validator konten lolos. |
| Mutation runs | `--max-mutation-runs` | `1` | Bisa dimatikan dengan `--disable-mutation`. |
| Patch runs | `--max-patch-runs` | `2` | Refusal tidak memakan budget. |
| Attempt per hipotesis | `--max-validation-attempts` | `1` | Maksimum 3 setelah normalisasi. |
| Read / list / search | — | `80.000` byte, `2.000` entry, `40` hit | Batas keras untuk tool. |
| Ukuran test file | — | `100.000` byte | Ditolak kalau lebih. |
| Output & evidence | — | `30.000` char, `20` item | stdout/stderr dan evidence di-truncate. |

Setiap respons tool menyertakan snapshot budget (`forge_runs_remaining`, `writes_remaining`, `mutation_runs_remaining`, `patch_runs_remaining`, `attempts`), jadi sisa budget selalu terlihat oleh agen dan reviewer.

### Bounty eligibility gate (v4, fail-closed)

Gate hanya menerima **bukti deterministik**: hasil scan authz di level source, scan PoC role-grant, judge verdict, verdict patch-differential, dan hasil reconciliation artefak. Klaim LLM tidak pernah cukup.

Yang tidak bisa di-override LLM:

- exclusion eksplisit dari bounty spec,
- status privileged-only saat privileged actor dikecualikan,
- klaim `poc_validated` / `integrity_ok` yang tidak punya artefak,
- adanya authz boundary di level source pada fungsi target.

Reason codes yang mungkin muncul:

| Reason code | Arti |
|---|---|
| `SOURCE_AUTHZ_BOUNDARY_PRESENT` | Scan source menemukan boundary otorisasi pada fungsi target (`onlyRole`, `_isStrategy`, konstanta `*_ROLE`, …). |
| `POC_REQUIRES_ROLE_GRANT` | Test memberi role ke akun bernama `attacker` lewat `grantRole`/`setRole` — bukan attacker unprivileged. |
| `JUDGE_VERDICT_MISSING` | Tidak ada blok `json:judge-verdicts` untuk hipotesis itu. |
| `PRIVILEGED_ONLY_OUT_OF_SCOPE` | Bounty spec menyatakan privileged/admin-only out of scope. |
| `POC_NOT_DETERMINISTICALLY_VALIDATED` | Tidak ada test yang benar-benar dieksekusi dengan hasil positif sesuai `test_mode`. |
| `DIRECT_FUND_LOSS_OR_PERMANENT_LOCK_NOT_DETECTED` | Narasi tidak menunjukkan direct fund loss / permanent lock. |
| `ATTACKER_TYPE_UNVERIFIED` | Attacker type tidak bisa ditentukan dari bukti. |
| `SEVERITY_NOT_ELIGIBLE` / `SEVERITY_UNVERIFIED` | Severity di luar daftar bounty spec / tidak terbaca. |
| `PATCH_DIFFERENTIAL_*` | Verdict patch bukan `PATCH_CONFIRMED` (mis. `PATCH_DIFFERENTIAL_NOT_RUN`, `PATCH_DIFFERENTIAL_NO_EFFECT`). |
| `RECONCILIATION_FAILED` | Finding reportable tanpa test terikat atau tanpa artefak forge nyata. |
| `PRIVILEGED_PATH_IN_JSON`, `IMPACT_NOT_FUND_LOSS_OR_LOCK`, `STRUCTURED_DOWNGRADE`, `STRUCTURED_OVERALL_MISMATCH`, `HYPOTHESIS_ID_UNPARSEABLE` | Inkonsistensi blok `json:bounty-gating` yang di-emit reporter. |

Judge verdict yang diakui: `BUG_VALIDATED`, `NOT_A_BUG`, `BY_DESIGN`, `INCONCLUSIVE`. Gate hanya menerima `BUG_VALIDATED`; `BY_DESIGN` tidak reportable.

---

## Hasil

### Evidence artifacts

Semua bukti ditulis ke `.security_pipeline/`:

```
.security_pipeline/
├── preflight.json                     ← hasil preflight + reproducibility lock
├── static_prepass.json                ← lead dari slither/aderyn
├── modern_surfaces.json               ← kategori permukaan modern yang terdeteksi
├── findings.json                      ← registry duplicate/fingerprint
├── gate_inputs.json                   ← judge verdicts, authz map, role grants, patch map, git
├── bounty_eligibility.json            ← keputusan gate + reason codes
├── artifacts/
│   └── HYP-001/
│       ├── test_write.json
│       ├── forge_result.json
│       ├── mutation_result.json
│       ├── patch_diff.json
│       └── confidence.json
├── static/
│   └── aderyn_report.json
├── logs/agents/
│   ├── 01_ingestor.log … 11_reporter.log
│   ├── _tool_calls.log
│   ├── timeline.log
│   ├── SUMMARY.md
│   └── stats.json
└── mutation_sandbox/                  ← hanya selama mutation run
```

Reporter hanya boleh mengutip dari artefak ini, bukan dari ingatan LLM. Test yang di-generate ditulis ke `test/security_pipeline/` di dalam project.

### Finding confidence ladder

Setiap hipotesis punya status berbasis bukti, bukan skor numerik:

```
HYPOTHESIS_ONLY
    ↓
SOURCE_CONFIRMED
    ↓
REACHABILITY_CONFIRMED
    ↓
INVARIANT_CONFIRMED
    ↓
TEST_WRITTEN
    ↓
TEST_EXECUTED
    ↓
TEST_VALIDATED
    ↓
FULL_VALIDATION
```

Status hanya naik kalau tahap deterministiknya benar-benar terjadi; LLM tidak bisa menaikkannya sendiri. Dua sinyal tambahan dilacak terpisah dari ladder: `mutation_killed` (kualitas test) dan `patch_confirmed` (atribusi bug, dikonsumsi gate).

### Forge result type

`TEST_PASS`, `TEST_FAILURE`, `COMPILATION_ERROR`, `EXECUTION_ERROR`, `NO_TESTS_RECOGNIZED`, `UNSAFE_PROJECT_CONFIG`, `BUDGET_EXHAUSTED`.

Interpretasinya bergantung `test_mode` yang direkam saat test ditulis — bukan ditebak dari exit code.

### Mutation status

Mutation check mengukur **kualitas test**, bukan kerentanan protokol. Dua mutasi diterapkan pada test yang di-generate: `assertEq(a, b)` -> `assertEq(a, a)` (tautologi) dan `assertTrue(expr)` -> `assertTrue(!(expr))`. Rewrite kosmetik/komutatif sengaja dihindari karena selalu `SURVIVED` dan menghasilkan sinyal menyesatkan.

| Status | Arti |
|---|---|
| `KILLED_BY_ASSERTION` | Mutant tertangkap oleh assertion. Kill kuat. |
| `KILLED_BY_TEST_FAILURE` | Mutant tertangkap oleh test failure. Kill kuat. |
| `KILLED_BY_COMPILATION_ERROR` | Mutant tidak compile. **Bukan** kill kuat. |
| `SURVIVED` | Test tidak mendeteksi mutasi. Sinyal kualitas lemah. |
| `TIMEOUT` / `EXECUTION_ERROR` | Bukan kill kuat. |
| `NOT_APPLICABLE` | Mutasi tidak bisa diterapkan ke test itu. |
| `BUDGET_EXHAUSTED` | Budget mutation habis. |

Agregat: `PARTIAL_KILL` (campuran) atau `ALL_SURVIVED_OR_INCONCLUSIVE` (lemah). Hanya `KILLED_BY_ASSERTION` dan `KILLED_BY_TEST_FAILURE` dihitung sebagai strong kill.

### Patch-differential verdict

Gate dan reconciliation mensyaratkan `PATCH_CONFIRMED` untuk setiap finding yang reportable. Alurnya: test terikat dijalankan pada salinan project di dalam `authorized_root` dengan unified-diff fix minimal diterapkan, lalu dibandingkan dengan baseline.

Aturan keras: patch hanya boleh menyentuh `.sol` di luar `test/`, dan hanya file yang mendeklarasikan kontrak target atau base yang di-inherit-nya. Project yang diaudit tidak pernah dimodifikasi.

| Verdict | Arti |
|---|---|
| `PATCH_CONFIRMED` | Hasil test berbalik persis seperti prediksi bug. |
| `PATCH_NO_EFFECT` | Hasil sama dengan baseline → bug tidak teratribusi. |
| `PATCH_INCONCLUSIVE` | Hasil berubah tapi tidak sesuai prediksi. |
| `PATCH_INVALID` | Salinan ter-patch gagal compile. |
| `BASELINE_NOT_POSITIVE` | Baseline belum menunjukkan sinyal positif, jadi pembanding tidak bermakna. |
| `SKIPPED` / `REJECTED` | Test tidak ditemukan, di luar `test/security_pipeline/`, diff tidak bisa diparse, atau target patch tidak relevan. |

---

## Batasan

- **Tidak ada verifikasi on-chain.** Semua analisis berdasarkan source code di disk; semua test mock-only.
- **Patch-differential bukan differential testing antar versi.** Ia membandingkan baseline vs salinan dengan fix minimal, bukan dua rilis kontrak.
- **Mutation testing terbatas** pada dua mutasi sederhana dan hanya pada test yang di-generate pipeline. Bukan mutation testing lengkap.
- **Static prepass hanya lead.** Slither/Aderyn tidak wajib ada, dan temuannya tidak pernah dianggap bukti.
- **Source slicing bersifat slice-lite**, bukan SSA/call-graph. Agen tetap membaca file secara utuh.
- **Test `INVARIANT_MUST_HOLD` vs `PROPERTY_HOLDS_ON_PASS` vs `EXPLOIT_MUST_SUCCEED`** dikonfigurasi per hipotesis oleh agen invariant. Salah pilih mode → interpretasi hasil salah. Reviewer manusia wajib memverifikasi.
- **PoC validation bersifat struktural.** `EXPLOIT_MUST_SUCCEED` dicek dari pola assertion/state call, bukan dari eksploitasi sistem nyata.
- **Kualitas temuan sangat bergantung pada LLM** yang menjalankan agen. Konsistensi antar run tidak dijamin.
- **Gate fail-closed bisa menghasilkan false negative.** Temuan valid yang tidak punya test terikat, verdict judge, atau patch-differential `PATCH_CONFIRMED` akan diturunkan menjadi `NON_REPORTABLE`.
- **Bukan pengganti audit manusia.** Pipeline menghasilkan draf, bukan verdict.
- **Test coverage tidak diukur.** Kalau hipotesis tidak disertai test yang benar, pipeline tidak akan tahu.

---

## Etika dan legal

Gunakan hanya pada:

- repository yang kamu miliki, atau
- repository dengan lisensi yang mengizinkan analisis lokal, atau
- program bug bounty yang secara eksplisit mencakup repositori tersebut dalam scope.

Pipeline ini **tidak** melakukan:

- kontak jaringan ke chain atau RPC,
- deploy kontrak,
- interaksi dengan kontrak live,
- eksekusi bytecode di luar `forge test`.

Penggunaan terhadap sistem tanpa izin dapat melanggar hukum. Tanggung jawab sepenuhnya pada pengguna.

---

## Roadmap

Belum diimplementasikan, sengaja ditunda sampai fondasi stabil:

- **Fork-state validation** — replay hipotesis terhadap state fork RPC, dengan credential yang di-inject eksplisit, bukan via environment.
- **Differential testing antar versi** — bandingkan perilaku dua versi kontrak dengan input yang sama (patch-differential saat ini hanya baseline vs fix minimal).
- **Stateful fuzzing** — sequence generator untuk bug state-machine (deposit → borrow → price change → withdraw → liquidate).
- **Program slicing penuh** — call graph dan dependency graph, bukan slice-lite.
- **Parser Forge yang lebih kaya** — mengenali format `forge test --json` dan `--gas-report`.
- **Preflight multi-file & proxy patterns** — validasi target kontrak di balik proxy dan layout multi-file.

---

## Kontribusi

Ini proyek eksperimental. Sebelum membuka PR besar:

1. Jalankan `python3 -c "import ast, pathlib; ast.parse(pathlib.Path('pipeline_final.py').read_text())"`.
2. Pastikan tidak ada `subprocess.run` tanpa `shell=False` dan tanpa `start_new_session=True`.
3. Pastikan tidak ada `Path.write_text` tanpa `reject_symlink_components` di jalur sebelumnya.
4. Pastikan validasi konten baru dijalankan **sebelum** budget dikonsumsi.
5. Tambahkan test untuk setiap perubahan di lapisan deterministik.

Area yang paling berharga untuk dikontribusi:

- Klasifikasi mutation yang lebih akurat.
- Preflight check untuk project multi-file dan proxy patterns.
- Parser Forge untuk output JSON.
- Dokumentasi kasus nyata (berhasil dan gagal).

---

## Lisensi

Belum ditentukan. Tambahkan sebelum publikasi.

---

## Kredit

Diinspirasi oleh praktik nyata PoC-driven smart contract bug bounty, terutama standar PoC Foundry yang digunakan di program-program Immunefi. Pipeline ini bukan afiliasi dengan platform bounty mana pun.
