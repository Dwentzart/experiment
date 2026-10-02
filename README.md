# Solidity Security Pipeline

Pipeline analisis keamanan smart contract Solidity berbasis **8 agen CrewAI** dengan **lapisan verifikasi deterministik** (Foundry) sebagai gate terakhir.

Status: **eksperimental**. Belum untuk produksi. Ditujukan hanya untuk repository yang kamu miliki atau kamu punya izin eksplisit untuk diaudit.

---

## Daftar isi

- [Apa ini](#apa-ini)
- [Arsitektur](#arsitektur)
- [Model keamanan](#model-keamanan)
- [Instalasi](#instalasi)
- [Struktur workspace](#struktur-workspace)
- [Penggunaan](#penggunaan)
- [Hasil](#hasil)
- [Batasan](#batasan)
- [Etika dan legal](#etika-dan-legal)
- [Roadmap](#roadmap)
- [Kontribusi](#kontribusi)
- [Lisensi](#lisensi)
- [Kredit](#kredit)

---

## Apa ini

Pipeline ini menerima satu repository Foundry yang sudah ada di disk, menjalankan delapan agen analisis berurutan, kemudian memaksa setiap hipotesis melewati verifikasi deterministik.

Ini **bukan**:

- scanner pengganti auditor,
- alat auto-submit bug bounty,
- proof-of-exploit generator,
- alat untuk memindai kontrak pihak ketiga tanpa izin.

Yang dihasilkan: draf laporan Markdown berisi hipotesis yang sudah/belum lolos verifikasi lokal, lengkap dengan bukti artefak, integrity snapshot, dan metadata reproducibility. Laporan **wajib** ditinjau manusia sebelum dipakai.

---

## Arsitektur

```
                    ┌──────────────────────┐
                    │      PREFLIGHT       │
                    │  foundry.toml audit  │
                    │  forge + forge-std   │
                    │  path / symlink      │
                    └──────────┬───────────┘
                               │  fail → stop, no LLM tokens burned
                               ▼
        ┌──────────────────────────────────────────────┐
        │            8 CREWAI AGENTS (sequential)      │
        │                                              │
        │  1. Scope Ingestor                           │
        │  2. DeFi Security Historian                  │
        │  3. EVM Deep-Dive Analyst                    │
        │  4. Invariant Engineer                       │
        │  5. Adversarial Critic                       │
        │  6. State Assumption Analyst                 │
        │  7. Local Foundry Validation Engineer        │
        │  8. Security Report Writer                   │
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
        │  mutation tester   confidence ladder         │
        └──────────────────┬───────────────────────────┘
                           ▼
                    FOUNDRY EVIDENCE
                           │
                           ▼
                  HUMAN REVIEW REQUIRED
```

Delapan agen adalah **satu-satunya** bagian yang menggunakan LLM. Semua kontrol di bawahnya adalah Python deterministik — tidak ada keputusan keamanan yang diserahkan ke model bahasa.

---

## Model keamanan

### Yang dikunci secara paksa

| Kontrol | Detail |
|---|---|
| Subprocess | `shell=False`. `forge` dipanggil hanya via command family `forge test`. |
| Environment | Default-deny. Hanya variabel yang masuk allowlist diteruskan. Substring `RPC`, `API_KEY`, `TOKEN`, `SECRET`, `PRIVATE`, `MNEMONIC`, `SEED`, `CREDENTIAL`, `AUTH`, `PROXY` diblokir. |
| FFI | `FOUNDRY_FFI=false` di env, `--no-ffi` di CLI. |
| Path | Semua akses file dibatasi `authorized_root`. Symlink di path mana pun ditolak. |
| Write | Hanya `.t.sol` di bawah `test/security_pipeline/`. Tidak boleh overwrite. Atomic open dengan `"x"`. |
| `foundry.toml` | Di-parse dengan `tomllib`. `ffi`, `rpc_endpoints`, `eth_rpc_url`, `etherscan_api_key`, `private_key`, `sender`, `unlocked_accounts`, `fork_url`, `fork_block_number` → hard reject. `fs_permissions read-write` atau `read` pada root → hard reject. |
| `forge-std` | Wajib ada. Jika tidak ada, preflight gagal sebelum LLM dipanggil. |
| Budget | Forge runs, test writes, mutation runs, dan attempts per hipotesis dibatasi di Python, bukan lewat prompt. |
| Output | stdout/stderr di-truncate. Evidence item dibatasi. |
| Integrity | Snapshot `sha256` sebelum dan sesudah setiap forge run; mismatch → `WORKSPACE_TAMPERED`. |
| Mutation | Hanya di sandbox `.security_pipeline/mutation_sandbox/`. Workspace asli tidak pernah disentuh. |

### Yang tidak dilakukan

- Tidak ada fork testing, tidak ada RPC, tidak ada on-chain state.
- Tidak ada differential testing antar versi kontrak.
- Tidak ada auto-submit ke Immunefi / Code4rena / platform bounty apa pun.
- Tidak ada klaim severity otomatis.
- Tidak ada generator PoC exploit.

---

## Instalasi

Prasyarat:

- Python **3.11+** (butuh `tomllib`).
- [Foundry](https://book.getfoundry.sh/) (`forge` di `PATH`).
- Repository Foundry target, sudah ada di disk. Pipeline **tidak** melakukan clone atau fetch.

```bash
git clone https://github.com/Dwentzart/experiment
cd experiment

python -m venv .venv
source .venv/bin/activate

pip install crewai pydantic
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
└── .security_pipeline/        ← evidence, registry, mutation sandbox
```

File pipeline yang perlu ada di root repo:

```
.
├── README.md                  ← file ini
├── pipeline_final.py          ← pipeline utama
└── .gitignore
```

Isi `.gitignore` minimal:

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

## Penggunaan

### 1. Konfigurasi

Edit blok `if __name__ == "__main__"` di `pipeline_final.py`:

```python
config = PipelineConfig(
    repo_url="https://github.com/target-protocol/defi-vault",  # metadata saja
    authorized_root="./workspace",
    project_dir="./workspace",
    forge_timeout=300,
    fuzz_runs=256,
    max_forge_runs=12,
    max_test_writes=9,
    max_mutation_runs=4,
    max_validation_attempts=3,
)
```

`repo_url` hanya metadata. Pipeline tidak melakukan clone/fetch.

### 2. Preflight

```bash
python pipeline_final.py
```

Preflight berjalan lebih dulu. Jika `ready: false`, pipeline berhenti **sebelum** menyentuh LLM. Contoh output:

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
    "warnings": []
  },
  "ready": true
}
```

Jika ada yang gagal:

- `forge_std: false` → jalankan `forge install foundry-rs/forge-std --no-git --no-commit`
- `forge: false` → Foundry belum terpasang atau tidak ada di `PATH`
- `config_audit.safe_to_execute: false` → `foundry.toml` berisi setting yang ditolak (lihat `errors`)

### 3. Jalankan

Jika preflight hijau, pipeline otomatis menjalankan delapan agen. Output akhir adalah draf laporan Markdown dengan status:

```
HUMAN_REVIEW_REQUIRED
```

---

## Hasil

### Evidence artifacts

Semua bukti ditulis ke `.security_pipeline/`:

```
.security_pipeline/
├── preflight.json
├── findings.json                      ← registry duplicate/fingerprint
├── artifacts/
│   ├── HYP-001/
│   │   ├── test_write.json
│   │   ├── forge_result.json
│   │   ├── mutation_result.json
│   │   └── confidence.json
│   └── HYP-002/
│       └── ...
└── mutation_sandbox/                  ← hanya selama mutation run
```

Reporter hanya boleh mengutip dari artefak ini, bukan dari ingatan LLM.

### Finding confidence ladder

Setiap hipotesis memiliki status berbasis bukti, bukan skor numerik:

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
INTEGRITY_OK
    ↓
FULL_VALIDATION
```

Status hanya naik jika tahap deterministiknya benar-benar terjadi. LLM tidak bisa menaikkan statusnya sendiri.

### Mutation status

Mutation check mengukur **kualitas test**, bukan kerentanan protokol. Status yang mungkin:

| Status | Arti |
|---|---|
| `KILLED_BY_ASSERTION` | Mutant tertangkap oleh assertion. Kill kuat. |
| `KILLED_BY_TEST_FAILURE` | Mutant tertangkap oleh test failure. Kill kuat. |
| `KILLED_BY_COMPILATION_ERROR` | Mutant tidak compile. **Bukan** kill kuat. |
| `TIMEOUT` / `EXECUTION_ERROR` | Bukan kill kuat. |
| `SURVIVED` | Test tidak mendeteksi mutasi. Sinyal kualitas lemah. |

Hanya dua status pertama dihitung sebagai strong kill.

---

## Batasan

- **Tidak ada verifikasi on-chain.** Semua analisis berdasarkan source code di disk.
- **Tidak ada differential testing.** Perubahan antar versi kontrak tidak dibandingkan.
- **Mutation testing terbatas** pada dua jenis mutasi sederhana (`assertEq` swap, `assertTrue` → `assertFalse`). Bukan mutation testing lengkap.
- **Source slicing bersifat slice-lite**, bukan SSA/call-graph. Agen tetap membaca file secara utuh.
- **Test `INVARIANT_MUST_HOLD` vs `PROPERTY_HOLDS_ON_PASS`** dikonfigurasi per hipotesis oleh agen invariant. Salah pilih mode → interpretasi hasil salah. Reviewer manusia wajib memverifikasi.
- **Kualitas temuan sangat bergantung pada LLM** yang menjalankan agen. Konsistensi antar run tidak dijamin.
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
- **Differential testing** — bandingkan perilaku dua versi kontrak dengan input yang sama.
- **Stateful fuzzing** — sequence generator untuk bug state-machine (deposit → borrow → price change → withdraw → liquidate).
- **Program slicing penuh** — call graph dan dependency graph, bukan slice-lite.
- **Parser Forge yang lebih kaya** — mengenali format `forge test --json` dan `--gas-report`.

---

## Kontribusi

Ini proyek eksperimental. Sebelum membuka PR besar:

1. Jalankan `python -c "import ast, pathlib; ast.parse(pathlib.Path('pipeline_final.py').read_text())"`.
2. Pastikan tidak ada `subprocess.run` tanpa `shell=False`.
3. Pastikan tidak ada `Path.write_text` tanpa `reject_symlink_components` di jalur sebelumnya.
4. Tambahkan test untuk setiap perubahan di lapisan deterministik.

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
