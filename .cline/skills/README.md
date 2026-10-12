# Security / Bug Bounty Skills (Cline)

Kumpulan **171 skill** (format Agent Skills) untuk smart contract security, bug bounty
web2/API, dan red-team. Dipasang di `.cline/skills/<name>/SKILL.md` supaya otomatis
terbaca saat workspace ini dibuka di **Cline Desktop**.

## Cara Cline menemukan skill (penting)

Dari source `@cline/core`: skill harus **tepat satu level** di bawah `.cline/skills/`,
yaitu `.cline/skills/<folder>/SKILL.md`, dan **nama folder wajib sama persis** dengan
field `name` di frontmatter `SKILL.md`. Folder bersarang (mis. `pack/skills/foo/SKILL.md`)
**tidak** akan terdeteksi - karena itu semua skill di sini sudah di-flatten.

Validasi cepat semua skill:

```bash
cd .cline/skills
for d in */; do d=${d%/}; n=$(grep -am1 '^name:' "$d/SKILL.md" | sed 's/name:[[:space:]]*//');
  [ "$n" = "$d" ] || echo "MISMATCH $d / $n"; done; echo done
```

## Paket yang dipasang

### 1. Web3 / Smart Contract (11 skill) - `web3-*`
Sumber: [awarexone/web3-bug-bounty-hunting-ai-skills](https://github.com/awarexone/web3-bug-bounty-hunting-ai-skills) (MIT).
Dibangun dari 2,749 laporan Immunefi + 681 reproduksi DeFiHackLabs.
Mulai dari `web3-start-here`, lalu `web3-bug-classes`, `web3-grep-arsenal`,
`web3-poc-foundry`, `web3-triage-report`, dst.

### 2. HuntPack - web2 bug bounty pipeline (12 skill: 11 + router)
Sumber: [Aetherdz/huntpack](https://github.com/Aetherdz/huntpack) (MIT).
Pipeline 6 tahap: Understand -> Recon -> Hunt -> Discipline -> Prove -> Deliver.
Entry point: skill `router`. Lalu `web2-recon`, `web2-vuln-classes`,
`business-logic-hunter`, `api-security`, `false-positive-killer`,
`triage-validation`, `attack-path-builder`, `report-writing`, dst.

### 3. claude-hunterKit - bug bounty / red-team (148 skill)
Sumber: [vigilantshield/Claude-HunterKit](https://github.com/vigilantshield/Claude-HunterKit) (Apache-2.0).
148 skill terstruktur per domain: `web-*` (51 kelas web), `api-*`, `ai-*` (24 AI/LLM),
`auth-*`, `network-*`, `cloud-*`, `recon-*`, `report-*`.
Referensi payload/wordlist (1,754 file) ada di folder `wordlists/` di root repo -
path skill `wordlists/<domain>/<nama>/` resolve dari root workspace.

## Daftar cepat

| Paket | Jumlah | Prefix | Contoh skill |
|-------|--------|--------|--------------|
| Web3 | 11 | `web3-` | `web3-start-here`, `web3-poc-foundry` |
| HuntPack | 12 | (beragam) | `router`, `web2-vuln-classes`, `api-security` |
| claude-hunterKit | 148 | `web-`, `api-`, `ai-`, ... | `web-23-idor`, `api-04-bola` |

Total: **171 skill**.

## Lisensi

- `LICENSE.web3-bug-bounty-hunting-ai-skills` - MIT (shuvonsec)
- `LICENSE.huntpack` - MIT (Aetherdz)
- claude-hunterKit - Apache-2.0 (vigilantshield), lihat repo upstream.

> Etika: semua skill ini untuk pengujian **yang diotorisasi** saja - target milikmu
> sendiri atau yang kamu punya izin eksplisit. Bukan untuk menyerang sistem pihak
> ketiga tanpa izin.
