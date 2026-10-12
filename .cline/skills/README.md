# Web3 Bug Bounty Skills

Kumpulan 11 skill Cline/Claude untuk smart contract security, dipasang di
`.cline/skills/` supaya otomatis terbaca saat workspace ini dibuka di Cline
Desktop (dan kompatibel juga dengan Claude Code / AI lain yang membaca file skill).

## Sumber

- Upstream: https://github.com/awarexone/web3-bug-bounty-hunting-ai-skills
- Dibuat dari 2,749 laporan Immunefi, 681 reproduksi DeFiHackLabs, dan pengalaman hunt nyata.
- Lisensi: MIT (lihat `LICENSE.web3-bug-bounty-hunting-ai-skills`).

## Daftar skill

| Skill | Isi |
|-------|-----|
| `web3-start-here` | Indeks utama + cara navigasi rantai skill |
| `web3-hunt-foundation` | Mindset hunter, target scoring (scorecard 10 poin), recon |
| `web3-bug-classes` | 10 kelas bug DeFi + pola + contoh Solidity |
| `web3-grep-arsenal` | Arsenal grep/regex per kelas bug |
| `web3-poc-foundry` | Panduan PoC Foundry + cheatcodes + template exploit |
| `web3-triage-report` | Gerbang validasi, format laporan Immunefi, 20 contoh dibayar |
| `web3-methodology-research` | Sintesis metodologi ToB, SlowMist, ConsenSys, Cyfrin |
| `web3-case-study-role-misconfig` | Studi kasus hunt: role misconfiguration |
| `web3-ai-tools` | Tools AI (Shannon, SmartGuard, CAI, LuaN1ao) |
| `web3-hunt-zksync-era` | Studi kasus pertahanan: ZKsync Era (0 temuan) |
| `web3-solidity-audit-mcp` | MCP server: Slither + Aderyn + SWC di Claude Code |

## Cara pakai

Buka workspace ini di Cline Desktop — skill akan terdeteksi otomatis.
Untuk mulai, minta agen membaca `.cline/skills/web3-start-here/SKILL.md`.

> Catatan etika: skill ini untuk mengaudit kontrak yang kamu miliki atau punya
> izin eksplisit. Bukan untuk memindai kontrak pihak ketiga tanpa izin.
