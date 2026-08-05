# macOS bezbednost i eskalacija privilegija

{{#include ../../banners/hacktricks-training.md}}

## Osnove MacOS-a

Ako niste upoznati sa macOS-om, trebalo bi da počnete učenjem osnova macOS-a:

- Posebni macOS **fajlovi i dozvole:**


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- Uobičajeni macOS **korisnici**


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- **Arhitektura** k**ernela**


{{#ref}}
mac-os-architecture/
{{#endref}}

- Uobičajeni macOS n**mrežni servisi i protokoli**


{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Za preuzimanje `tar.gz` promenite URL kao što je [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) u [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

U kompanijama će macOS sistemi vrlo verovatno biti **upravljani pomoću MDM-a**. Zato je iz perspektive napadača korisno znati **kako to funkcioniše**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - pregledanje, debugging i fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## macOS bezbednosne zaštite


{{#ref}}
macos-security-protections/
{{#endref}}

## Površina napada

### Dozvole fajlova

Ako **proces koji se izvršava kao root upisuje** fajl koji korisnik može da kontroliše, korisnik bi to mogao da zloupotrebi za **eskalaciju privilegija**.\
Ovo se može dogoditi u sledećim situacijama:

- Korišćeni fajl je već kreirao korisnik (u vlasništvu je korisnika)
- Korišćeni fajl je korisniku upisiv zbog pripadnosti grupi
- Korišćeni fajl se nalazi unutar direktorijuma čiji je vlasnik korisnik (korisnik može da kreira fajl)
- Korišćeni fajl se nalazi unutar direktorijuma čiji je vlasnik root, ali korisnik ima dozvolu upisa zbog pripadnosti grupi (korisnik može da kreira fajl)

Mogućnost da **kreirate fajl** koji će **koristiti root**, omogućava korisniku da **iskoristi njegov sadržaj** ili čak da kreira **symlinks/hardlinks** koji vode na drugo mesto.

Kod ove vrste ranjivosti ne zaboravite da **proverite ranjive `.pkg` installere**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Rukovaoci ekstenzijama fajlova i URL scheme-ovima

Neobične aplikacije registrovane pomoću ekstenzija fajlova mogu biti zloupotrebljene, a različite aplikacije mogu biti registrovane za otvaranje određenih protokola


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP eskalacija privilegija

U macOS-u **aplikacije i binarni fajlovi mogu imati dozvole** za pristup folderima ili podešavanjima, zbog čega imaju više privilegija od drugih.

Zato će napadač koji želi da uspešno kompromituje macOS mašinu morati da **eskalira svoje TCC privilegije** (ili čak da **zaobiđe SIP**, u zavisnosti od svojih potreba).

Ove privilegije se obično dodeljuju u obliku **entitlements** sa kojima je aplikacija potpisana, ili je aplikacija mogla da zatraži određene pristupe, koji se nakon **odobrenja korisnika** mogu pronaći u **TCC bazama podataka**. Drugi način na koji proces može dobiti ove privilegije jeste da bude **child procesa** sa tim **privilegijama**, jer se one obično **nasleđuju**.

Pratite ove linkove da biste pronašli različite načine za [**eskalaciju privilegija u TCC-u**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), za [**zaobilaženje TCC-a**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) i da biste saznali kako je u prošlosti [**SIP bio zaobiđen**](macos-security-protections/macos-sip.md#sip-bypasses).

## Tradicionalna macOS eskalacija privilegija

Naravno, iz perspektive red team-a trebalo bi da vas zanima i eskalacija do root-a. Pogledajte sledeći post za nekoliko smernica:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS usklađenost

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Reference

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
