# macOS Security & Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Osnove macOS-a

Ako niste upoznati sa macOS-om, trebalo bi da počnete učenjem osnova macOS-a:

- Posebne macOS **datoteke i dozvole:**


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

- macOS otvorenog koda (**Opensource**): [https://opensource.apple.com/](https://opensource.apple.com/)
- Za preuzimanje `tar.gz` promenite URL kao što je [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) u [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

U kompanijama će macOS sistemi sa velikom verovatnoćom biti **upravljani pomoću MDM-a**. Zato je iz perspektive napadača korisno znati **kako to funkcioniše**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Inspecting, Debugging and Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## macOS Security Protections


{{#ref}}
macos-security-protections/
{{#endref}}

## Attack Surface

### Dozvole nad datotekama

Ako **proces koji se izvršava kao root upisuje** datoteku koju korisnik može da kontroliše, korisnik bi to mogao da iskoristi za **eskalaciju privilegija**.\
To se može dogoditi u sledećim situacijama:

- Korišćena datoteka je već kreirana od strane korisnika (u vlasništvu korisnika)
- Korišćena datoteka je upisiva od strane korisnika zbog grupe
- Korišćena datoteka se nalazi unutar direktorijuma u vlasništvu korisnika (korisnik može da kreira datoteku)
- Korišćena datoteka se nalazi unutar direktorijuma u vlasništvu root-a, ali korisnik ima dozvolu upisa zbog grupe (korisnik može da kreira datoteku)

Mogućnost **kreiranja datoteke** koju će **koristiti root** omogućava korisniku da **iskoristi njen sadržaj** ili čak kreira **symlink/hardlink** koji će je usmeriti na drugo mesto.

Kod ove vrste ranjivosti ne zaboravite da **proverite ranjive `.pkg` installere**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Rukovaoci aplikacija za ekstenzije datoteka i URL šeme

Neobične aplikacije registrovane preko ekstenzija datoteka mogu biti zloupotrebljene, a različite aplikacije mogu biti registrovane za otvaranje određenih protokola


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

U macOS-u **aplikacije i binarne datoteke mogu imati dozvole** za pristup fasciklama ili podešavanjima zbog kojih imaju veće privilegije od drugih.

Zato će napadač koji želi da uspešno kompromituje macOS mašinu morati da **eskalira svoje TCC privilegije** (ili čak da **zaobiđe SIP**, u zavisnosti od svojih potreba).

Ove privilegije se obično dodeljuju u obliku **entitlements** sa kojima je aplikacija potpisana, ili je aplikacija možda zatražila određene pristupe; nakon što ih **korisnik odobri**, oni se mogu pronaći u **TCC bazama podataka**. Drugi način na koji proces može dobiti ove privilegije jeste da bude **child proces** procesa sa tim **privilegijama**, jer se one obično **nasleđuju**.<sup>[[5]](#references)</sup>

Pratite ove linkove da biste pronašli različite načine za [**eskalaciju privilegija u TCC-u**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), za [**zaobilaženje TCC-a**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) i kako je u prošlosti [**SIP bio zaobiđen**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Traditional Privilege Escalation

Naravno, iz perspektive red team-a trebalo bi da vas zanima i eskalacija do root-a. Pogledajte sledeći tekst za nekoliko smernica:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS Compliance

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Reference

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
