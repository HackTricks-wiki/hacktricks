# macOS Bezbednost i Eskalacija Privilegija

{{#include ../../banners/hacktricks-training.md}}

## Osnovni MacOS

Ako niste upoznati sa macOS, trebali biste početi učiti osnove macOS-a:

- Specijalni macOS **fajlovi i dozvole:**

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

- Uobičajene macOS n**etwork usluge i protokoli**

{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Da preuzmete `tar.gz`, promenite URL kao što je [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) u [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

U kompanijama **macOS** sistemi će verovatno biti **upravljani putem MDM-a**. Stoga, iz perspektive napadača, zanimljivo je znati **kako to funkcioniše**:

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Istraživanje, Debagovanje i Fuzzing

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS Bezbednosne Zaštite

{{#ref}}
macos-security-protections/
{{#endref}}

## Površina Napada

### Dozvole Fajlova

Ako **proces koji se izvršava kao root piše** fajl koji može kontrolisati korisnik, korisnik bi to mogao zloupotrebiti da **eskalira privilegije**.\
To se može dogoditi u sledećim situacijama:

- Fajl koji se koristi je već kreiran od strane korisnika (u vlasništvu korisnika)
- Fajl koji se koristi je zapisiv od strane korisnika zbog grupe
- Fajl koji se koristi je unutar direktorijuma koji je u vlasništvu korisnika (korisnik može kreirati fajl)
- Fajl koji se koristi je unutar direktorijuma koji je u vlasništvu root-a, ali korisnik ima pristup za pisanje zbog grupe (korisnik može kreirati fajl)

Mogućnost da **kreirate fajl** koji će biti **koristen od strane root-a**, omogućava korisniku da **iskoristi njegov sadržaj** ili čak kreira **simlinkove/hardlinkove** da ga usmeri na drugo mesto.

Za ovu vrstu ranjivosti ne zaboravite da **proverite ranjive `.pkg` instalere**:

{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Rukovaoci aplikacija za ekstenzije fajlova i URL sheme

Čudne aplikacije registrovane po ekstenzijama fajlova mogle bi biti zloupotrebljene, a različite aplikacije mogu biti registrovane da otvore specifične protokole

{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Eskalacija Privilegija

U macOS-u **aplikacije i binarni fajlovi mogu imati dozvole** za pristup folderima ili podešavanjima koja ih čine privilegovanijim od drugih.

Stoga, napadač koji želi uspešno da kompromituje macOS mašinu moraće da **eskalira svoje TCC privilegije** (ili čak **obiđe SIP**, u zavisnosti od njegovih potreba).

Ove privilegije se obično daju u obliku **entiteta** sa kojima je aplikacija potpisana, ili aplikacija može zatražiti neke pristupe i nakon što **korisnik odobri** može ih pronaći u **TCC bazama podataka**. Drugi način na koji proces može dobiti ove privilegije je da bude **dete procesa** sa tim **privilegijama**, jer se obično **nasleđuju**.

Pratite ove linkove da pronađete različite načine za [**eskalaciju privilegija u TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), da [**obiđete TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) i kako je u prošlosti [**SIP bio zaobiđen**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Tradicionalna Eskalacija Privilegija

Naravno, iz perspektive crvenih timova, trebali biste biti zainteresovani i za eskalaciju na root. Proverite sledeći post za neke savete:

{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS Usklađenost

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Reference

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
- [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
