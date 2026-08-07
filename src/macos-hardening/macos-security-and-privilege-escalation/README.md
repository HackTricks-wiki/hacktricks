# macOS-sekuriteit & Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basiese MacOS

As jy nie vertroud is met macOS nie, moet jy begin deur die basiese beginsels van macOS te leer:

- Spesiale macOS **lêers & permissions:**


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- Algemene macOS **gebruikers**


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- Die **argitektuur** van die k**ern**


{{#ref}}
mac-os-architecture/
{{#endref}}

- Algemene macOS n**etwerkdienste & protokolle**


{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Om ’n `tar.gz` af te laai, verander ’n URL soos [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) na [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

In maatskappye gaan **macOS**-stelsels hoogs waarskynlik **met ’n MDM bestuur word**. Daarom is dit vanuit ’n aanvaller se perspektief interessant om te weet **hoe dit werk**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Inspeksie, Debugging en Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS-sekuriteitsbeskermings


{{#ref}}
macos-security-protections/
{{#endref}}

## Aanvalsoppervlak

### File Permissions

As ’n **proses wat as root loop ’n** lêer **skryf** wat deur ’n gebruiker beheer kan word, kan die gebruiker dit misbruik om **privileges te eskaleer**.\
Dit kan in die volgende situasies gebeur:

- Die gebruikte lêer is reeds deur ’n gebruiker geskep (besit deur die gebruiker)
- Die gebruikte lêer is deur die gebruiker skryfbaar weens ’n groep
- Die gebruikte lêer is binne ’n gids wat deur die gebruiker besit word (die gebruiker kan die lêer skep)
- Die gebruikte lêer is binne ’n gids wat deur root besit word, maar die gebruiker het skryftoegang daartoe weens ’n groep (die gebruiker kan die lêer skep)

As ’n gebruiker ’n **lêer kan skep** wat deur **root gebruik gaan word**, kan die gebruiker die inhoud daarvan **benut** of selfs **symlinks/hardlinks** skep om dit na ’n ander plek te laat wys.

Vir hierdie soort kwesbaarhede, moenie vergeet om **kwesbare `.pkg`-installers** na te gaan nie:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Lêeruitbreiding & URL-skema-app-handlers

Vreemde apps wat deur lêeruitbreidings geregistreer is, kan misbruik word, en verskillende toepassings kan geregistreer word om spesifieke protokolle oop te maak.


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

In macOS kan **toepassings en binaries permissions hê** om toegang tot gidse of instellings te verkry wat hulle meer privileged as ander maak.

Daarom sal ’n aanvaller wat ’n macOS-masjien suksesvol wil kompromitteer, sy **TCC privileges moet eskaleer** (of selfs **SIP moet omseil**, afhangend van sy behoeftes).

Hierdie privileges word gewoonlik toegeken in die vorm van **entitlements** waarmee die toepassing onderteken is, of die toepassing kan sekere toegange versoek en nadat die **gebruiker dit goedgekeur het**, kan dit in die **TCC-databasisse** gevind word. ’n Ander manier waarop ’n proses hierdie privileges kan verkry, is deur ’n **kind van ’n proses** met daardie **privileges** te wees, aangesien hulle gewoonlik **geërf** word.<sup>[[5]](#references)</sup>

Volg hierdie skakels om verskillende maniere te vind om [**privileges in TCC te eskaleer**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), om [**TCC te omseil**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) en hoe [**SIP in die verlede omseil is**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Traditional Privilege Escalation

Vanuit ’n red team-perspektief behoort jy natuurlik ook daarin belang te stel om na root te eskaleer. Kyk na die volgende plasing vir ’n paar wenke:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS-nakoming

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Verwysings

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
