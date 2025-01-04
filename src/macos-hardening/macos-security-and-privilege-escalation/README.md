# macOS Sekuriteit & Privilege Escalering

{{#include ../../banners/hacktricks-training.md}}

## Basiese MacOS

As jy nie vertroud is met macOS nie, moet jy begin om die basiese beginsels van macOS te leer:

- Spesiale macOS **lêers & toestemmings:**

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

- Die **argitektuur** van die k**ernel**

{{#ref}}
mac-os-architecture/
{{#endref}}

- Algemene macOS n**etwerkdienste & protokolle**

{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Om 'n `tar.gz` af te laai, verander 'n URL soos [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) na [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

In maatskappye **macOS** stelsels gaan hoogs waarskynlik **bestuur word met 'n MDM**. Daarom is dit vanuit 'n aanvaller se perspektief interessant om te weet **hoe dit werk**:

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Inspekteer, Debugeer en Fuzz

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## MacOS Sekuriteit Beskermings

{{#ref}}
macos-security-protections/
{{#endref}}

## Aanvaloppervlak

### Lêertoestemmings

As 'n **proses wat as root loop 'n lêer skryf** wat deur 'n gebruiker beheer kan word, kan die gebruiker dit misbruik om **privileges te verhoog**.\
Dit kan in die volgende situasies gebeur:

- Lêer wat gebruik is, is reeds deur 'n gebruiker geskep (besit deur die gebruiker)
- Lêer wat gebruik is, is skryfbaar deur die gebruiker weens 'n groep
- Lêer wat gebruik is, is binne 'n gids besit deur die gebruiker (die gebruiker kan die lêer skep)
- Lêer wat gebruik is, is binne 'n gids besit deur root, maar die gebruiker het skryftoegang daaroor weens 'n groep (die gebruiker kan die lêer skep)

In staat wees om 'n **lêer te skep** wat gaan **gebruik word deur root**, stel 'n gebruiker in staat om **voordeel te trek uit sy inhoud** of selfs **simboliese skakels/hardskakels** te skep om dit na 'n ander plek te wys.

Vir hierdie tipe kwesbaarhede, moenie vergeet om **kwesbare `.pkg` installeerders** te **kontroleer**:

{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Lêeruitbreiding & URL skema app hanteerders

Vreemde apps wat deur lêeruitbreidings geregistreer is, kan misbruik word en verskillende toepassings kan geregistreer word om spesifieke protokolle te open

{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalering

In macOS **toepassings en lêers kan toestemmings hê** om toegang te verkry tot gidse of instellings wat hulle meer bevoorregte maak as ander.

Daarom sal 'n aanvaller wat 'n macOS masjien suksesvol wil kompromitteer, moet **sy TCC-toestemmings verhoog** (of selfs **SIP omseil**, afhangende van sy behoeftes).

Hierdie toestemmings word gewoonlik gegee in die vorm van **regte** waarmee die toepassing onderteken is, of die toepassing mag sekere toegang versoek het en nadat die **gebruiker dit goedgekeur het**, kan dit in die **TCC databasisse** gevind word. 'n Ander manier waarop 'n proses hierdie toestemmings kan verkry, is deur 'n **kind van 'n proses** met daardie **toestemmings** te wees, aangesien dit gewoonlik **geërf** word.

Volg hierdie skakels om verskillende maniere te vind om [**privileges in TCC te verhoog**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), om [**TCC te omseil**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) en hoe in die verlede [**SIP omseil is**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Tradisionele Privilege Escalering

Natuurlik moet jy ook belangstel om na root te verhoog vanuit 'n rooi span se perspektief. Kyk na die volgende pos vir 'n paar wenke:

{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS Nakoming

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Verwysings

- [**OS X Voorval Respons: Scripting en Analise**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
- [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
