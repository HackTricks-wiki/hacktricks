# Usalama wa macOS na Kuongezwa kwa Privilege

{{#include ../../banners/hacktricks-training.md}}

## Misingi ya MacOS

Ikiwa huifahamu macOS, unapaswa kuanza kujifunza misingi ya macOS:

- **Faili na permissions** maalum za macOS:


{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- **Users** wa kawaida wa macOS


{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**


{{#ref}}
macos-applefs.md
{{#endref}}

- **Architecture** ya k**ernel**


{{#ref}}
mac-os-architecture/
{{#endref}}

- **Huduma na protocols** za kawaida za macOS


{{#ref}}
macos-protocols.md
{{#endref}}

- macOS ya **Opensource**: [https://opensource.apple.com/](https://opensource.apple.com/)
- Ili kupakua `tar.gz`, badilisha URL kama [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) kuwa [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

Katika makampuni, mifumo ya **macOS** ina uwezekano mkubwa wa kuwa **managed with a MDM**. Kwa hiyo, kwa mtazamo wa attacker, ni muhimu kujua **jinsi inavyofanya kazi**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Kukagua, Debugging na Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Ulinzi wa Usalama wa MacOS


{{#ref}}
macos-security-protections/
{{#endref}}

## Attack Surface

### File Permissions

Ikiwa **process inayoendeshwa kama root itaandika** faili inayoweza kudhibitiwa na user, user anaweza kutumia hali hii **kuongeza privileges**.\
Hili linaweza kutokea katika hali zifuatazo:

- Faili iliyotumika ilikuwa tayari imeundwa na user (inamilikiwa na user)
- Faili iliyotumika inaweza kuandikwa na user kwa sababu ya group
- Faili iliyotumika iko ndani ya directory inayomilikiwa na user (user angeweza kuunda faili)
- Faili iliyotumika iko ndani ya directory inayomilikiwa na root, lakini user ana access ya kuandika humo kwa sababu ya group (user angeweza kuunda faili)

Kuweza **kuunda faili** ambayo itakayotumiwa na **root**, humwezesha user **kutumia vibaya maudhui yake** au hata kuunda **symlinks/hardlinks** zinazoielekeza mahali pengine.

Kwa aina hii ya vulnerabilities, usisahau **kukagua installers za `.pkg` zilizo hatarini**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### File Extension & URL scheme app handlers

Apps zisizo za kawaida zilizosajiliwa kwa file extensions zinaweza kutumiwa vibaya, na applications tofauti zinaweza kusajiliwa ili kufungua protocols maalum


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

Katika macOS, **applications na binaries zinaweza kuwa na permissions** za kufikia folders au settings zinazozifanya ziwe na privileges zaidi kuliko nyingine.

Kwa hiyo, attacker anayetaka kucompromise mashine ya macOS kwa mafanikio atahitaji **kuongeza TCC privileges zake** (au hata **kubypass SIP**, kulingana na mahitaji yake).

Privileges hizi kwa kawaida hutolewa kwa mfumo wa **entitlements** ambazo application imesainiwa nazo, au application inaweza kuwa imeomba access fulani na baada ya **user kuziidhinisha**, zinaweza kupatikana katika **TCC databases**. Njia nyingine ambayo process inaweza kupata privileges hizi ni kuwa **child wa process** yenye **privileges** hizo, kwa kuwa kwa kawaida **hurithiwa**.<sup>[[5]](#references)</sup>

Fuata links hizi ili kupata njia mbalimbali za [**kuongeza privileges katika TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), za [**kubypass TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) na jinsi hapo awali [**SIP ilivyobypassishwa**](macos-security-protections/macos-sip.md#sip-bypasses).

## macOS Traditional Privilege Escalation

Bila shaka, kwa mtazamo wa red teams unapaswa pia kuvutiwa na kuongeza privileges hadi root. Angalia post ifuatayo kwa vidokezo:


{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## macOS Compliance

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## References

- [1] [OS X Incident Response: Scripting and Analysis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis (Patrick Wardle)](https://taomm.org/vol1/analysis.html)
- [3] [NicolasGrimonpont/Cheatsheet — macOS/Linux/Windows commands & security tools cheatsheet](https://github.com/NicolasGrimonpont/Cheatsheet)
- [4] [SentinelOne — macOS Security Resource](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [5] [2022 - macOS local security: escaping the sandbox and bypassing TCC (YouTube)](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
