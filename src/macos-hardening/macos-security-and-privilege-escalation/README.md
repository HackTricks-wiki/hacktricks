# Usalama wa macOS na Kuongeza Privilege

{{#include ../../banners/hacktricks-training.md}}

## Msingi wa MacOS

Ikiwa huifahamu macOS, unapaswa kuanza kujifunza misingi ya macOS:

- **Files & permissions** maalum za macOS:


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

- **Network services & protocols** za kawaida za macOS


{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Ili kupakua `tar.gz`, badilisha URL kama [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) kuwa [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

Katika kampuni, mifumo ya **macOS** ina uwezekano mkubwa wa kuwa **managed with a MDM**. Kwa hivyo, kwa mtazamo wa attacker, ni muhimu kujua **jinsi inavyofanya kazi**:


{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Kukagua, Ku-debug na Kufanya Fuzzing


{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Security Protections za MacOS


{{#ref}}
macos-security-protections/
{{#endref}}

## Attack Surface

### File Permissions

Ikiwa **process inayotumia root itaandika** file inayoweza kudhibitiwa na user, user anaweza kutumia hali hii **kuongeza privileges**.\
Hili linaweza kutokea katika hali zifuatazo:

- File iliyotumika ilikuwa tayari imeundwa na user (inamilikiwa na user)
- File iliyotumika inaweza kuandikwa na user kwa sababu ya group
- File iliyotumika iko ndani ya directory inayomilikiwa na user (user anaweza kuunda file)
- File iliyotumika iko ndani ya directory inayomilikiwa na root, lakini user ana write access juu yake kwa sababu ya group (user anaweza kuunda file)

Kuweza **kuunda file** ambayo **itatumiwa na root**, humruhusu user **kunufaika na maudhui yake** au hata kuunda **symlinks/hardlinks** zinazoielekeza sehemu nyingine.

Kwa aina hii ya vulnerabilities, usisahau **kukagua installers za `.pkg` zilizo hatarini**:


{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### File Extension & URL scheme app handlers

Apps zisizo za kawaida zilizosajiliwa kupitia file extensions zinaweza kutumiwa vibaya, na applications tofauti zinaweza kusajiliwa ili kufungua protocols maalum


{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## macOS TCC / SIP Privilege Escalation

Katika macOS, **applications na binaries zinaweza kuwa na permissions** za kufikia folders au settings zinazozifanya ziwe na privileges zaidi kuliko nyingine.

Kwa hivyo, attacker anayetaka ku-compromise mashine ya macOS kwa mafanikio atahitaji **kuongeza TCC privileges** (au hata **kubypass SIP**, kulingana na mahitaji yake).

Privileges hizi kwa kawaida hutolewa kwa njia ya **entitlements** ambazo application imesainiwa nazo, au application inaweza kuwa imeomba access fulani na baada ya **user kuziidhinisha**, zinaweza kupatikana katika **TCC databases**. Njia nyingine ambayo process inaweza kupata privileges hizi ni kuwa **child wa process** yenye **privileges** hizo, kwa kuwa kwa kawaida **hurithiwa**.

Fuata links hizi ili kupata njia tofauti za [**kuongeza privileges katika TCC**](macos-security-protections/macos-tcc/index.html#tcc-privesc-and-bypasses), za [**kubypass TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/index.html) na jinsi hapo awali [**SIP ilivyobypassiwa**](macos-security-protections/macos-sip.md#sip-bypasses).

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
