# Usalama wa macOS & Kuinua Privilege

{{#include ../../banners/hacktricks-training.md}}

## Msingi wa MacOS

Ikiwa hujafahamu macOS, unapaswa kuanza kujifunza misingi ya macOS:

- Faili maalum za macOS **na ruhusa:**

{{#ref}}
macos-files-folders-and-binaries/
{{#endref}}

- Watumiaji wa kawaida wa macOS

{{#ref}}
macos-users.md
{{#endref}}

- **AppleFS**

{{#ref}}
macos-applefs.md
{{#endref}}

- **Muundo** wa k**ernel**

{{#ref}}
mac-os-architecture/
{{#endref}}

- Huduma za kawaida za macOS n**etwork & protokali**

{{#ref}}
macos-protocols.md
{{#endref}}

- **Opensource** macOS: [https://opensource.apple.com/](https://opensource.apple.com/)
- Ili kupakua `tar.gz` badilisha URL kama [https://opensource.apple.com/**source**/dyld/](https://opensource.apple.com/source/dyld/) kuwa [https://opensource.apple.com/**tarballs**/dyld/**dyld-852.2.tar.gz**](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

### MacOS MDM

Katika kampuni **sistimu za macOS** zina uwezekano mkubwa wa **kusimamiwa na MDM**. Hivyo, kutoka mtazamo wa mshambuliaji ni muhimu kujua **jinsi hiyo inavyofanya kazi**:

{{#ref}}
../macos-red-teaming/macos-mdm/
{{#endref}}

### MacOS - Kukagua, Kurekebisha na Fuzzing

{{#ref}}
macos-apps-inspecting-debugging-and-fuzzing/
{{#endref}}

## Ulinzi wa Usalama wa MacOS

{{#ref}}
macos-security-protections/
{{#endref}}

## Uso wa Shambulio

### Ruhusa za Faili

Ikiwa **mchakato unaotembea kama root unaandika** faili ambayo inaweza kudhibitiwa na mtumiaji, mtumiaji anaweza kuitumia hii ili **kuinua ruhusa**.\
Hii inaweza kutokea katika hali zifuatazo:

- Faili iliyotumika tayari iliumbwa na mtumiaji (inamilikiwa na mtumiaji)
- Faili iliyotumika inaweza kuandikwa na mtumiaji kwa sababu ya kundi
- Faili iliyotumika iko ndani ya directory inayomilikiwa na mtumiaji (mtumiaji anaweza kuunda faili hiyo)
- Faili iliyotumika iko ndani ya directory inayomilikiwa na root lakini mtumiaji ana ufaccess wa kuandika juu yake kwa sababu ya kundi (mtumiaji anaweza kuunda faili hiyo)

Kuweza **kuunda faili** ambayo itatumika na **root**, inamruhusu mtumiaji **kunufaika na maudhui yake** au hata kuunda **symlinks/hardlinks** kuielekeza mahali pengine.

Kwa aina hii ya udhaifu usisahau **kuangalia waandishi wa `.pkg` walio hatarini**:

{{#ref}}
macos-files-folders-and-binaries/macos-installers-abuse.md
{{#endref}}

### Mipangilio ya Faili & Wakala wa mpango wa URL

Programu za ajabu zilizosajiliwa na mipangilio ya faili zinaweza kutumiwa vibaya na programu tofauti zinaweza kusajiliwa kufungua protokali maalum

{{#ref}}
macos-file-extension-apps.md
{{#endref}}

## Kuinua Privilege ya macOS TCC / SIP

Katika macOS **programu na binaries zinaweza kuwa na ruhusa** za kufikia folda au mipangilio ambayo inawafanya kuwa na nguvu zaidi kuliko wengine.

Hivyo, mshambuliaji anayetaka kufanikiwa kuathiri mashine ya macOS atahitaji **kuinua ruhusa zake za TCC** (au hata **kupita SIP**, kulingana na mahitaji yake).

Ruhusa hizi kwa kawaida hutolewa kwa njia ya **entitlements** ambayo programu imeandikwa nayo, au programu inaweza kuomba baadhi ya ufaccess na baada ya **mtumiaji kuidhinisha** zinaweza kupatikana katika **maktaba za TCC**. Njia nyingine mchakato unaweza kupata ruhusa hizi ni kwa kuwa **mtoto wa mchakato** wenye **ruhusa hizo** kwani kwa kawaida **zinarithiwa**.

Fuata viungo hivi kupata njia tofauti za [**kuinua ruhusa katika TCC**](macos-security-protections/macos-tcc/#tcc-privesc-and-bypasses), [**kupita TCC**](macos-security-protections/macos-tcc/macos-tcc-bypasses/) na jinsi katika siku za nyuma [**SIP imepita**](macos-security-protections/macos-sip.md#sip-bypasses).

## Kuinua Privilege ya Kawaida ya macOS

Bila shaka kutoka mtazamo wa timu nyekundu unapaswa pia kuwa na hamu ya kuinua hadi root. Angalia chapisho lifuatalo kwa vidokezo vingine:

{{#ref}}
macos-privilege-escalation.md
{{#endref}}

## Uzingatiaji wa macOS

- [https://github.com/usnistgov/macos_security](https://github.com/usnistgov/macos_security)

## Marejeleo

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://github.com/NicolasGrimonpont/Cheatsheet**](https://github.com/NicolasGrimonpont/Cheatsheet)
- [**https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ**](https://assets.sentinelone.com/c/sentinal-one-mac-os-?x=FvGtLJ)
- [**https://www.youtube.com/watch?v=vMGiplQtjTY**](https://www.youtube.com/watch?v=vMGiplQtjTY)

{{#include ../../banners/hacktricks-training.md}}
