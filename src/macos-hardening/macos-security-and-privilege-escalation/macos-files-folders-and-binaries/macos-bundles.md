# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Bundles katika macOS hutumikia kama vyombo vya rasilimali mbalimbali ikiwa ni pamoja na programu, maktaba, na faili nyingine muhimu, na kuonekana kama vitu vya pekee katika Finder, kama vile faili maarufu za `*.app`. Bundle inayokutana mara nyingi ni bundle ya `.app`, ingawa aina nyingine kama `.framework`, `.systemextension`, na `.kext` pia ni za kawaida.

### Essential Components of a Bundle

Ndani ya bundle, hasa ndani ya saraka ya `<application>.app/Contents/`, kuna rasilimali muhimu mbalimbali:

- **\_CodeSignature**: Saraka hii inahifadhi maelezo ya saini ya msimbo ambayo ni muhimu kwa kuthibitisha uhalali wa programu. Unaweza kuchunguza taarifa za saini ya msimbo kwa kutumia amri kama: %%%bash openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64 %%%
- **MacOS**: Inashikilia binary inayoweza kutekelezwa ya programu ambayo inafanya kazi wakati wa mwingiliano wa mtumiaji.
- **Resources**: Hifadhi ya vipengele vya interface ya mtumiaji wa programu ikiwa ni pamoja na picha, hati, na maelezo ya interface (faili za nib/xib).
- **Info.plist**: Inafanya kazi kama faili kuu ya usanidi wa programu, muhimu kwa mfumo kutambua na kuingiliana na programu ipasavyo.

#### Important Keys in Info.plist

Faili ya `Info.plist` ni msingi wa usanidi wa programu, ikiwa na funguo kama:

- **CFBundleExecutable**: Inaelezea jina la faili kuu inayoweza kutekelezwa iliyoko katika saraka ya `Contents/MacOS`.
- **CFBundleIdentifier**: Inatoa kitambulisho cha kimataifa kwa programu, kinachotumika sana na macOS kwa usimamizi wa programu.
- **LSMinimumSystemVersion**: Inaonyesha toleo la chini la macOS linalohitajika kwa programu kufanya kazi.

### Exploring Bundles

Ili kuchunguza maudhui ya bundle, kama `Safari.app`, amri ifuatayo inaweza kutumika: `bash ls -lR /Applications/Safari.app/Contents`

Uchunguzi huu unaonyesha saraka kama `_CodeSignature`, `MacOS`, `Resources`, na faili kama `Info.plist`, kila moja ikihudumu kusudi la kipekee kutoka kwa kulinda programu hadi kufafanua interface yake ya mtumiaji na vigezo vya uendeshaji.

#### Additional Bundle Directories

Mbali na saraka za kawaida, bundles zinaweza pia kujumuisha:

- **Frameworks**: Inashikilia maktaba zilizojumuishwa zinazotumiwa na programu. Frameworks ni kama dylibs zenye rasilimali za ziada.
- **PlugIns**: Saraka ya plug-ins na nyongeza zinazoongeza uwezo wa programu.
- **XPCServices**: Inashikilia huduma za XPC zinazotumiwa na programu kwa mawasiliano yasiyo ya mchakato.

Muundo huu unahakikisha kwamba vipengele vyote muhimu vimefungwa ndani ya bundle, na kuwezesha mazingira ya programu ya moduli na salama.

Kwa maelezo zaidi kuhusu funguo za `Info.plist` na maana zao, hati za waendelezaji wa Apple zinatoa rasilimali nyingi: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

{{#include ../../../banners/hacktricks-training.md}}
