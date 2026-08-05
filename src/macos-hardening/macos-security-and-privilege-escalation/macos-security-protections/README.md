# Ulinzi wa Usalama wa macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper kwa kawaida hutumiwa kurejelea mchanganyiko wa **Quarantine + Gatekeeper + XProtect**, modules 3 za usalama za macOS zinazojaribu **kuwazuia watumiaji kutekeleza software inayoweza kuwa hasidi iliyopakuliwa**.

Maelezo zaidi katika:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Vikomo vya Michakato

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox **huzuia applications** zinazoendeshwa ndani ya sandbox kufanya zaidi ya **vitendo vinavyoruhusiwa vilivyobainishwa kwenye Sandbox profile** ambayo app inaendeshwa nayo. Hii husaidia kuhakikisha kuwa **application itafikia resources zinazotarajiwa pekee**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** ni security framework. Imeundwa **kusimamia permissions** za applications, hasa kwa kudhibiti ufikiaji wao wa vipengele nyeti. Hii inajumuisha vitu kama **location services, contacts, photos, microphone, camera, accessibility, na full disk access**. TCC huhakikisha kuwa apps zinaweza kufikia vipengele hivi tu baada ya kupata idhini ya wazi ya mtumiaji, hivyo kuimarisha privacy na udhibiti wa data binafsi.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch constraints katika macOS ni security feature ya **kudhibiti uanzishaji wa process** kwa kufafanua **nani anaweza ku-launch** process, **jinsi**, na **kutoka wapi**. Zilianzishwa katika macOS Ventura, na hupanga system binaries katika makundi ya constraints ndani ya **trust cache**. Kila executable binary ina seti ya **rules** za **launch** yake, zikiwemo constraints za **self**, **parent**, na **responsible**. Zikapanuliwa kwa third-party apps kama **Environment** Constraints katika macOS Sonoma, features hizi husaidia kupunguza uwezekano wa system exploitation kwa kudhibiti masharti ya ku-launch process.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) ni sehemu nyingine ya macOS's security infrastructure. Kama jina linavyopendekeza, kazi kuu ya MRT ni **kuondoa malware inayojulikana kutoka kwenye systems zilizoambukizwa**.

Mara malware inapogunduliwa kwenye Mac (iwe kupitia XProtect au kwa njia nyingine), MRT inaweza kutumika **kuondoa malware** hiyo kiotomatiki. MRT hufanya kazi kimya nyuma ya pazia na kwa kawaida huendeshwa kila system inaposasishwa au definition mpya ya malware inapopakuliwa (inaonekana rules ambazo MRT hutumia kugundua malware ziko ndani ya binary).

Ingawa XProtect na MRT zote ni sehemu ya security measures za macOS, zinafanya kazi tofauti:

- **XProtect** ni preventative tool. **Hukagua files zinapopakuliwa** (kupitia applications fulani), na ikigundua aina yoyote inayojulikana ya malware, **huzuia file kufunguka**, hivyo kuzuia malware isiambukize system yako tangu mwanzo.
- **MRT**, kwa upande mwingine, ni **reactive tool**. Hufanya kazi baada ya malware kugunduliwa kwenye system, ikiwa na lengo la kuondoa software inayosababisha tatizo ili kusafisha system.

MRT application iko katika **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Usimamizi wa Background Tasks

**macOS** sasa **huonya** kila wakati tool inapotumia **technique inayojulikana ya kudumisha code execution** (kama Login Items, Daemons...), ili mtumiaji ajue vizuri zaidi **ni software ipi inayodumishwa**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Hii huendeshwa na **daemon** iliyoko katika `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` na **agent** iliyoko katika `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

Jinsi **`backgroundtaskmanagementd`** inavyojua kuwa kitu kimesakinishwa kwenye folder ya persistence ni kwa **kupata FSEvents** na kuunda baadhi ya **handlers** kwa ajili yake.<sup>[[1]](#references)</sup>

Zaidi ya hayo, kuna plist file iliyo na **applications zinazojulikana** ambazo mara kwa mara hujipersist, na inayodumishwa na apple, iliyoko katika: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeration

Inawezekana **ku-enumerate zote** background items zilizosanidiwa kwa kutumia Apple cli tool:<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Zaidi ya hayo, inawezekana pia kuorodhesha taarifa hii kwa kutumia [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Maelezo haya yanahifadhiwa katika **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** na Terminal inahitaji FDA.<sup>[[2]](#references)</sup>

### Messing with BTM

Persistence mpya inapopatikana, event ya aina **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** hutokea. Kwa hivyo, njia yoyote ya **kuzuia** **event** hii kutumwa au **agent isitoe alert** kwa mtumiaji itamsaidia mshambuliaji _**bypass**_ BTM.<sup>[[1]](#references)</sup>

- **Kureset database**: Kuendesha command ifuatayo kuta-reset database (inapaswa kuijenga upya kuanzia mwanzo), hata hivyo, kwa sababu fulani, baada ya kuendesha hii, **hakuna persistence mpya itakayopewa alert hadi mfumo ureboot**.<sup>[[1]](#references)</sup>
- **root** inahitajika.
```bash
# Reset the database
sfltool resettbtm
```
- **Stop the Agent**: Inawezekana kutuma signal ya kusimamisha kwa Agent ili **asiwe anamtahadharisha user** wakati detections mpya zinapopatikana.<sup>[[1]](#references)</sup>
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
- **Hitilafu**: Ikiwa **process iliyounda persistence ita-exit mara tu baada yake**, daemon itajaribu **kupata taarifa** kuihusu, **ishindwe**, na **ishindwe kutuma event** inayoonyesha kuwa kitu kipya kinaendelea kufanya persistence.<sup>[[1]](#references)</sup>

## Marejeleo

- [1] [OBTS v6.0: "Demystifying (& Bypassing) macOS's Background Task Management" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [New (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Manage login items and background tasks on Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
