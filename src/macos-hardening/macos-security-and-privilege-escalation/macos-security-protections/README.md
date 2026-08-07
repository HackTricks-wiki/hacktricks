# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper kwa kawaida hutumiwa kurejelea mchanganyiko wa **Quarantine + Gatekeeper + XProtect**, modules 3 za usalama za macOS ambazo zitajaribu **kuzuia watumiaji kutekeleza software inayoweza kuwa malicious iliyopakuliwa**.

Maelezo zaidi katika:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Vikomo vya Processes

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox **huwekea mipaka applications** zinazoendesha ndani ya sandbox kwa **actions zinazoruhusiwa zilizoainishwa katika Sandbox profile** ambayo app inaendesha nayo. Hii husaidia kuhakikisha kwamba **application itafikia resources zinazotarajiwa pekee**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** ni security framework. Imeundwa **kusimamia permissions** za applications, hasa kwa kudhibiti access yao kwa features nyeti. Hii inajumuisha vitu kama **location services, contacts, photos, microphone, camera, accessibility, na full disk access**. TCC huhakikisha kwamba apps zinaweza kufikia features hizi baada tu ya kupata idhini ya wazi ya mtumiaji, hivyo kuimarisha privacy na udhibiti wa data binafsi.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch constraints katika macOS ni security feature ya **kudhibiti kuanzishwa kwa processes** kwa kufafanua **nani anaweza kuanzisha** process, **kwa njia gani**, na **kutoka wapi**. Zilizoanzishwa katika macOS Ventura, huainisha system binaries katika constraint categories ndani ya **trust cache**. Kila executable binary ina **rules** zilizowekwa kwa ajili ya **launch** yake, zikijumuisha constraints za **self**, **parent**, na **responsible**. Zikiwa zimepanuliwa kwa third-party apps kama **Environment** Constraints katika macOS Sonoma, features hizi husaidia kupunguza uwezekano wa system exploitations kwa kudhibiti masharti ya kuanzisha processes.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) ni sehemu nyingine ya macOS's security infrastructure. Kama jina linavyopendekeza, kazi kuu ya MRT ni **kuondoa malware inayojulikana kutoka kwenye systems zilizoambukizwa**.

Mara malware inapogunduliwa kwenye Mac (iwe na XProtect au kwa njia nyingine), MRT inaweza kutumiwa **kuondoa malware** hiyo automatically. MRT hufanya kazi kimya kimya background na kwa kawaida huendeshwa kila system inapofanyiwa update au definition mpya ya malware inapopakuliwa (inaonekana rules ambazo MRT hutumia kugundua malware ziko ndani ya binary).

Ingawa XProtect na MRT zote ni sehemu ya security measures za macOS, zinafanya functions tofauti:

- **XProtect** ni preventative tool. **Hukagua files zinapopakuliwa** (kupitia applications fulani), na ikigundua aina yoyote inayojulikana ya malware, **huzuia file kufunguka**, hivyo kuzuia malware kuambukiza system yako tangu mwanzo.
- **MRT**, kwa upande mwingine, ni **reactive tool**. Hufanya kazi baada ya malware kugunduliwa kwenye system, ikiwa na lengo la kuondoa software inayosababisha tatizo ili kusafisha system.

Application ya MRT iko katika **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Background Tasks Management

**macOS** sasa **huonya** kila tool inapotumia **technique inayojulikana ya ku-persist code execution** (kama Login Items, Daemons...), ili mtumiaji ajue vizuri zaidi **ni software gani inayopersist**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Hii huendeshwa na **daemon** iliyoko katika `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` na **agent** iliyoko katika `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

Njia ambayo **`backgroundtaskmanagementd`** hutumia kujua kwamba kitu kimesakinishwa katika persistent folder ni kwa **kupata FSEvents** na kuunda **handlers** kwa ajili yake.<sup>[[1]](#references)</sup>

Zaidi ya hayo, kuna plist file yenye **applications zinazojulikana** ambazo mara kwa mara hu-persist, inayodumishwa na apple na iliyo katika: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
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
### Uorodheshaji

Inawezekana **kuorodhesha vitu vyote** vya usuli vilivyosanidiwa vinavyoendeshwa kwa kutumia zana ya Apple ya cli:<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Zaidi ya hayo, inawezekana pia kuorodhesha maelezo haya kwa kutumia [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Maelezo haya yanahifadhiwa katika **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** na Terminal inahitaji FDA.<sup>[[2]](#references)</sup>

### Kuchezea BTM

Persistence mpya inapopatikana, event ya aina **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** hutokea. Kwa hivyo, njia yoyote ya **kuzuia** hii **event** kutumwa au **agent kutotoa alert** kwa mtumiaji itamsaidia attacker _**kubypass**_ BTM.<sup>[[1]](#references)</sup>

- **Kureset database**: Kuendesha command ifuatayo kuta-reset database (inapaswa kuijenga upya kuanzia mwanzo), hata hivyo, kwa sababu fulani, baada ya kuendesha hii, **hakuna persistence mpya itakayotolewa alert hadi mfumo u-reboot**.<sup>[[1]](#references)</sup>
- **root** inahitajika.
```bash
# Reset the database
sfltool resettbtm
```
- **Simamisha Agent**: Inawezekana kutuma ishara ya kusimamisha kwa agent ili **asimjulisha mtumiaji** wakati ugunduzi mpya unapopatikana.<sup>[[1]](#references)</sup>
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
- **Hitilafu**: Ikiwa **process iliyounda persistence ita-exit haraka mara tu baada yake**, daemon itajaribu **kupata taarifa** kuihusu, **itashindwa**, na **haitaweza kutuma event** inayoonyesha kuwa kipengele kipya kinafanya persistence.<sup>[[1]](#references)</sup>

## Marejeo

- [1] [OBTS v6.0: "Kufichua (& Kupita) Usimamizi wa Background Task wa macOS" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Tool Mpya ya (Developer): "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Dhibiti login items na background tasks kwenye Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
