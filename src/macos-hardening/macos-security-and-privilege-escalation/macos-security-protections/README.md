# Ulinzi wa Usalama wa macOS

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper kwa kawaida hutumiwa kurejelea mchanganyiko wa **Quarantine + Gatekeeper + XProtect**, moduli 3 za usalama za macOS ambazo zitajaribu **kuwazuia watumiaji kutekeleza software inayoweza kuwa hatari iliyopakuliwa**.

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

Sandbox ya MacOS **hupunguza vitendo vya applications** zinazoendesha ndani ya sandbox hadi kwenye **vitendo vinavyoruhusiwa vilivyoainishwa katika Sandbox profile** ambayo app inaendesha nayo. Hii husaidia kuhakikisha kwamba **application itafikia rasilimali zilizotarajiwa pekee**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** ni security framework. Imeundwa **kusimamia permissions** za applications, hasa kwa kudhibiti ufikiaji wao wa features nyeti. Hii inajumuisha vitu kama **location services, contacts, photos, microphone, camera, accessibility, na full disk access**. TCC huhakikisha kwamba apps zinaweza kufikia features hizi baada tu ya kupata idhini ya wazi ya mtumiaji, hivyo kuimarisha privacy na udhibiti wa data binafsi.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch constraints katika macOS ni feature ya usalama ya **kudhibiti uanzishaji wa process** kwa kufafanua **nani anaweza ku-launch** process, **kwa njia gani**, na **kutoka wapi**. Zilianzishwa katika macOS Ventura, na huweka system binaries katika categories za constraints ndani ya **trust cache**. Kila executable binary ina **rules** zilizowekwa kwa ajili ya **launch** yake, zikiwemo constraints za **self**, **parent**, na **responsible**. Zilipozidishwa hadi kwenye third-party apps kama **Environment** Constraints katika macOS Sonoma, features hizi husaidia kupunguza uwezekano wa system exploitation kwa kudhibiti masharti ya ku-launch process.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) ni sehemu nyingine ya miundombinu ya usalama ya macOS. Kama jina linavyopendekeza, kazi kuu ya MRT ni **kuondoa malware inayojulikana kutoka kwenye systems zilizoambukizwa**.

Mara malware inapogunduliwa kwenye Mac (iwe ni kupitia XProtect au kwa njia nyingine), MRT inaweza kutumika **kuondoa malware** hiyo automatically. MRT hufanya kazi kimya kimya background na kwa kawaida huendesha kila mara system inaposasishwa au malware definition mpya inapopakuliwa (inaonekana rules ambazo MRT hutumia kugundua malware zimo ndani ya binary).

Ingawa XProtect na MRT zote ni sehemu ya hatua za usalama za macOS, zinafanya functions tofauti:

- **XProtect** ni tool ya kuzuia. **Hukagua files zinapopakuliwa** (kupitia applications fulani), na ikigundua aina yoyote inayojulikana ya malware, **huzuia file kufunguka**, hivyo kuzuia malware isiambukize system yako tangu mwanzo.
- **MRT**, kwa upande mwingine, ni **tool ya kukabiliana**. Hufanya kazi baada ya malware kugunduliwa kwenye system, ikiwa na lengo la kuondoa software inayosababisha tatizo ili kusafisha system.

MRT application iko katika **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Usimamizi wa Background Tasks

**macOS** sasa **huonya** kila mara tool inapotumia **technique inayojulikana ya kudumisha code execution** (kama vile Login Items, Daemons...), ili mtumiaji ajue vizuri **ni software gani inayodumisha persistence**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Hii huendeshwa na **daemon** iliyo katika `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` na **agent** iliyo katika `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

Jinsi **`backgroundtaskmanagementd`** inavyojua kuwa kitu kimewekwa katika folder ya persistence ni kwa **kupata FSEvents** na kuunda **handlers** kwa ajili yake.<sup>[[1]](#references)</sup>

Zaidi ya hayo, kuna plist file iliyo na **applications zinazojulikana** ambazo mara nyingi hudumisha persistence, inayotunzwa na Apple na iko katika: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
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
### Uhesabuji

Inawezekana **kuorodhesha vitu vyote** vya usuli vilivyosanidiwa kwa kutumia Apple cli tool:<sup>[[3]](#references)</sup>
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
Taarifa hii inahifadhiwa katika **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** na Terminal inahitaji FDA.<sup>[[2]](#references)</sup>

### Kuchezea BTM

Persistence mpya inapopatikana, tukio la aina **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** hutokea. Kwa hivyo, njia yoyote ya **kuzuia** **tukio** hili lisitumwe au **agent isimtahadharishe** mtumiaji itamsaidia mshambulizi _**bypass**_ BTM.<sup>[[1]](#references)</sup>

- **Kuweka upya database**: Kuendesha command ifuatayo huweka upya database (ambayo inapaswa kujengwa upya kutoka mwanzo). Hata hivyo, baada ya kufanya hivi, hakuna alerts mpya za persistence zitakazoonekana hadi mfumo uanzishwe upya.<sup>[[1]](#references)</sup>
- **root** inahitajika.
```bash
# Reset the database
sfltool resettbtm
```
- **Simamisha Agent**: Inawezekana kutuma signal ya kusimamisha kwa Agent ili **asimuonye mtumiaji** wakati ugunduzi mpya unapatikana.<sup>[[1]](#references)</sup>
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
- **Bug**: Ikiwa **process iliyounda persistence itatoka mara moja baadaye**, daemon hujaribu **kupata taarifa** kuihusu, **hushindwa**, na **haiwezi kutuma event** inayoonyesha kuwa kipengee kipya kinaendelea kufanya persistence.<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: "Kufafanua (& Kupita) Usimamizi wa Background Tasks wa macOS" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Tool Mpya ya (Developer): "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Dhibiti login items na background tasks kwenye Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)
{{#include ../../../banners/hacktricks-training.md}}
