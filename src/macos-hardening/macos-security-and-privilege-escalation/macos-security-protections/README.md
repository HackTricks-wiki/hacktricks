# macOS-sekuriteitsbeskermings

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper word gewoonlik gebruik om te verwys na die kombinasie van **Quarantine + Gatekeeper + XProtect**, 3 macOS-sekuriteitsmodules wat sal probeer om te **verhoed dat gebruikers potensieel kwaadwillige sagteware wat afgelaai is, uitvoer**.

Meer inligting in:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Prosesbeperkings

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox **beperk toepassings** wat binne die sandbox loop tot die **toegelate aksies wat in die Sandbox-profiel gespesifiseer word** waarmee die toepassing loop. Dit help verseker dat **die toepassing slegs toegang tot verwagte hulpbronne verkry**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** is 'n sekuriteitsraamwerk. Dit is ontwerp om **die toestemmings van toepassings te bestuur**, spesifiek deur hul toegang tot sensitiewe funksies te reguleer. Dit sluit elemente soos **liggingdienste, kontakte, foto's, mikrofoon, kamera, toeganklikheid en volledige skyftoegang** in. TCC verseker dat toepassings slegs toegang tot hierdie funksies kan verkry nadat uitdruklike gebruikerstoestemming verkry is, en versterk sodoende privaatheid en beheer oor persoonlike data.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch constraints in macOS is 'n sekuriteitsfunksie om **prosesinisiasie te reguleer** deur te definieer **wie** 'n proses kan launch, **hoe**, en **van waar af**. Dit is in macOS Ventura bekendgestel en kategoriseer stelselbinaries in constraint-kategorieë binne 'n **trust cache**. Elke uitvoerbare binary het vasgestelde **reëls** vir sy **launch**, insluitend **self-, parent- en responsible-constraints**. Hierdie funksies, wat na derdeparty-toepassings uitgebrei is as **Environment Constraints** in macOS Sonoma, help om potensiële stelseluitbuitings te versag deur die voorwaardes vir die launching van prosesse te beheer.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Die Malware Removal Tool (MRT) is nog 'n deel van macOS se sekuriteitsinfrastruktuur. Soos die naam aandui, is MRT se hooffunksie om **bekende malware van besmette stelsels te verwyder**.

Sodra malware op 'n Mac opgespoor word (hetsy deur XProtect of op enige ander manier), kan MRT gebruik word om die **malware outomaties te verwyder**. MRT werk stilweg in die agtergrond en loop gewoonlik wanneer die stelsel opgedateer word of wanneer 'n nuwe malware-definisie afgelaai word (dit lyk asof die reëls wat MRT gebruik om malware op te spoor, binne die binary is).

Hoewel XProtect en MRT albei deel is van macOS se sekuriteitsmaatreëls, verrig hulle verskillende funksies:

- **XProtect** is 'n voorkomende hulpmiddel. Dit **kontroleer lêers terwyl hulle afgelaai word** (via sekere toepassings), en indien dit enige bekende tipes malware opspoor, **verhoed dit dat die lêer oopgemaak word**, en voorkom dit sodoende dat die malware jou stelsel in die eerste plek besmet.
- **MRT**, daarenteen, is 'n **reaktiewe hulpmiddel**. Dit werk nadat malware op 'n stelsel opgespoor is, met die doel om die aanstootlike sagteware te verwyder en die stelsel skoon te maak.

Die MRT-toepassing is geleë in **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Agtergrondtakebestuur

**macOS** **waarsku** nou elke keer wanneer 'n hulpmiddel 'n bekende **tegniek gebruik om kode-uitvoering volhoubaar te maak** (soos Login Items, Daemons...), sodat die gebruiker beter weet **watter sagteware volhoubaar gemaak word**.<sup>[3]</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Dit loop met 'n **daemon** wat geleë is in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` en die **agent** in `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[1]</sup>

Die manier waarop **`backgroundtaskmanagementd`** weet dat iets in 'n persistente vouer geïnstalleer is, is deur die **FSEvents te verkry** en sekere **handlers** daarvoor te skep.<sup>[1]</sup>

Daarbenewens is daar 'n plist-lêer wat **bekende toepassings** bevat wat gereeld volhoubaar gemaak word, deur Apple onderhou word, en geleë is in: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[3]</sup>
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
### Enumerasie

Dit is moontlik om **alle** gekonfigureerde agtergronditems te enumereer deur die Apple CLI-tool uit te voer:<sup>[3]</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Boonop is dit ook moontlik om hierdie inligting met [**DumpBTM**](https://github.com/objective-see/DumpBTM) te lys.<sup>[2]</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Hierdie inligting word in **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** gestoor en die Terminal benodig FDA.<sup>[2]</sup>

### Inmenging met BTM

Wanneer ’n nuwe persistence gevind word, word ’n gebeurtenis van die tipe **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** gegenereer. Enige manier om te **verhoed** dat hierdie **gebeurtenis** gestuur word, of om te verhoed dat die **agent die gebruiker waarsku**, sal ’n aanvaller help om BTM te _**bypass**_.<sup>[1]</sup>

- **Herstel van die databasis**: Deur die volgende command uit te voer, sal die databasis herstel word (dit behoort dit van nuuts af te herbou); om een of ander rede sal geen nuwe persistence egter **geflag** word totdat die stelsel herbegin word nie.<sup>[1]</sup>
- **root** word vereis.
```bash
# Reset the database
sfltool resettbtm
```
- **Stop the Agent**: Dit is moontlik om ’n stopsein na die agent te stuur sodat dit **nie die gebruiker sal waarsku** wanneer nuwe bespeurings gevind word nie.<sup>[1]</sup>
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
- **Fout**: As die **proses wat die persistence geskep het kort daarna vinnig afsluit**, sal die daemon probeer om **inligting** daaroor te **bekom**, **misluk**, en **nie die gebeurtenis kan stuur** wat aandui dat iets nuuts persistence gebruik nie.<sup>[1]</sup>

## Verwysings

- [1] [OBTS v6.0: "Demystifying (& Bypassing) macOS's Background Task Management" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [New (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Manage login items and background tasks on Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
