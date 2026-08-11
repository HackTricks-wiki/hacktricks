# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper se obično koristi za označavanje kombinacije **Quarantine + Gatekeeper + XProtect**, 3 macOS security modula koji će pokušati da **spreče korisnike da izvrše potencijalno malicious software preuzet** sa interneta.

Više informacija na:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Ograničenja procesa

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox **ograničava aplikacije** koje se izvršavaju unutar sandbox-a na **dozvoljene radnje navedene u Sandbox profilu** sa kojim se aplikacija izvršava. Ovo pomaže da se osigura da će **aplikacija pristupati samo očekivanim resursima**.


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** je security framework. Dizajniran je da **upravlja dozvolama** aplikacija, konkretno regulišući njihov pristup osetljivim funkcijama. Ovo obuhvata elemente kao što su **usluge lokacije, kontakti, fotografije, mikrofon, kamera, accessibility i full disk access**. TCC osigurava da aplikacije mogu da pristupe ovim funkcijama tek nakon dobijanja izričite saglasnosti korisnika, čime se unapređuju privatnost i kontrola nad ličnim podacima.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch constraints u macOS-u predstavljaju security funkciju za **regulisanje pokretanja procesa** definisanjem **ko može da pokrene** proces, **kako** i **odakle**. Uvedene su u macOS Ventura i sistemske binarne fajlove kategorizuju u kategorije ograničenja unutar **trust cache-a**. Svaki izvršni binarni fajl ima definisana **pravila** za svoje **pokretanje**, uključujući **self**, **parent** i **responsible** constraints. Proširene na third-party aplikacije kao **Environment Constraints** u macOS Sonoma, ove funkcije pomažu u ublažavanju potencijalnih system exploitations tako što regulišu uslove pokretanja procesa.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) je još jedan deo macOS security infrastrukture. Kao što naziv sugeriše, glavna funkcija MRT-a je da **ukloni poznati malware sa zaraženih sistema**.

Kada se malware detektuje na Mac-u (bilo pomoću XProtect-a ili na neki drugi način), MRT može da se koristi za automatsko **uklanjanje malware-a**. MRT neprimetno radi u pozadini i obično se pokreće svaki put kada se sistem ažurira ili kada se preuzme nova malware definicija (izgleda da se pravila koja MRT koristi za detekciju malware-a nalaze unutar binarnog fajla).

Iako su i XProtect i MRT deo macOS security mera, oni obavljaju različite funkcije:

- **XProtect** je preventivni alat. On **proverava fajlove dok se preuzimaju** (putem određenih aplikacija), a ako detektuje bilo koji poznati tip malware-a, **sprečava otvaranje fajla**, čime sprečava da malware uopšte zarazi sistem.
- **MRT**, s druge strane, predstavlja **reaktivni alat**. Radi nakon što se malware detektuje na sistemu, sa ciljem da ukloni problematični software i očisti sistem.

MRT aplikacija se nalazi na lokaciji **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Background Tasks Management

**macOS** sada **upozorava** svaki put kada alat koristi dobro poznatu **tehniku za održavanje code execution-a** (kao što su Login Items, Daemons...), kako bi korisnik bolje znao **koji software održava persistence**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Ovo se izvršava pomoću **daemon-a** koji se nalazi na lokaciji `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` i **agent-a** na lokaciji `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

Način na koji **`backgroundtaskmanagementd`** saznaje da je nešto instalirano u persistent folder-u jeste **preuzimanjem FSEvents-a** i kreiranjem određenih **handler-a** za njih.<sup>[[1]](#references)</sup>

Pored toga, postoji plist fajl koji sadrži **dobro poznate aplikacije** koje često održavaju persistence, a koji Apple održava i koji se nalazi na lokaciji: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
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
### Enumeracija

Moguće je **enumerirati sve** konfigurisane pozadinske stavke pomoću Apple cli alata:<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Štaviše, ove informacije je moguće izlistati i pomoću alata [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Ove informacije se čuvaju u **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**, a Terminalu je potreban FDA.<sup>[[2]](#references)</sup>

### Manipulisanje BTM-om

Kada se pronađe nova persistence stavka, generiše se event tipa **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Stoga će svaki način da se **spreči** slanje ovog **eventa** ili da se **agentu onemogući upozoravanje** korisnika pomoći napadaču da _**zaobiđe**_ BTM.<sup>[[1]](#references)</sup>

- **Resetovanje baze podataka**: Pokretanje sledeće komande resetuje bazu podataka (koja bi trebalo da bude ponovo izgrađena od nule). Međutim, nakon toga se **ne pojavljuju nova upozorenja o persistence stavkama dok se sistem ponovo ne pokrene**.<sup>[[1]](#references)</sup>
- Potreban je **root**.
```bash
# Reset the database
sfltool resettbtm
```
- **Zaustavite agenta**: Moguće je poslati signal za zaustavljanje agentu, tako da **neće obaveštavati korisnika** kada se pronađu nove detekcije.<sup>[[1]](#references)</sup>
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
- **Greška**: Ako **proces koji je kreirao persistence odmah nakon toga izađe**, daemon pokušava da **dobije informacije** o njemu, **ne uspeva** i **ne može da pošalje događaj** koji ukazuje da novi item persistira.<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: „Razjašnjavanje (i zaobilaženje) upravljanja macOS pozadinskim zadacima“ - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Novi (Developer) alat: „DumpBTM“ - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Upravljanje login item-ima i pozadinskim zadacima na Mac-u - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)
{{#include ../../../banners/hacktricks-training.md}}
