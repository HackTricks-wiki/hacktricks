# macOS bezbednosne zaštite

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper se obično koristi za označavanje kombinacije **Quarantine + Gatekeeper + XProtect**, 3 macOS bezbednosna modula koji će pokušati da **spreče korisnike da izvrše potencijalno maliciozni softver preuzet sa Interneta**.

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

**TCC (Transparency, Consent, and Control)** je bezbednosni framework. Dizajniran je da **upravlja dozvolama** aplikacija, konkretno regulisanjem njihovog pristupa osetljivim funkcijama. To obuhvata elemente kao što su **usluge lokacije, kontakti, fotografije, mikrofon, kamera, accessibility i full disk access**. TCC osigurava da aplikacije mogu da pristupe ovim funkcijama tek nakon dobijanja izričite saglasnosti korisnika, čime se unapređuju privatnost i kontrola nad ličnim podacima.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch constraints u macOS-u predstavljaju bezbednosnu funkciju za **regulisanje pokretanja procesa**, definisanjem **ko može da pokrene** proces, **kako** i **odakle**. Uvedene u macOS Ventura, one sistemske binarne datoteke razvrstavaju u kategorije ograničenja unutar **trust cache-a**. Svaka izvršna binarna datoteka ima definisana **pravila** za svoje **pokretanje**, uključujući **self**, **parent** i **responsible** ograničenja. Ove funkcije, proširene na aplikacije trećih strana kao **Environment** Constraints u macOS Sonoma, pomažu u ublažavanju potencijalnih iskorišćavanja sistema upravljanjem uslovima pokretanja procesa.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) je još jedan deo macOS bezbednosne infrastrukture. Kao što ime sugeriše, glavna funkcija MRT-a je da **ukloni poznati malware sa zaraženih sistema**.

Kada se malware detektuje na Mac-u (bilo pomoću XProtect-a ili na neki drugi način), MRT se može koristiti za automatsko **uklanjanje malware-a**. MRT neprimetno radi u pozadini i obično se pokreće svaki put kada se sistem ažurira ili kada se preuzme nova definicija malware-a (izgleda da se pravila koja MRT koristi za detekciju malware-a nalaze unutar binarne datoteke).

Iako su XProtect i MRT deo macOS bezbednosnih mera, oni obavljaju različite funkcije:

- **XProtect** je preventivni alat. On **proverava datoteke prilikom njihovog preuzimanja** (putem određenih aplikacija) i, ako detektuje bilo koji poznati tip malware-a, **sprečava otvaranje datoteke**, čime sprečava da malware uopšte zarazi sistem.
- **MRT**, sa druge strane, predstavlja **reaktivni alat**. On radi nakon što je malware detektovan na sistemu, sa ciljem da ukloni problematični softver i očisti sistem.

MRT aplikacija se nalazi na lokaciji **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Upravljanje zadacima u pozadini

**macOS** sada **upozorava** svaki put kada alat koristi dobro poznatu **tehniku za održavanje perzistentnog izvršavanja koda** (kao što su Login Items, Daemons...), kako bi korisnik bolje znao **koji softver održava perzistenciju**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Ovo se izvršava pomoću **daemon-a** koji se nalazi na lokaciji `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` i **agent-a** na lokaciji `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

Način na koji **`backgroundtaskmanagementd`** zna da je nešto instalirano u folderu za perzistenciju jeste **dobijanje FSEvents-a** i kreiranje određenih **handler-a** za njih.<sup>[[1]](#references)</sup>

Pored toga, postoji plist datoteka koja sadrži **dobro poznate aplikacije** koje često održavaju perzistenciju, a koju Apple održava na lokaciji: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
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

Moguće je **enumerirati sve** konfigurisane pozadinske stavke pokretanjem Apple CLI alata:<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Štaviše, moguće je izlistati ove informacije pomoću alata [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Ove informacije se čuvaju u **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**, a Terminal zahteva FDA.<sup>[[2]](#references)</sup>

### Manipulisanje BTM-om

Kada se pronađe nova persistence, generiše se event tipa **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Dakle, svaki način da se **spreči** slanje ovog **eventa** ili da se **agentu onemogući upozoravanje** korisnika pomoći će napadaču da _**zaobiđe**_ BTM.<sup>[[1]](#references)</sup>

- **Resetovanje baze podataka**: Pokretanje sledeće komande resetovaće bazu podataka (trebalo bi da je ponovo izgradi od početka); međutim, iz nekog razloga, nakon njenog pokretanja, nijedna nova persistence neće biti prijavljena dok se sistem ponovo ne pokrene.<sup>[[1]](#references)</sup>
- Potreban je **root**.
```bash
# Reset the database
sfltool resettbtm
```
- **Zaustavljanje Agent-a**: Moguće je poslati signal za zaustavljanje agentu, tako da **neće obavestiti korisnika** kada se pronađu nove detekcije.<sup>[[1]](#references)</sup>
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
- **Greška**: Ako **proces koji je kreirao persistence brzo završi odmah nakon toga**, daemon će pokušati da **dobavi informacije** o njemu, **neće uspeti** i **neće moći da pošalje događaj** koji ukazuje da novi element ostaje aktivan.<sup>[[1]](#references)</sup>

## Reference

- [1] [OBTS v6.0: „Demistifikacija (i zaobilaženje) macOS-ovog upravljanja pozadinskim zadacima“ - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Novi (Developer) alat: „DumpBTM“ - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Upravljanje login item-ima i pozadinskim zadacima na Mac-u - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
