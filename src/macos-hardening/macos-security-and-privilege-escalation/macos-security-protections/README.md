# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper se obično koristi za označavanje kombinacije **Quarantine + Gatekeeper + XProtect**, 3 macOS bezbednosna modula koja će pokušati da **spreče korisnike da izvrše potencijalno maliciozan softver preuzet sa interneta**.

Više informacija:


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

**TCC (Transparency, Consent, and Control)** je bezbednosni framework. Namenjen je **upravljanju dozvolama** aplikacija, konkretno regulisanjem njihovog pristupa osetljivim funkcijama. Ovo obuhvata elemente kao što su **usluge lokacije, kontakti, fotografije, mikrofon, kamera, accessibility i full disk access**. TCC osigurava da aplikacije mogu da pristupe ovim funkcijama tek nakon dobijanja izričite saglasnosti korisnika, čime se poboljšavaju privatnost i kontrola nad ličnim podacima.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch constraints u macOS-u su bezbednosna funkcija za **regulisanje pokretanja procesa**, definisanjem **ko može da pokrene** proces, **kako** i **odakle**. Uvedene u macOS Ventura, one kategorizuju sistemske binarne datoteke u kategorije ograničenja unutar **trust cache-a**. Svaka izvršna binarna datoteka ima skup **pravila** za svoje **pokretanje**, uključujući **self**, **parent** i **responsible** constraints. Proširene na aplikacije trećih strana kao **Environment Constraints** u macOS Sonoma, ove funkcije pomažu u ublažavanju potencijalnih eksploatacija sistema kontrolisanjem uslova pod kojima se procesi pokreću.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) je još jedan deo macOS bezbednosne infrastrukture. Kao što naziv sugeriše, glavna funkcija MRT-a je da **ukloni poznati malware sa zaraženih sistema**.

Kada se malware otkrije na Mac-u (bilo pomoću XProtect-a ili na neki drugi način), MRT se može koristiti za automatsko **uklanjanje malware-a**. MRT nečujno radi u pozadini i obično se pokreće svaki put kada se sistem ažurira ili kada se preuzme nova definicija malware-a (izgleda da se pravila koja MRT koristi za otkrivanje malware-a nalaze unutar binarne datoteke).

Iako su i XProtect i MRT deo macOS bezbednosnih mera, oni obavljaju različite funkcije:

- **XProtect** je preventivni alat. On **proverava datoteke prilikom njihovog preuzimanja** (putem određenih aplikacija) i, ako otkrije neki poznati tip malware-a, **sprečava otvaranje datoteke**, čime sprečava da malware uopšte zarazi sistem.
- **MRT** je, sa druge strane, **reaktivni alat**. On deluje nakon što je malware otkriven na sistemu, sa ciljem uklanjanja problematičnog softvera kako bi se sistem očistio.

MRT aplikacija se nalazi na lokaciji **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Upravljanje zadacima u pozadini

**macOS** sada **upozorava** svaki put kada alat koristi dobro poznatu **tehniku za održavanje izvršavanja koda** (kao što su Login Items, Daemons...), kako bi korisnik bolje znao **koji softver održava persistence**.<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Ovo funkcioniše pomoću **daemon-a** koji se nalazi na lokaciji `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` i **agent-a** na lokaciji `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[[1]](#references)</sup>

Način na koji **`backgroundtaskmanagementd`** zna da je nešto instalirano u persistence folderu jeste **preuzimanjem FSEvents-a** i kreiranjem određenih **handler-a** za njih.<sup>[[1]](#references)</sup>

Pored toga, postoji plist datoteka koja sadrži **dobro poznate aplikacije** koje se često koriste za persistence, a koju Apple održava na lokaciji: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
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

Moguće je **enumerisati sve** konfigurisane pozadinske stavke pokretanjem Apple CLI alata:<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Štaviše, ove informacije je moguće izlistati i pomoću [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Ove informacije se čuvaju u **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**, a Terminalu je potreban FDA.<sup>[[2]](#references)</sup>

### Manipulisanje BTM-om

Kada se pronađe nova persistence stavka, generiše se događaj tipa **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Dakle, svaki način da se **spreči** slanje ovog **događaja** ili da se **agentu onemogući upozoravanje** korisnika pomoći će napadaču da _**zaobiđe**_ BTM.<sup>[[1]](#references)</sup>

- **Resetovanje baze podataka**: Pokretanje sledeće komande resetovaće bazu podataka (trebalo bi da je ponovo izgradi od početka); međutim, iz nekog razloga, nakon ovog postupka, nijedna nova persistence stavka neće biti prijavljena sve dok se sistem ponovo ne pokrene.<sup>[[1]](#references)</sup>
- Potreban je **root**.
```bash
# Reset the database
sfltool resettbtm
```
- **Zaustavite Agent**: Moguće je poslati Agent-u signal za zaustavljanje kako **ne bi obaveštavao korisnika** kada se pronađu nove detekcije.<sup>[[1]](#references)</sup>
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
- **Greška**: Ako **process koji je kreirao persistence izađe odmah nakon toga**, daemon će pokušati da **dobije informacije** o njemu, **neće uspeti** i **neće moći da pošalje event** koji ukazuje da novi element ima persistence.<sup>[[1]](#references)</sup>

## Reference

- [1] [OBTS v6.0: "Demystifying (& Bypassing) macOS's Background Task Management" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [New (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Manage login items and background tasks on Mac - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
