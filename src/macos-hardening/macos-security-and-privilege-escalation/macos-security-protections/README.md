# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper se obično koristi za označavanje kombinacije **Quarantine + Gatekeeper + XProtect**, 3 macOS security modula koji će pokušati da **spreče korisnike da izvrše potencijalno zlonamerni softver preuzet** sa Interneta.

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

**TCC (Transparency, Consent, and Control)** je security framework. Namenjen je **upravljanju dozvolama** aplikacija, konkretno regulisanjem njihovog pristupa osetljivim funkcijama. To uključuje elemente kao što su **usluge lokacije, kontakti, fotografije, mikrofon, kamera, accessibility i full disk access**. TCC osigurava da aplikacije mogu da pristupe ovim funkcijama tek nakon dobijanja izričite saglasnosti korisnika, čime se dodatno unapređuju privatnost i kontrola nad ličnim podacima.


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

Launch constraints u macOS-u predstavljaju security funkciju za **regulisanje pokretanja procesa**, definisanjem **ko može da pokrene** proces, **na koji način** i **odakle**. Uvedene su u macOS Ventura i kategorizuju sistemske binarne fajlove u kategorije ograničenja unutar **trust cache-a**. Svaki izvršni binarni fajl ima skup **pravila** za svoje **pokretanje**, uključujući ograničenja **self**, **parent** i **responsible**. Ove funkcije su proširene na third-party aplikacije kao **Environment Constraints** u macOS Sonoma i pomažu u ublažavanju potencijalnih system exploitations tako što kontrolišu uslove pod kojima se procesi pokreću.


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT) je još jedan deo macOS security infrastrukture. Kao što ime sugeriše, glavna funkcija MRT-a je da **ukloni poznati malware sa zaraženih sistema**.

Kada se malware detektuje na Mac-u (bilo pomoću XProtect-a ili na neki drugi način), MRT se može koristiti za automatsko **uklanjanje malware-a**. MRT neprimetno radi u pozadini i obično se pokreće svaki put kada se sistem ažurira ili kada se preuzme nova definicija malware-a (izgleda da se pravila koja MRT koristi za detekciju malware-a nalaze unutar binarnog fajla).

Iako su i XProtect i MRT deo macOS security mera, oni obavljaju različite funkcije:

- **XProtect** je preventivni alat. On **proverava fajlove dok se preuzimaju** (putem određenih aplikacija) i, ako detektuje bilo koju poznatu vrstu malware-a, **sprečava otvaranje fajla**, čime sprečava malware da zarazi sistem.
- **MRT**, sa druge strane, predstavlja **reaktivni alat**. On deluje nakon što je malware detektovan na sistemu, sa ciljem da ukloni problematični softver i očisti sistem.

MRT aplikacija se nalazi na lokaciji **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Upravljanje Background Tasks

**macOS** sada **upozorava** svaki put kada alat koristi dobro poznatu **tehniku za održavanje code execution-a** (kao što su Login Items, Daemons...), kako bi korisnik bolje znao **koji softver održava persistence**.<sup>[3]</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

Ovo se izvršava pomoću **daemon-a** koji se nalazi na lokaciji `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` i **agent-a** na lokaciji `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`<sup>[1]</sup>

Način na koji **`backgroundtaskmanagementd`** zna da je nešto instalirano u persistent folder-u jeste tako što **preuzima FSEvents** i za njih kreira određene **handlers**.<sup>[1]</sup>

Pored toga, postoji plist fajl koji sadrži **dobro poznate aplikacije** koje često održavaju persistence, a koji Apple održava na lokaciji: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[3]</sup>
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

Moguće je **enumerisati sve** konfigurisane stavke u pozadini pomoću Apple CLI alata:<sup>[3]</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Štaviše, ove informacije je takođe moguće izlistati pomoću [**DumpBTM**](https://github.com/objective-see/DumpBTM).<sup>[2]</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Ove informacije se čuvaju u **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`**, a Terminalu je potreban FDA.<sup>[2]</sup>

### Manipulisanje BTM-om

Kada se pronađe nova persistence, generiše se događaj tipa **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Zato će svaki način da se **spreči** slanje ovog **događaja** ili da se **agentu onemogući upozoravanje** korisnika pomoći napadaču da _**zaobiđe**_ BTM.<sup>[1]</sup>

- **Resetovanje baze podataka**: Pokretanje sledeće komande resetovaće bazu podataka (trebalo bi da je ponovo izgradi od nule); međutim, iz nekog razloga, nakon njenog pokretanja **nijedna nova persistence neće biti prijavljena sve dok se sistem ponovo ne pokrene**.<sup>[1]</sup>
- Potreban je **root**.
```bash
# Reset the database
sfltool resettbtm
```
- **Zaustavljanje Agent-a**: Moguće je poslati signal za zaustavljanje Agent-u, tako da **neće obaveštavati korisnika** kada se pronađu nove detekcije.<sup>[1]</sup>
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
- **Bug**: Ako **proces koji je kreirao persistence izađe odmah nakon toga**, daemon će pokušati da **dobije informacije** o njemu, **neće uspeti** i **neće moći da pošalje događaj** koji ukazuje na to da se nova stvar održava persistentnom.<sup>[1]</sup>

## Reference

- [1] [OBTS v6.0: „Razjašnjavanje (i zaobilaženje) upravljanja macOS Background Task-ovima“ - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [Novi (Developer) alat: „DumpBTM“ - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Upravljanje login item-ima i Background Task-ovima na Mac-u - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
