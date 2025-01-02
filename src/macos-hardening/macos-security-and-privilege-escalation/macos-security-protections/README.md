# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper se obično koristi da se odnosi na kombinaciju **Quarantine + Gatekeeper + XProtect**, 3 macOS sigurnosna modula koja će pokušati da **spreče korisnike da izvršavaju potencijalno zlonamerni softver preuzet**.

Više informacija u:

{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Processes Limitants

### MACF

### SIP - System Integrity Protection

{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox **ograničava aplikacije** koje se izvršavaju unutar sandbox-a na **dozvoljene radnje specificirane u Sandbox profilu** sa kojim aplikacija radi. Ovo pomaže da se osigura da **aplikacija pristupa samo očekivanim resursima**.

{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** je sigurnosni okvir. Dizajniran je da **upravlja dozvolama** aplikacija, posebno regulisanjem njihovog pristupa osetljivim funkcijama. Ovo uključuje elemente kao što su **usluge lokacije, kontakti, fotografije, mikrofon, kamera, pristupačnost i pristup celom disku**. TCC osigurava da aplikacije mogu pristupiti ovim funkcijama samo nakon dobijanja eksplicitne saglasnosti korisnika, čime se jača privatnost i kontrola nad ličnim podacima.

{{#ref}}
macos
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

Moguće je **enumerisati sve** konfigurisane pozadinske stavke koristeći Apple cli alat:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Pored toga, moguće je i da se ova informacija prikaže pomoću [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Ove informacije se čuvaju u **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** i Terminalu je potrebna FDA.

### Manipulacija sa BTM

Kada se pronađe nova perzistencija, događa se događaj tipa **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Dakle, bilo koji način da se **spreči** slanje ovog **događaja** ili da **agent ne obavesti** korisnika će pomoći napadaču da _**zaobiđe**_ BTM.

- **Resetovanje baze podataka**: Pokretanje sledeće komande će resetovati bazu podataka (trebalo bi da je ponovo izgradi od nule), međutim, iz nekog razloga, nakon pokretanja ovoga, **nema novih obaveštenja o perzistenciji dok se sistem ne restartuje**.
- **root** je potreban.
```bash
# Reset the database
sfltool resettbtm
```
- **Zaustavite Agenta**: Moguće je poslati signal za zaustavljanje agentu tako da **neće obaveštavati korisnika** kada se pronađu nova otkrića.
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
- **Greška**: Ako **proces koji je stvorio postojanost postoji brzo nakon njega**, demon će pokušati da **dobije informacije** o njemu, **neće uspeti** i **neće moći da pošalje događaj** koji ukazuje na to da nova stvar postojano postoji.

Reference i **više informacija o BTM**:

- [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
- [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

{{#include ../../../banners/hacktricks-training.md}}
