# Dumping memorije na macOS-u

{{#include ../../../banners/hacktricks-training.md}}

## Artefakti memorije

### Swap datoteke

Swap datoteke, kao što je `/private/var/vm/swapfile0`, služe kao **keš kada je fizička memorija puna**. Kada više nema prostora u fizičkoj memoriji, njeni podaci se prebacuju u swap datoteku, a zatim se po potrebi vraćaju u fizičku memoriju. Može biti prisutno više swap datoteka, sa nazivima kao što su swapfile0, swapfile1 i tako dalje.

### Hibernate image

Datoteka koja se nalazi na `/private/var/vm/sleepimage` ključna je tokom **režima hibernacije**. **Podaci iz memorije se čuvaju u ovoj datoteci kada OS X pređe u hibernaciju**. Prilikom buđenja računara, sistem preuzima podatke o memoriji iz ove datoteke, omogućavajući korisniku da nastavi tamo gde je stao.

Vredi napomenuti da je na modernim MacOS sistemima ova datoteka obično šifrovana iz bezbednosnih razloga, što otežava oporavak podataka.

- Da biste proverili da li je šifrovanje omogućeno za sleepimage, možete pokrenuti komandu `sysctl vm.swapusage`. Ona će prikazati da li je datoteka šifrovana.

### Dnevnici pritiska memorije

Još jedna važna datoteka povezana sa memorijom na MacOS sistemima jeste **dnevnik pritiska memorije**. Ovi dnevnici se nalaze u `/var/log` i sadrže detaljne informacije o korišćenju memorije sistema i događajima povezanima sa pritiskom memorije. Mogu biti naročito korisni za dijagnostikovanje problema povezanih sa memorijom ili za razumevanje načina na koji sistem upravlja memorijom tokom vremena.

## Dumping memorije pomoću osxpmem

Da biste izvršili dump memorije na MacOS računaru, možete koristiti [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Napomena**: Ovo je sada uglavnom **legacy workflow**. `osxpmem` zavisi od učitavanja kernel ekstenzije, projekat [Rekall](https://github.com/google/rekall) je arhiviran, najnovije izdanje potiče iz **2017. godine**, a objavljena binarna datoteka namenjena je **Intel Mac računarima**. Na aktuelnim macOS izdanjima, naročito na **Apple Silicon** uređajima, akviziciju cele RAM memorije zasnovanu na kext-u obično blokiraju moderna ograničenja kernel ekstenzija, SIP i zahtevi za potpisivanje platforme. U praksi ćete na modernim sistemima češće završiti sa **dumpom ograničenim na proces**, umesto sa slikom cele RAM memorije.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Ako naiđete na ovu grešku: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Možete je otkloniti na sledeći način:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Druge greške** mogu biti otklonjene tako što ćete **dozvoliti učitavanje kext-a** u odeljku „Security & Privacy --> General“ — jednostavno kliknite na **Allow**.

Takođe možete koristiti ovaj **oneliner** za preuzimanje aplikacije, učitavanje kext-a i izvršavanje dump-a memorije:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Dumping živog procesa pomoću LLDB-a

Za **novije verzije macOS-a**, najpraktičniji pristup je obično dump memorije **određenog procesa**, umesto pokušaja da se napravi image celokupne fizičke memorije.

LLDB može da sačuva Mach-O core file iz živog targeta:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target.core
```
Podrazumevano, ovo obično kreira **skinny core**. Da biste primorali LLDB da uključi svu mapiranu memoriju procesa:
```bash
sudo lldb --attach-pid <pid>
(lldb) process save-core /tmp/target-full.core --style full
```
Korisne naredbe za nastavak pre dumpovanja:
```bash
# Show loaded images and main binary
(lldb) image list

# Inspect mapped regions and permissions
(lldb) memory region --all

# Dump only one interesting range
(lldb) memory read --force --outfile /tmp/region.bin --binary <start> <end>
```
Ovo je obično dovoljno kada je cilj oporaviti:

- Dešifrovane konfiguracione blobove
- Tokene, kolačiće ili kredencijale u memoriji
- Tajne u otvorenom tekstu koje su zaštićene samo dok miruju
- Dešifrovane Mach-O stranice nakon raspakivanja / JIT-a / runtime patching-a

Ako je cilj zaštićen pomoću **hardened runtime-a** ili `taskgated` odbije attach, obično vam je potreban jedan od sledećih uslova:

- Cilj poseduje **`get-task-allow`**
- Vaš debugger je potpisan odgovarajućim **debugger entitlement-om**
- Vi ste **root**, a cilj je third-party proces bez hardened runtime-a

Za više informacija o pribavljanju task port-a i o tome šta se njime može uraditi:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Brze provere pre attach-a

Pre nego što utrošite vreme na LLDB/Frida, brzo proverite da li je cilj realno **dumpable**:
```bash
# Check entitlements that commonly decide whether an attach will work
codesign -d --entitlements - /Applications/Target.app 2>/dev/null | \
egrep -A1 'get-task-allow|com.apple.security.cs.debugger'

# Quick view of hardened runtime / code-signing flags
codesign -dvvv /Applications/Target.app 2>&1 | egrep 'Runtime Version|flags='

# Inspect memory layout before deciding between a full core and a selective dump
vmmap <pid>
```
U praksi, to obično znači:

- Aplikacija treće strane isporučena sa **`get-task-allow`** često se može direktno dumpovati pomoću LLDB-a, a dobijeni dump može otkriti podatke zaštićene TCC-om kojima je aplikacija već pristupila.<sup>[[1]](#references)</sup>
- **Hardened** target bez `get-task-allow` obično će odbiti attach, čak i kada ste `root`, osim ako kontrolišete relevantne debugger entitlements / policy path.
- Unhardened procesi trećih strana i dalje su najlakše mesto za korišćenje alata `lldb`, `vmmap`, Frida ili prilagođenih čitača zasnovanih na `task_for_pid`/`vm_read`.

### Potražite dumpable ugnježdene helpere

Nedavna istraživanja notarizovanih macOS aplikacija i dalje pronalaze **`get-task-allow`** u ugnježdenim helperima, umesto u glavnom GUI binary-ju. Kada aplikacija na najvišem nivou izgleda hardened, pre nego što odustanete, enumerišite njene **XPC services**, **login items**, **helper tools** i CLI-jeve uključene u paket:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Ugnježdeni executable sa `get-task-allow` često je najlakše mesto za povezivanje pomoću `lldb`, pravljenje core dump-a ili preuzimanje memorije pomoću prilagođenog `task_for_pid` klijenta, čak i kada je glavna aplikacija bolje zaštićena.

## Selektivni dump-ovi pomoću Frida-e ili userland čitača

Kada je kompletan core previše bučan, dumpovanje samo **zanimljivih čitljivih opsega** često je brže. Frida je naročito korisna jer dobro funkcioniše za **ciljanu ekstrakciju** kada možete da se povežete sa procesom.

Primer pristupa:

1. Nabrojati čitljive/upisive opsege
2. Filtrirati prema modulu, heap-u, stack-u ili anonimnoj memoriji
3. Dumpovati samo regione koji sadrže potencijalne stringove, ključeve, protobuf-e, plist/XML blob-ove ili dekriptovani kod/podatke

Minimalni Frida primer za dumpovanje svih čitljivih anonimnih opsega:
```javascript
Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(function (range) {
try {
if (range.file) return;
var dump = range.base.readByteArray(range.size);
var f = new File('/tmp/' + range.base + '.bin', 'wb');
f.write(dump);
f.close();
} catch (e) {}
});
```
Ovo je korisno kada želite da izbegnete ogromne core fajlove i prikupite samo:

- App heap chunks koji sadrže secrets
- Anonymous regions koje su kreirali custom packers ili loaders
- JIT / unpacked code pages nakon promene protections

Kada target nastavi da **alocira / oslobađa** memoriju dok vršite dump, za nestabilne opsege koristite Frida-inu **`readVolatile()`** primitivu umesto **`readByteArray()`**. Sporija je, ali sprečava prekid rada targeta ako stranica postane nečitljiva usred čitanja. Za veća preuzimanja može biti čistije i da stream-ujete chunks nazad pomoću `send(..., data)` i da ih kompresujete na strani controller-a, umesto da unutar targeta kreirate hiljade malih fajlova.

Postoje i stariji userland alati, kao što je [`readmem`](https://github.com/gdbinit/readmem), ali oni su uglavnom korisni kao **source references** za direktno dump-ovanje u stilu `task_for_pid`/`vm_read` i nisu dobro održavani za moderne Apple Silicon workflows.

## Heap / VM snapshots sa `.memgraph`

Ako vas prvenstveno zanimaju **heap objects**, **allocation provenance** ili snapshot koji može da se prenese na drugu mašinu, `.memgraph` je često praktičniji od ogromnog Mach-O core-a. `leaks` tooling može da ga generiše iz živog procesa:<sup>[[2]](#references)</sup>
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Zatim obavite triage van mreže pomoću standardnih Apple alata:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` je glavni razlog da sačuvate snimak `-fullContent`, jer su oznake koje opisuju sadržaj memorije izostavljene iz minimalnog `.memgraph` fajla.

Ovo je naročito korisno kada:

- Želite **manji snimak koji se može deliti** umesto kompletnog core dump-a
- `MallocStackLogging` je bio omogućen i želite **backtrace-ove alokacija**
- Već znate **zanimljivu heap adresu** i želite da nastavite analizу pomoću `malloc_history`
- Potreban vam je brzi **VM/heap pregled** pre nego što odlučite da li se isplati praviti kompletan dump

### Triage diferencijalnih memgraph snimaka

Ako kontrolišete način na koji se target pokreće, omogućite **historical allocation logging** pre pokretanja kako bi kasniji snimci sačuvali korisne backtrace-ove alokacija i oslobađanja:
```bash
env MallocStackLoggingNoCompact=1 /path/to/TargetBinary
```
Zatim napravite snapshot-e pre i posle zanimljive radnje i uporedite ih offline:
```bash
# Baseline before login / decrypt / unpack
leaks <pid> -outputGraph /tmp/pre.memgraph -fullContent -fullStackHistory

# Snapshot after the sensitive action
leaks <pid> -outputGraph /tmp/post.memgraph -fullContent -fullStackHistory

# Show only new leaks introduced after the baseline
leaks /tmp/post.memgraph -diffFrom=/tmp/pre.memgraph

# Walk from roots to one candidate allocation, or filter the whole tree by class / VM type
leaks /tmp/post.memgraph -traceTree 0xADDR
leaks /tmp/post.memgraph -referenceTree='CFData[50k+]'

# Pivot into the preserved stack history at the interesting high-water mark
malloc_history /tmp/post.memgraph -callTree -highWaterMark
```
Ovo je praktičan način za izolovanje **objekata nakon autentifikacije**, **velikih `CFData` bafera** ili **anonimnih VM regiona** koji se pojavljuju tek nakon faze dešifrovanja, raspakivanja ili preuzimanja tajne.

## Mete sa mnogo Swift koda: `swift-inspect`

Za aplikacije koje čuvaju vredne podatke unutar **objekata Swift runtime-a**, `swift-inspect` može biti dobra dopuna alatima LLDB ili Frida. Umesto da prvo izbacite sve, možete da upitate određene Swift runtime strukture iz aktivnog procesa:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Ovo je korisno za identifikovanje:

- Velikih Swift nizova koji baferuju zanimljive podatke
- Alokacija metapodataka koje otkrivaju tipove učitane tokom izvršavanja
- Swift concurrency stanja (`Task`, actor, odnosi između niti) pre ciljano usmerenog dump-a

Za detaljniji triage na nivou objekata, kada već možete da pregledate proces, pogledajte [posvećenu stranicu o objektima u memoriji](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Napomene za brzi triage

- `sysctl vm.swapusage` je i dalje brz način za proveru **upotrebe swap-a** i utvrđivanje da li je swap **šifrovan**.
- `sleepimage` je i dalje uglavnom relevantan za scenarije **hibernacije/safe sleep-a**, ali ga moderni sistemi često štite, pa ga treba posmatrati kao **izvor artefakata koji treba proveriti**, a ne kao pouzdan put za akviziciju.
- Na novijim izdanjima macOS-a, **dump procesa** je generalno realističniji od **potpunog snimanja fizičke memorije**, osim ako kontrolišete boot policy, stanje SIP-a i učitavanje kext-ova.

## Reference

- [1] [Da li dozvoliti get-task-allow ili ne: analiza macOS bezbednosti](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
