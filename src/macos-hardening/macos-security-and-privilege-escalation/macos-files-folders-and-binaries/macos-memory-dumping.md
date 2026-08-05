# Dump memorije macOS-a

{{#include ../../../banners/hacktricks-training.md}}

## Artefakti memorije

### Swap datoteke

Swap datoteke, kao što je `/private/var/vm/swapfile0`, služe kao **keš kada je fizička memorija puna**. Kada više nema prostora u fizičkoj memoriji, njeni podaci se prebacuju u swap datoteku, a zatim se po potrebi vraćaju u fizičku memoriju. Može biti prisutno više swap datoteka, sa nazivima kao što su swapfile0, swapfile1 i tako dalje.

### Hibernate image

Datoteka koja se nalazi na `/private/var/vm/sleepimage` od ključnog je značaja tokom **hibernation mode-a**. **Podaci iz memorije čuvaju se u ovoj datoteci kada OS X pređe u hibernation**. Kada se računar probudi, sistem preuzima podatke o memoriji iz ove datoteke, omogućavajući korisniku da nastavi tamo gde je stao.

Vredi napomenuti da je na modernim MacOS sistemima ova datoteka obično šifrovana iz bezbednosnih razloga, što otežava oporavak podataka.

- Da biste proverili da li je encryption omogućen za sleepimage, možete pokrenuti komandu `sysctl vm.swapusage`. Ona će prikazati da li je datoteka šifrovana.

### Logovi pritiska memorije

Još jedna važna datoteka povezana sa memorijom na MacOS sistemima jeste **memory pressure log**. Ovi logovi se nalaze u `/var/log` i sadrže detaljne informacije o korišćenju memorije sistema i događajima povezanima sa pritiskom memorije. Mogu biti naročito korisni za dijagnostikovanje problema povezanih sa memorijom ili za razumevanje načina na koji sistem upravlja memorijom tokom vremena.

## Dumpovanje memorije pomoću osxpmem

Da biste dumpovali memoriju na MacOS mašini, možete koristiti [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Napomena**: Ovo je sada uglavnom **legacy workflow**. `osxpmem` zavisi od učitavanja kernel ekstenzije, projekat [Rekall](https://github.com/google/rekall) je arhiviran, najnovije izdanje je iz **2017. godine**, a objavljeni binary namenjen je **Intel Mac računarima**. Na aktuelnim macOS izdanjima, naročito na **Apple Silicon** uređajima, kext-based full-RAM acquisition je obično blokiran modernim ograničenjima kernel ekstenzija, SIP-om i zahtevima za platform signing. U praksi ćete na modernim sistemima češće završiti sa **process-scoped dump-om** umesto image-a cele RAM memorije.
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
**Ostale greške** mogu biti otklonjene **dozvoljavanjem učitavanja kext-a** u odeljku „Security & Privacy --> General“; samo kliknite na **Allow**.

Takođe možete koristiti ovaj **oneliner** za preuzimanje aplikacije, učitavanje kext-a i dump memorije:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
## Dumping živog procesa pomoću LLDB-a

Za **novije verzije macOS-a**, najpraktičniji pristup je obično dump memorije **određenog procesa**, umesto pokušaja da se napravi image celokupne fizičke memorije.

LLDB može da sačuva Mach-O core file iz aktivnog targeta:
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
Ovo je obično dovoljno kada je cilj oporavak:

- Dešifrovanih konfiguracionih blobova
- Tokena, kolačića ili kredencijala iz memorije
- Tajni u čistom tekstu koje su zaštićene samo dok miruju
- Dešifrovanih Mach-O stranica nakon unpacking-a / JIT-a / runtime patching-a

Ako je cilj zaštićen pomoću **hardened runtime-a**, ili ako `taskgated` odbije attach, obično vam je potreban jedan od sledećih uslova:

- Cilj poseduje **`get-task-allow`**
- Vaš debugger je potpisan odgovarajućim **debugger entitlement-om**
- Vi ste **root**, a cilj je third-party proces bez hardened runtime-a

Za više informacija o dobijanju task port-a i radnjama koje se pomoću njega mogu izvršiti:

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/macos-thread-injection-via-task-port.md
{{#endref}}

### Brze provere pre attach-a

Pre nego što utrošite vreme na LLDB/Frida, brzo proverite da li je cilj realno **pogodan za dumpovanje**:
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

- Aplikacija treće strane isporučena sa **`get-task-allow`** često se može direktno dumpovati pomoću LLDB-a, a dobijeni dump može otkriti TCC-zaštićene podatke kojima je aplikacija već pristupila.<sup>[[1]](#references)</sup>
- **Hardened** target bez `get-task-allow` obično odbija attach, čak i kada je korisnik `root`, osim ako kontrolišete relevantne debugger entitlements / policy path.
- Nehardened procesi trećih strana i dalje su najlakše mesto za upotrebu alata `lldb`, `vmmap`, Frida ili prilagođenih `task_for_pid`/`vm_read` čitača.

### Potražite dumpable nested helpers

Nedavna istraživanja notarizovanih macOS aplikacija i dalje često pronalaze **`get-task-allow`** u nested helpers umesto u glavnom GUI binary-ju. Kada top-level aplikacija izgleda hardened, pre nego što odustanete, enumerišite njene **XPC services**, **login items**, **helper tools** i bundled CLIs:
```bash
find /Applications/Target.app -type f -perm -111 -print0 | while IFS= read -r -d '' bin; do
codesign -d --entitlements - "$bin" 2>/dev/null | grep -q 'get-task-allow' && echo "$bin"
done
```
Ugnježdeni executable sa `get-task-allow` često je najlakše mesto za povezivanje pomoću `lldb`, pravljenje core dump-a ili preuzimanje memorije pomoću prilagođenog `task_for_pid` klijenta, čak i kada je glavna aplikacija bolje zaštićena.

## Selektivni dumpovi uz Frida ili userland čitače

Kada je kompletan core previše bučan, dumpovanje samo **zanimljivih čitljivih opsega** često je brže. Frida je naročito korisna jer dobro funkcioniše za **ciljanu ekstrakciju** kada možete da se povežete sa procesom.

Primer pristupa:

1. Izlistajte čitljive/pisljive opsege
2. Filtrirajte prema modulu, heap-u, stack-u ili anonimnoj memoriji
3. Dumpujte samo regione koji sadrže potencijalne stringove, ključeve, protobuf-ove, plist/XML blob-ove ili dekriptovani code/data

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
Ovo je korisno kada želite da izbegnete ogromne core datoteke i prikupite samo:

- Delove heap-a aplikacije koji sadrže secrets
- Anonymous regione koje su kreirali custom packer-i ili loader-i
- JIT / unpacked code stranice nakon promene zaštita

Kada target nastavlja da **alocira / oslobađa** memoriju tokom dump-a, za nestabilne opsege koristite Frida-in **`readVolatile()`** primitive umesto **`readByteArray()`**. Sporiji je, ali sprečava prekid rada target-a ako stranica postane nečitljiva usred čitanja. Za veća preuzimanja može biti praktičnije i čistije da stream-ujete chunk-ove nazad pomoću `send(..., data)` i da ih kompresujete na strani controller-a, umesto da unutar target-a kreirate hiljade malih datoteka.

Postoje i stariji userland alati, kao što je [`readmem`](https://github.com/gdbinit/readmem), ali oni su uglavnom korisni kao **source reference** za direktan `task_for_pid`/`vm_read` stil dump-a i nisu dobro održavani za moderne Apple Silicon workflow-e.

## Heap / VM snapshot-i sa `.memgraph`

Ako vas prvenstveno zanimaju **heap objekti**, **poreklo alokacija** ili snapshot koji može da se prenese na drugu mašinu, `.memgraph` je često praktičniji od ogromnog Mach-O core-a. `leaks` tooling može da ga generiše iz live procesa:
```bash
# Capture a memory graph from a live process
leaks <pid> -outputGraph /tmp/target.memgraph

# Include richer object content when you expect to inspect strings / heap data offline
leaks <pid> -outputGraph /tmp/target-full.memgraph -fullContent
```
Zatim ga analizirajte van mreže pomoću standardnih Apple alata:
```bash
vmmap /tmp/target.memgraph
heap /tmp/target.memgraph
stringdups /tmp/target-full.memgraph
malloc_history /tmp/target.memgraph 0xADDR
```
`stringdups` je glavni razlog da sačuvate capture sa `-fullContent`, jer su oznake koje opisuju sadržaj memorije izostavljene iz minimalnog `.memgraph` fajla.

Ovo je naročito korisno kada:

- Želite **manji snapshot koji se može deliti**, umesto kompletnog core dump-a
- `MallocStackLogging` je bio omogućen i želite **allocation backtrace-ove**
- Već znate za **zanimljivu heap adresu** i želite da nastavite analizu pomoću `malloc_history`
- Potreban vam je brz **VM/heap pregled** pre nego što odlučite da li je full dump vredan dodatnog šuma

### Diferencijalni memgraph triage

Ako kontrolišete način na koji se target pokreće, omogućite **historical allocation logging** pre pokretanja, kako bi kasniji snapshot-i sačuvali korisne alloc/free backtrace-ove:
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
Ovo je praktičan način za izolovanje **post-authentication objekata**, velikih `CFData` bafera ili **anonymous VM regions** koji se pojavljuju tek nakon faze dešifrovanja, raspakivanja ili preuzimanja tajni.

## Mete sa mnogo Swift-a: `swift-inspect`

Za aplikacije koje čuvaju vredne podatke unutar **Swift runtime objekata**, `swift-inspect` može biti dobra dopuna alatima LLDB ili Frida. Umesto da prvo dumpujete sve, možete upitom proveriti određene Swift runtime strukture iz živog procesa:
```bash
# Usually available from the Xcode / Swift toolchain
swift-inspect dump-raw-metadata <pid-or-name>
swift-inspect dump-arrays <pid-or-name>
swift-inspect dump-concurrency <pid-or-name> # Darwin-only
```
Ovo je korisno za identifikovanje:

- Velikih Swift nizova koji baferuju zanimljive podatke
- Alokacija metapodataka koje otkrivaju tipove učitane tokom runtime-a
- Swift concurrency stanja (`Task`, odnosi između actor-a i thread-ova) pre obavljanja ciljanijeg dump-a

Za detaljniji runtime pregled na nivou objekata, kada već možete da pregledate proces, pogledajte [posebnu stranicu o objektima u memoriji](../macos-apps-inspecting-debugging-and-fuzzing/objects-in-memory.md).

## Kratke triage napomene

- `sysctl vm.swapusage` je i dalje brz način za proveru **upotrebe swap-a** i utvrđivanje da li je swap **šifrovan**.
- `sleepimage` je i dalje relevantan uglavnom za scenarije **hibernate/safe sleep**, ali ga moderni sistemi često štite, pa ga treba posmatrati kao **izvor artefakata koji treba proveriti**, a ne kao pouzdan acquisition path.
- Na novijim macOS izdanjima, **dump na nivou procesa** je generalno realniji od **pravljenja kompletne slike fizičke memorije**, osim ako kontrolišete boot policy, stanje SIP-a i učitavanje kext-ova.

## Reference

- [1] [To Allow or Not to get-task-allow: macOS Security Analysis](https://afine.com/to-allow-or-not-to-get-task-allow-that-is-the-question)
- [2] [leaks(1) man page](https://keith.github.io/xcode-man-pages/leaks.1.html)

{{#include ../../../banners/hacktricks-training.md}}
