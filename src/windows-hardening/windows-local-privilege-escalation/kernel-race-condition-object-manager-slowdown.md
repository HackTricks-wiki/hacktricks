# Eksploatacija race condition-a kernela putem sporih putanja Object Manager-a

{{#include ../../banners/hacktricks-training.md}}

## Zašto je važno produžiti race window

Mnogi Windows kernel LPE-ovi prate klasičan obrazac `check_state(); NtOpenX("name"); privileged_action();`. Na modernom hardveru, hladan `NtOpenEvent`/`NtOpenSection` razrešava kratko ime za približno 2 µs, ostavljajući gotovo nimalo vremena da se provereno stanje promeni pre izvršavanja bezbedne radnje. Namernim primoravanjem pretrage Object Manager Namespace-a (OMNS) u koraku 2 da traje desetinama mikrosekundi, napadač dobija dovoljno vremena da dosledno dobije race koji bi inače bio nepouzdan, bez potrebe za hiljadama pokušaja.<sup>[[1]](#references)</sup>

## Interni detalji Object Manager pretrage ukratko

* **OMNS struktura** – Imena kao što je `\BaseNamedObjects\Foo` razrešavaju se direktorijum po direktorijum. Svaka komponenta uzrokuje da kernel pronađe/otvori *Object Directory* i uporedi Unicode stringove. Simboličke veze (npr. slova diskova) mogu biti praćene tokom pretrage.
* **UNICODE_STRING ograničenje** – OM putanje se prenose unutar `UNICODE_STRING` čiji je `Length` 16-bitna vrednost. Apsolutno ograničenje je 65 535 bajtova (32 767 UTF-16 codepoint-a). Sa prefiksima kao što je `\BaseNamedObjects\`, napadač i dalje kontroliše približno 32 000 karaktera.
* **Preduslovi za napadača** – Svaki korisnik može da kreira objekte unutar direktorijuma sa dozvolom upisa, kao što je `\BaseNamedObjects`. Kada ranjivi kod koristi ime unutar njega ili prati simboličku vezu koja završava tamo, napadač kontroliše performanse pretrage bez posebnih privilegija.<sup>[[1]](#references)</sup>

## Primitiv za usporavanje #1 – Jedna maksimalna komponenta

Trošak razrešavanja komponente približno je linearan sa njenom dužinom, jer kernel mora da izvrši Unicode poređenje sa svakim unosom u nadređenom direktorijumu. Kreiranje event-a sa imenom dugim 32 kB odmah povećava latenciju `NtOpenEvent` sa približno 2 µs na približno 35 µs u sistemu Windows 11 24H2 (testna platforma Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktične napomene*

- Ograničenje dužine možete doseći korišćenjem bilo kog imenovanog kernel objekta (events, sections, semaphores…).
- Symbolic links ili reparse points mogu da usmere kratko ime „victim“ ka ovoj ogromnoj komponenti, tako da se usporavanje primeni transparentno.
- Pošto se sve nalazi u namespace-ovima koje korisnik može da menja, payload funkcioniše sa standardnim nivoom integriteta korisnika.<sup>[[1]](#references)</sup>

## Primitiv za usporavanje #2 – Duboko rekurzivni direktorijumi

Agresivnija varijanta alocira lanac od hiljada direktorijuma (`\BaseNamedObjects\A\A\...\X`). Svaki korak aktivira logiku za razrešavanje direktorijuma (provere ACL-a, hash lookups, reference counting), pa je kašnjenje po nivou veće nego kod jednog poređenja stringova. Sa približno 16 000 nivoa (ograničeno istom veličinom `UNICODE_STRING` strukture), empirijska merenja premašuju prag od 35 µs koji se postiže korišćenjem dugih pojedinačnih komponenti.
```cpp
ScopedHandle base_dir = OpenDirectory(L"\\BaseNamedObjects");
HANDLE last_dir = base_dir.get();
std::vector<ScopedHandle> dirs;
for (int i = 0; i < 16000; i++) {
dirs.emplace_back(CreateDirectory(L"A", last_dir));
last_dir = dirs.back().get();
if ((i % 500) == 0) {
auto result = RunTest(GetName(last_dir) + L"\\X", iterations);
printf("%d,%f\n", i + 1, result);
}
}
```
Saveti:

* Menjajte znak po nivou (`A/B/C/...`) ako nadređeni direktorijum počne da odbija duplikate.
* Čuvajte niz handle-ova kako biste mogli čisto da obrišete lanac nakon exploitation-a i izbegnete zagađivanje namespace-a.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – shadow directories, hash collisions & symlink reparses (minuti umesto mikrosekundi)

Object directories podržavaju **shadow directories** (fallback lookups) i hash tabele podeljene na bucket-e za entries. Iskoristite oba mehanizma, zajedno sa ograničenjem od 64 komponente za symbolic-link reparse, da višestruko usporite obradu bez prekoračenja dužine `UNICODE_STRING`:

1. Kreirajte dva direktorijuma ispod `\BaseNamedObjects`, na primer `A` (shadow) i `A\A` (target). Kreirajte drugi koristeći prvi kao shadow directory (`NtCreateDirectoryObjectEx`), tako da se missing lookups u `A` prosleđuju na `A\A`.
2. Popunite svaki direktorijum hiljadama **colliding names** koji dospevaju u isti hash bucket (na primer, menjajte završne cifre dok zadržavate istu vrednost `RtlHashUnicodeString`). Lookups se sada degradiraju u O(n) linearne pretrage unutar jednog direktorijuma.
3. Napravite lanac od približno 63 **Object Manager symbolic links** koji se ponovljenim reparse-om usmeravaju u dugački `A\A\…` suffix, trošeći reparse budžet. Svaki reparse ponovo pokreće parsiranje od vrha, čime se cena collision-a multiplicira.
4. Lookup finalne komponente (`...\\0`) sada traje **minutima** na Windows 11 kada je prisutno 16 000 collisions po direktorijumu, čime se obezbeđuje praktično garantovana pobeda u race-u za one-shot kernel LPEs.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Zašto je važno*: Usporavanje koje traje nekoliko minuta pretvara jednokratne LPE napade zasnovane na race condition-u u determinističke exploit-e.<sup>[[1]](#references)</sup>

### Beleške o ponovnom testiranju iz 2025. i gotovi alati

- James Forshaw je ponovo objavio tehniku sa ažuriranim vremenskim parametrima za Windows 11 24H2 (ARM64). Osnovna otvaranja i dalje traju oko 2 µs; komponenta od 32 kB povećava ovo na oko 35 µs, dok shadow-dir + collision + lanci sa 63 reparse tačke i dalje dostižu oko 3 minuta, čime se potvrđuje da primitives opstaju u aktuelnim buildovima. Izvorni kod i perf harness nalaze se u osveženoj Project Zero objavi.<sup>[[1]](#references)</sup>
- Podešavanje možete skriptovati pomoću javnog paketa `symboliclink-testing-tools`: `CreateObjectDirectory.exe` za kreiranje para shadow/target i `NativeSymlink.exe` u petlji za generisanje lanca od 63 hop-a. Ovo izbegava ručno pisanje `NtCreate*` wrapper-a i održava ACL-ove doslednim.<sup>[[2]](#references)</sup>

## Merenje vašeg race prozora

Ugradite brzi harness u svoj exploit kako biste izmerili koliki prozor postaje na hardveru žrtve. Isječak ispod otvara ciljni objekat `iterations` puta i vraća prosečnu cenu po otvaranju koristeći `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
```cpp
static double RunTest(const std::wstring name, int iterations,
std::wstring create_name = L"", HANDLE root = nullptr) {
if (create_name.empty()) {
create_name = name;
}
ScopedHandle event_handle = CreateEvent(create_name, root);
ObjectAttributes obja(name);
std::vector<ScopedHandle> handles;
Timer timer;
for (int i = 0; i < iterations; ++i) {
HANDLE open_handle;
Check(NtOpenEvent(&open_handle, MAXIMUM_ALLOWED, &obja));
handles.emplace_back(open_handle);
}
return timer.GetTime(iterations);
}
```
Rezultati se direktno koriste u strategiji orkestracije race uslova (npr. broj potrebnih radnih niti, intervali spavanja i koliko rano morate da promenite deljeno stanje).

## Tok eksploatacije

1. **Locirajte ranjivo otvaranje** – Pratite putanju kernela (pomoću simbola, ETW-a, hypervisor tracing-a ili reverse engineering-a) dok ne pronađete poziv `NtOpen*`/`ObOpenObjectByName` koji obrađuje ime pod kontrolom napadača ili simboličku vezu u direktorijumu u koji korisnik može da upisuje.
2. **Zamenite to ime sporom putanjom**
- Kreirajte dugu komponentu ili lanac direktorijuma pod `\BaseNamedObjects` (ili drugim upisivim OM root direktorijumom).
- Kreirajte simboličku vezu tako da se ime koje kernel očekuje sada razrešava u sporu putanju. Ranjivoj komponenti možete preusmeriti pretragu direktorijuma na svoju strukturu bez menjanja originalnog cilja.
3. **Pokrenite race uslov**
- Nit A (žrtva) izvršava ranjivi kod i blokira se unutar spore pretrage.
- Nit B (napadač) menja zaštićeno stanje (npr. menja file handle, ponovo upisuje simboličku vezu ili menja object security) dok je Nit A zauzeta.
- Kada se Nit A nastavi i izvrši privilegovanu radnju, ona vidi zastarelo stanje i izvršava operaciju pod kontrolom napadača.
4. **Očistite tragove** – Obrišite lanac direktorijuma i simboličke veze kako ne biste ostavili sumnjive artefakte ili prekinuli rad legitimnih IPC korisnika.<sup>[[1]](#references)</sup>

## Primenjeni lanac: promenljivi Cloud Files placeholders + Object Manager preusmeravanje putanje

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), objavljen kao bypass za RoguePlanet (CVE-2026-50656), demonstrira širi exploitation pattern: naterati privilegovani skener da klasifikuje jednu reprezentaciju logičkog fajla, a zatim promeniti i njegove bajtove i razrešavanje namespace-a pre nego što remediation upotrebi taj fajl. PoC kombinuje Cloud Files hydration TOCTOU, Object Manager shadow-directory fallback, hvatanje CLFS-generated-name vrednosti i lokalnu administrative-share link vezu kako bi čišćenje koje izvršava Defender pretvorio u upis zaštićenog DLL-a.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Zamenite sadržaj pomoću Cloud Files hydration procesa

Registrujte direktorijum u koji napadač može da upisuje kao Cloud Files sync root, povežite `CF_CALLBACK_TYPE_FETCH_DATA` callback i kreirajte placeholder čija oglašena veličina odgovara determinističkom detection trigger-u, kao što je EICAR ZIP. Prvi fetch vraća trigger i menja callback stanje; kasniji fetch pozivi vraćaju payload. Nakon što skener klasifikuje prvu reprezentaciju, preuzmite transfer key i ponovo pokrenite hydration sa metadata veličinom payload-a, a zatim naterajte hydration do EOF.<sup>[[4]](#references)</sup>
```cpp
CfRegisterSyncRoot(sync_root, &registration, &policies, flags);
CfConnectSyncRoot(sync_root, callbacks, &state, connect_flags, &connection);
CfCreatePlaceholders(sync_root, &placeholder, 1, 0, &created);
// First FETCH_DATA => detection trigger; later FETCH_DATA => payload.
CfGetTransferKey(placeholder_handle, &transfer_key);
opInfo.Type = CF_OPERATION_TYPE_RESTART_HYDRATION;
CfExecute(&opInfo, &restart_params);
CfHydratePlaceholder(placeholder_handle, {0}, CF_EOF, 0, NULL);
```
Granica bezbednosti ne uspeva ako se scan, verdict i remediation oslanjaju samo na pathname ili placeholder identity: nijedno od toga ne garantuje da će kasnija hydration vratiti bajtove koji su pregledani.<sup>[[4]](#references)</sup>

### 2. Preusmerite invariantnu putanju kroz shadow-directory fallback

Kreirajte ciljni Object Manager direktorijum i drugi direktorijum pomoću `NtCreateDirectoryObjectEx`, prosleđujući handle cilja kao njegov shadow/fallback direktorijum. Postavite istoimeni `WD_SCAN` entry u oba sloja rezolucije: vidljivi entry pokazuje na uobičajeni working directory, dok fallback entry pokazuje na `\CLFS\??\<working-directory>`. Defender-u prosledite samo invariantnu putanju u nastavku; brisanje vidljive veze dok je operacija aktivna dovodi do toga da isti string pređe na entry zasnovan na CLFS-u.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Ovo se razlikuje od korišćenja **shadow directories** samo radi usporavanja lookup-a: napadač menja **značenje** prethodno prihvaćene putanje bez izmene njenog stringa.<sup>[[4]](#references)</sup>

### 3. Preuzmite generisano ime i instalirajte link specifičan za ime datoteke

Nadgledajte radni direktorijum pomoću `ReadDirectoryChangesW`. Pri prvom `FILE_ACTION_ADDED`, uklonite vidljivi `WD_SCAN` link da biste aktivirali fallback lookup. Preuzmite drugo generisano ime datoteke, otvorite tu datoteku povezanu sa CLFS-om i zaključajte opseg `0..MAXLONGLONG` pomoću `LockFileEx`. Dok je privilegovana operacija blokirana, zamenite `WD_SCAN` u vidljivom direktorijumu pravim Object Manager direktorijumom i kreirajte podređeni simbolički link sa imenom izvedenim iz uočenog imena datoteke (PoC uklanja njegova poslednja četiri znaka). Usmerite ga ka zaštićenom odredištu kroz lokalni SMB:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Neprivilegovani proces ne može sam da upisuje na to odredište, ali Defender-ov SYSTEM kontekst može da pristupi loopback administrativnom share-u. Kombinovanje posmatranja generisanih imena sa vezom Object Manager-a specifičnom za naziv datoteke eliminiše potrebu da se unapred predvidi remediation artefakt.<sup>[[4]](#references)</sup>

### 4. Stabilizujte race uslov tokom čišćenja i pokrenite privilegovani loader

Pre skeniranja, PoC čuva validan PE (`ntdll.dll`) u placeholder-ovom `:stream` NTFS alternate data stream-u. Nakon što redirekcija kreira zaštićenu osnovnu datoteku, otvara `phoneinfo.dll:stream` sa execute pristupom i održava aktivnim `PAGE_EXECUTE_READ | SEC_IMAGE` mapiranje dok se čišćenje nastavlja; aktivni objekti datoteke/sekcije ograničavaju brisanje ili zamenu tokom završnog race uslova. Ponovo pokrenuta hydration operacija sada vraća payload DLL umesto EICAR-a, tako da zaštićena osnovna datoteka sadrži kod pod kontrolom napadača.<sup>[[4]](#references)</sup>

Zaštićeni upis se zatim pretvara u SYSTEM izvršavanje postavljanjem kreiranog `Report.wer` fajla pod `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` i pozivanjem `\Microsoft\Windows\Windows Error Reporting\QueueReporting` kroz Task Scheduler COM API. U ovom lancu, privilegovana WER obrada učitava ubačeni `C:\Windows\System32\phoneinfo.dll`; konekcija imenovanim pipe-om koristi se kao signal za izvršavanje payload-a.<sup>[[4]](#references)</sup>

### Detekcioni indikatori

Korisne korelacije su specifičnije od bilo kog pojedinačnog privremenog naziva datoteke i obuhvataju sve namespace tranzicije u lancu:<sup>[[4]](#references)</sup>

- Novo registrovani Cloud Files provider, nakon kog slede EICAR detekcija i `CF_OPERATION_TYPE_RESTART_HYDRATION` nad istim placeholder-om.
- Object Manager putanje koje sadrže `WD_TARGET_*`, `WD_SHADOW_*` ili `WD_SCAN`, naročito scan putanju ispod `\\.\globalroot\BaseNamedObjects\Restricted\`.
- Kreiranje CLFS datoteke, nakon kog slede ekskluzivno zaključavanje cele datoteke i loopback pristup putanji `\\127.0.0.1\C$\Windows\System32\*.dll` iz privilegovanog security procesa.
- Kreiranje System32 DLL-a zajedno sa NTFS ADS-om, nakon kog slede `SEC_IMAGE` mapiranje stream-a.
- WER queue unos koji je kreirao napadač, nakon kog slede neuobičajeno ručno pokretanje `\Microsoft\Windows\Windows Error Reporting\QueueReporting` i učitavanje image-a ubačenog DLL-a.

## Operativna razmatranja

- **Kombinujte primitive** – Možete koristiti dugo ime *po nivou* u lancu direktorijuma za još veće kašnjenje, sve dok ne iscrpite veličinu `UNICODE_STRING`.
- **One-shot bugovi** – Prošireni prozor (od desetina mikrosekundi do nekoliko minuta) čini “single trigger” bugove realističnim kada se kombinuju sa vezivanjem za CPU affinity ili preemption-om potpomognutim hypervisor-om.
- **Sporedni efekti** – Usporavanje utiče samo na malicious putanju, tako da ukupne performanse sistema ostaju nepromenjene; defenderi će to retko primetiti osim ako nadziru rast namespace-a.
- **Čišćenje** – Zadržite handle-ove ka svakom direktorijumu/objektu koji kreirate kako biste nakon toga mogli da pozovete `NtMakeTemporaryObject`/`NtClose`. Lanci direktorijuma bez ograničenja mogu u suprotnom opstati i nakon restartovanja sistema.
- **Race uslovi na file system-u** – Ako se ranjiva putanja na kraju razrešava kroz NTFS, možete postaviti Oplock (npr. `SetOpLock.exe` iz istog toolkit-a) nad pratećom datotekom dok OM slowdown traje, zamrzavajući consumer na dodatne milisekunde bez menjanja OM grafa.<sup>[[2]](#references)</sup>

## Odbrambene napomene

- Kernel kod koji se oslanja na named objekte treba ponovo da proveri security-sensitive stanje *nakon* otvaranja ili da uzme referencu pre provere (zatvarajući TOCTOU prazninu).
- Nametnite gornje granice dubine/dužine OM putanje pre dereferenciranja imena pod kontrolom korisnika. Odbacivanje predugačkih imena primorava napadače da se vrate u prozor od nekoliko mikrosekundi.
- Instrumentujte rast namespace-a Object Manager-a (ETW `Microsoft-Windows-Kernel-Object`) kako biste otkrili sumnjive lance sa hiljadama komponenti ispod `\BaseNamedObjects`.

## References

- [1] [Project Zero – Windows Tehnike eksploatacije: Dobijanje race uslova pomoću pretrage putanja](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
{{#include ../../banners/hacktricks-training.md}}
