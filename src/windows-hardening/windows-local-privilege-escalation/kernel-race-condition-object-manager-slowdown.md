# Exploatacija Kernel Race Condition putem Slow Paths u Object Manager-u

{{#include ../../banners/hacktricks-training.md}}

## Zašto je važno produžiti race window

Mnogi Windows kernel LPE-ovi prate klasičan obrazac `check_state(); NtOpenX("name"); privileged_action();`. Na modernom hardveru, cold `NtOpenEvent`/`NtOpenSection` razrešava kratko ime za približno 2 µs, ostavljajući gotovo nimalo vremena da se provereno stanje promeni pre izvršavanja bezbedne radnje. Namernim primoravanjem Object Manager Namespace (OMNS) lookup-a u koraku 2 da traje desetinama mikrosekundi, napadač dobija dovoljno vremena da dosledno dobije inače nepouzdane race-ove bez potrebe za hiljadama pokušaja.<sup>[[1]](#references)</sup>

## Ukratko o internim detaljima Object Manager lookup-a

* **OMNS struktura** – Imena kao što je `\BaseNamedObjects\Foo` razrešavaju se direktorijum po direktorijum. Svaka komponenta zahteva da kernel pronađe/otvori *Object Directory* i uporedi Unicode stringove. Symbolic links (npr. slova diskova) mogu biti praćeni tokom tog procesa.
* **UNICODE_STRING ograničenje** – OM putanje se prenose unutar `UNICODE_STRING` čiji je `Length` 16-bitna vrednost. Apsolutno ograničenje iznosi 65 535 bajtova (32 767 UTF-16 codepoints). Sa prefiksima kao što je `\BaseNamedObjects\`, napadač i dalje kontroliše približno 32 000 karaktera.
* **Preduslovi za napadača** – Svaki korisnik može kreirati objekte unutar direktorijuma u koje je dozvoljen upis, kao što je `\BaseNamedObjects`. Kada ranjivi kod koristi ime unutar takvog direktorijuma ili prati symbolic link koji tamo vodi, napadač kontroliše performanse lookup-a bez posebnih privilegija.<sup>[[1]](#references)</sup>

## Primitiva za usporavanje #1 – Jedna maksimalna komponenta

Trošak razrešavanja komponente približno je linearan u odnosu na njenu dužinu, jer kernel mora da izvrši Unicode poređenje sa svakim unosom u nadređenom direktorijumu. Kreiranje event-a sa imenom dugim 32 kB odmah povećava latenciju `NtOpenEvent` sa približno 2 µs na približno 35 µs na Windows 11 24H2 (testno okruženje Snapdragon X Elite).
```cpp
std::wstring path;
while (path.size() <= 32000) {
auto result = RunTest(L"\\BaseNamedObjects\\A" + path, 1000);
printf("%zu,%f\n", path.size(), result);
path += std::wstring(500, 'A');
}
```
*Praktične napomene*

- Ograničenje dužine možete dostići korišćenjem bilo kog named kernel object-a (events, sections, semaphores…).
- Symbolic links ili reparse points mogu usmeriti kratko ime „victim“ ka ovoj ogromnoj komponenti, tako da se usporavanje primenjuje transparentno.
- Pošto se sve nalazi u namespace-ovima koje korisnik može da menja, payload funkcioniše sa standardnim nivoom integriteta korisnika.<sup>[[1]](#references)</sup>

## Slowdown primitive #2 – Duboko rekurzivni direktorijumi

Agresivnija varijanta alocira lanac od hiljada direktorijuma (`\BaseNamedObjects\A\A\...\X`). Svaki korak pokreće logiku razrešavanja direktorijuma (provere ACL-ova, hash pretrage, reference counting), pa je latencija po nivou veća nego kod jednog poređenja stringova. Sa približno 16 000 nivoa (ograničeno istom veličinom `UNICODE_STRING`-a), empirijska merenja premašuju prag od 35 µs postignut korišćenjem dugih pojedinačnih komponenti.
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

* Menjajte karakter po nivou (`A/B/C/...`) ako nadređeni direktorijum počne da odbija duplikate.
* Čuvajte niz handle-ova kako biste mogli čisto da obrišete lanac nakon exploitation-a i izbegnete zagađivanje namespace-a.<sup>[[1]](#references)</sup>

## Slowdown primitive #3 – Shadow directories, hash collisions & symlink reparses (minuti umesto mikrosekundi)

Object directories podržavaju **shadow directories** (fallback lookups) i hash tabele podeljene na bucket-e za entries. Zloupotrebite oba mehanizma, zajedno sa ograničenjem od 64 komponente za symbolic-link reparse, kako biste višestruko povećali usporavanje bez prekoračenja dužine `UNICODE_STRING`:

1. Kreirajte dva direktorijuma pod `\BaseNamedObjects`, na primer `A` (shadow) i `A\A` (target). Kreirajte drugi koristeći prvi kao shadow directory (`NtCreateDirectoryObjectEx`), tako da se nepostojeći lookups u `A` prosleđuju u `A\A`.
2. Popunite svaki direktorijum hiljadama **colliding names** koji završavaju u istom hash bucket-u (na primer, menjajte završne cifre uz zadržavanje iste `RtlHashUnicodeString` vrednosti). Lookups se sada degradiraju u O(n) linearna skeniranja unutar jednog direktorijuma.
3. Izgradite lanac od približno 63 **object manager symbolic links** koji se uzastopno reparsiraju u dugački `A\A\…` suffix, trošeći reparse budžet. Svaki reparse ponovo pokreće parsiranje od početka, višestruko povećavajući collision cost.
4. Lookup završne komponente (`...\\0`) sada traje **minutima** na Windows 11 kada je u svakom direktorijumu prisutno 16 000 collisions, što praktično garantuje dobijanje race-a kod one-shot kernel LPE-ova.
```cpp
ScopedHandle shadow = CreateDirectory(L"\\BaseNamedObjects\\A");
ScopedHandle target = CreateDirectoryEx(L"A", shadow.get(), shadow.get());
CreateCollidingEntries(shadow, 16000, dirs);
CreateCollidingEntries(target, 16000, dirs);
CreateSymlinkChain(shadow, LongSuffix(L"\\A", 16000), 63);
printf("%f\n", RunTest(LongSuffix(L"\\A", 16000) + L"\\0", 1));
```
*Zašto je važno*: Usporavanje od nekoliko minuta pretvara jednokratne race-based LPE napade u determinističke exploit-e.<sup>[[1]](#references)</sup>

### Beleške o ponovnom testiranju iz 2025. i gotovi alati

- James Forshaw je ponovo objavio tehniku sa ažuriranim vremenima na Windows 11 24H2 (ARM64). Osnovna otvaranja i dalje traju približno 2 µs; komponenta od 32 kB povećava to na približno 35 µs, a shadow-dir + collision + 63-reparse lanci i dalje dostižu približno ~3 minuta, čime se potvrđuje da primitive opstaju u aktuelnim buildovima. Izvorni kod i perf harness nalaze se u osveženoj Project Zero objavi.<sup>[[1]](#references)</sup>
- Podešavanje možete automatizovati pomoću javno dostupnog `symboliclink-testing-tools` paketa: `CreateObjectDirectory.exe` za kreiranje shadow/target para i `NativeSymlink.exe` u petlji za generisanje lanca od 63 hop-a. Ovo eliminiše potrebu za ručno pisanim `NtCreate*` wrapper-ima i održava ACL-ove doslednim.<sup>[[2]](#references)</sup>

## Measuring your race window

U svoj exploit ubacite brzi harness kako biste izmerili koliki prozor postaje na victim hardveru. Iskaz u nastavku otvara target object `iterations` puta i vraća prosečan trošak po otvaranju pomoću `QueryPerformanceCounter`.<sup>[[1]](#references)</sup>
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
Rezultati se direktno koriste u vašoj strategiji orkestracije race uslova (npr. broj potrebnih worker thread-ova, intervali spavanja i koliko rano treba promeniti deljeno stanje).

## Tok eksploatacije

1. **Locirajte ranjivo otvaranje** – Pratite putanju kroz kernel (pomoću simbola, ETW-a, hypervisor tracing-a ili reverse engineering-a) dok ne pronađete poziv `NtOpen*`/`ObOpenObjectByName` koji obrađuje ime pod kontrolom napadača ili symbolic link u direktorijumu u koji korisnik može da upisuje.
2. **Zamenite to ime sporom putanjom**
- Kreirajte dugu komponentu ili lanac direktorijuma ispod `\BaseNamedObjects` (ili drugog upisivog OM root-a).
- Kreirajte symbolic link tako da se ime koje kernel očekuje sada razrešava na sporu putanju. Ranjivi driver-ov directory lookup možete usmeriti na svoju strukturu bez menjanja originalnog target-a.
3. **Pokrenite race**
- Thread A (žrtva) izvršava ranjivi kod i blokira se unutar sporog lookup-a.
- Thread B (napadač) menja zaštićeno stanje (npr. zamenjuje file handle, ponovo upisuje symbolic link ili menja object security) dok je Thread A zauzet.
- Kada Thread A nastavi izvršavanje i obavi privilegovanu radnju, on uočava zastarelo stanje i izvršava operaciju pod kontrolom napadača.
4. **Očistite tragove** – Obrišite lanac direktorijuma i symbolic links kako ne biste ostavili sumnjive artefakte ili pokvarili legitimne IPC korisnike.<sup>[[1]](#references)</sup>

## Primenjeni chain: mutable Cloud Files placeholders + Object Manager path switching

[ShieldBreak](https://github.com/MSNightmare/ShieldBreak), objavljen kao bypass za RoguePlanet (CVE-2026-50656), demonstrira širi obrazac eksploatacije: naterati privilegovani scanner da klasifikuje jednu reprezentaciju logičkog fajla, a zatim promeniti i njegove bajtove i razrešavanje namespace-a pre nego što remediation iskoristi te podatke. PoC kombinuje Cloud Files hydration TOCTOU, Object Manager shadow-directory fallback, CLFS-generated-name capture i lokalni administrative-share link kako bi Defender cleanup pretvorio u upis zaštićenog DLL-a.<sup>[[3]](#references)[[4]](#references)</sup>

### 1. Zamenite sadržaj kroz Cloud Files hydration

Registrujte direktorijum u koji napadač može da upisuje kao Cloud Files sync root, povežite `CF_CALLBACK_TYPE_FETCH_DATA` callback i kreirajte placeholder čija se oglašena veličina podudara sa determinističkim detection trigger-om, kao što je EICAR ZIP. Prvi fetch vraća trigger i menja stanje callback-a; naredni fetch-ovi vraćaju payload. Nakon što scanner klasifikuje prvu reprezentaciju, pribavite transfer key i ponovo pokrenite hydration sa metadata-om veličine payload-a, a zatim forsirajte hydration do EOF-a.<sup>[[4]](#references)</sup>
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
Granica bezbednosti ne uspeva ako se scan, procena i remediation odnose samo na putanju ili placeholder identitet: nijedno od toga ne garantuje da će kasnija hidratacija vratiti bajtove koji su bili pregledani.<sup>[[4]](#references)</sup>

### 2. Prebacite invariantnu putanju kroz shadow-directory fallback

Kreirajte ciljnu Object Manager fasciklu i drugu fasciklu pomoću `NtCreateDirectoryObjectEx`, prosleđujući handle ciljne fascikle kao njenu shadow/fallback fasciklu. Postavite istoimeni `WD_SCAN` unos u oba sloja razrešavanja: vidljivi unos pokazuje na uobičajenu radnu fasciklu, dok fallback unos pokazuje na `\CLFS\??\<working-directory>`. Defenderu prosledite samo invariantnu putanju u nastavku; brisanje vidljive veze dok je operacija aktivna dovodi do toga da isti string pređe na CLFS-backed unos.<sup>[[4]](#references)</sup>
```text
\\.\globalroot\BaseNamedObjects\Restricted\WD_SHADOW_<GUID>\WD_SCAN\BERLIN
```
Ovo se razlikuje od korišćenja shadow directories samo za usporavanje pretrage: napadač menja **značenje** prethodno prihvaćene putanje bez izmene njenog stringa.<sup>[[4]](#references)</sup>

### 3. Hvatanje generisanog imena i instaliranje linka specifičnog za naziv datoteke

Nadgledajte radni direktorijum pomoću `ReadDirectoryChangesW`. Pri prvom `FILE_ACTION_ADDED` uklonite vidljivi `WD_SCAN` link da biste aktivirali fallback lookup. Uhvatite drugo generisano ime datoteke, otvorite tu datoteku povezanu sa CLFS-om i zaključajte opseg `0..MAXLONGLONG` pomoću `LockFileEx`. Dok je privilegovana operacija zaustavljena, zamenite `WD_SCAN` u vidljivom direktorijumu pravim Object Manager direktorijumom i kreirajte child symbolic link sa nazivom izvedenim iz uočenog imena datoteke (PoC uklanja njegova poslednja četiri znaka). Usmerite ga ka zaštićenom odredištu kroz lokalni SMB:<sup>[[4]](#references)</sup>
```text
\??\UNC\127.0.0.1\C$\Windows\System32\phoneinfo.dll
```
Neprivilegovani proces ne može sam da upisuje na to odredište, ali Defender-ov SYSTEM kontekst može da pristupi loopback administrativnom share-u. Kombinovanje posmatranja generisanog imena sa Object Manager linkom specifičnim za naziv datoteke uklanja potrebu za prethodnim predviđanjem remediation artefakta.<sup>[[4]](#references)</sup>

### 4. Stabilizovanje cleanup race-a i pokretanje privilegovanog loader-a

Pre skeniranja, PoC čuva validan PE (`ntdll.dll`) u placeholder-ovom `:stream` NTFS alternate data stream-u. Nakon što redirection kreira zaštićenu osnovnu datoteku, otvara `phoneinfo.dll:stream` sa execute pristupom i održava `PAGE_EXECUTE_READ | SEC_IMAGE` mapiranje aktivnim dok se cleanup nastavlja; aktivni file/section objekti ograničavaju brisanje ili zamenu tokom završnog race-a. Ponovo pokrenuta hydration operacija sada vraća payload DLL umesto EICAR-a, tako da zaštićena osnovna datoteka sadrži kod pod kontrolom napadača.<sup>[[4]](#references)</sup>

Zaštićeni upis se zatim pretvara u SYSTEM izvršavanje postavljanjem konstruisanog `Report.wer` fajla u `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\...` i pozivanjem `\Microsoft\Windows\Windows Error Reporting\QueueReporting` preko Task Scheduler COM API-ja. U ovom chain-u, privilegovani WER processing učitava postavljeni `C:\Windows\System32\phoneinfo.dll`; named-pipe konekcija se koristi kao signal za izvršavanje payload-a.<sup>[[4]](#references)</sup>

### Detection pivots

Korisne korelacije su specifičnije od bilo kog pojedinačnog privremenog imena i obuhvataju sve namespace tranzicije u chain-u:<sup>[[4]](#references)</sup>

- Novo registrovani Cloud Files provider, nakon čega slede EICAR detekcija i `CF_OPERATION_TYPE_RESTART_HYDRATION` nad istim placeholder-om.
- Object Manager putanje koje sadrže `WD_TARGET_*`, `WD_SHADOW_*` ili `WD_SCAN`, naročito scan putanja ispod `\\.\globalroot\BaseNamedObjects\Restricted\`.
- Kreiranje CLFS datoteke, nakon čega slede ekskluzivni lock nad celom datotekom i loopback pristup lokaciji `\\127.0.0.1\C$\Windows\System32\*.dll` iz privilegovanog security procesa.
- Kreiranje System32 DLL-a zajedno sa NTFS ADS-om, nakon čega sledi `SEC_IMAGE` mapiranje stream-a.
- WER queue entry koji je kreirao napadač, nakon čega slede neuobičajeno ručno pokretanje `\Microsoft\Windows\Windows Error Reporting\QueueReporting` i učitavanje image-a postavljenog DLL-a.

## Applied chain: oplock-gated mount-point switch against privileged remediation

Ponovljivi LPE pattern pojavljuje se kada privilegovani scanner proverava datoteku pod kontrolom napadača, a zatim vrši remediation tako što ponovo otvara **pathname**, umesto da nastavi preko validiranih handle-ova. FalconFlank je javni primer usmeren na CrowdStrike Falcon workflow za uklanjanje Office makroa; repository navodi testiranje na Windows 11 25H2 i Windows Server 2025 sa uključenom relevantnom policy-jem, ali ne objavljuje CVE, opseg pogođenih build-ova, vendor advisory niti status patch-a, pa product-specific claim treba tretirati kao neproveren i zavisan od build-a.<sup>[[5]](#references)[[6]](#references)</sup>

### Race layout

1. Napravite writable tree čije je završno relativno ime korisno na predviđenom odredištu. Primer koristi `%TEMP%\\Flanker_{GUID}\\WindowsPowerShell\\v1.0\\bcrypt.dll`, ali u početku upisuje OLE macro document — ne PE DLL — u `bcrypt.dll`. Content-based detection pokreće remediation, dok se basename pod kontrolom napadača zadržava za kasniji side-load.<sup>[[5]](#references)</sup>
2. Otvorite direktorijume sa širokim sharing-om i `FILE_OPEN_REPARSE_POINT`, zatim zatražite asinhroni RH oplock nad trigger-om pomoću `FSCTL_REQUEST_OPLOCK`, `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE` i `REQUEST_OPLOCK_INPUT_FLAG_REQUEST`. Sačekajte overlapped event i koristite njegovo završavanje kao signal za path-switch. RH oplock-break notification je savetodavna, a ne dokaz da je svaka konfliktna operacija blokirana, tako da exploitability i dalje zavisi od tačne open/remediation sekvence kod victim-a.<sup>[[5]](#references)[[7]](#references)</sup>
3. Nakon break-a, uklonite leaf directory pomoću `FileDispositionInformationEx` (information class 64), koristeći delete i POSIX-semantics flags, zatvorite njegov handle i primenite `IO_REPARSE_TAG_MOUNT_POINT` na sada prazan parent pomoću `FSCTL_SET_REPARSE_POINT_EX`. Mount point preusmerava nepromenjeni suffix u zaštićeno stablo, kao što je `\\SystemRoot\\System32\\WindowsPowerShell`; postavljanje reparse point-a ne uspeva ako direktorijum nije prazan, što objašnjava prethodni korak brisanja.<sup>[[5]](#references)[[8]](#references)</sup>
4. Nastavite privilegovani workflow. Ako ponovo razreši string bez potvrde da su directory chain i final object isti oni koji su prethodno pregledani, ista logička pathname sada vodi do directory-ja koji je napadač izabrao u zaštićenom stablu. U primeru se uspeh proverava ponovnim otvaranjem `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll` za čitanje/upis iz originalnog procesa; time se confused-deputy write primitive razlikuje od kasnije code-execution faze.<sup>[[5]](#references)</sup>
5. Zamenite rezultujuću datoteku pravim DLL-om i aktivirajte privilegovani loader. PoC koristi `CreateTransaction` + `CreateFileTransacted`, skraćuje datoteku, mapira zamenu veličine DLL-a, kopira PE i izvršava commit; TxF vezuje file handle i naredne handle-based operacije za transaction, ali je to mehanizam zamene nakon race-a, a ne izvor greške u privilege boundary-ju.<sup>[[5]](#references)[[9]](#references)</sup>
6. Na kraju pokrenite postojeći privilegovani scheduled task čiji executable proverava planted adjacent filename. FalconFlank poziva `\\Microsoft\\Windows\\Application Experience\\MareBackup`, čeka da se DLL poveže na `\\??\\pipe\\FALCONFLANK`, a zatim briše planted file. Nemojte pretpostaviti konkretan rezultujući token samo na osnovu naziva task-a — proverite pokrenuti proces, putanju modula, integrity level i token na testiranom build-u.<sup>[[5]](#references)</sup>

Osnovno audit pitanje zato nije „da li service validira originalnu input path?“, već „da li svaka privilegovana mutacija ostaje vezana za iste otvorene file i directory objekte koji su validirani?“. Zadržavanje handle-ova tokom check i use operacija, otvaranje child objekata relativno prema trusted directory handle-u, odbacivanje neočekivanih reparse tag-ova i ponovna validacija identiteta datoteke pre mutacije zatvaraju ovu klasu pathname-substitution bug-a.<sup>[[1]](#references)[[8]](#references)</sup>

### Detection and PoC triage

High-signal detection koreliše namespace tranziciju sa privilegovanim consumer-om: OLE header ispod DLL basename-a u GUID-named temporary tree-u, oplock break, POSIX-style uklanjanje leaf directory-ja, kreiranje mount point-a koji cilja zaštićeni Windows directory i kreiranje ili izmena istog basename-a ispod tog odredišta. Za javni primer dodajte `C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\bcrypt.dll`, ručno izvršavanje `MareBackup` i named pipe `FALCONFLANK` kao uže pivote; nijedan od njih nije dovoljan samostalno.<sup>[[5]](#references)</sup>

Prilikom reprodukcije PoC-a uzmite u obzir tri reliability defekta u objavljenom source-u: poziva `FlushFileBuffers` sa embedded byte-array pointer-om umesto file handle-a, proverava zastareli `HRESULT` nakon `GetFolder`, `GetTask` i `Run`, i koristi neograničene retry/wait loop-ove za brisanje direktorijuma, kreiranje reparse-a, oplock event i pipe connection.<sup>[[5]](#references)</sup>

## Operational considerations

- **Kombinovanje primitive** – Možete koristiti dugo ime *po nivou* u directory chain-u za još veću latenciju, dok ne iscrpite veličinu `UNICODE_STRING`.
- **One-shot bug-ovi** – Prošireni prozor (od desetina mikrosekundi do minuta) čini “single trigger” bug-ove realističnim kada se kombinuju sa CPU affinity pinning-om ili hypervisor-assisted preemption-om.
- **Sporedni efekti** – Usporavanje utiče samo na malicious path, pa ukupne performanse sistema ostaju nepromenjene; defenders će to retko primetiti osim ako nadgledaju rast namespace-a.
- **Cleanup** – Zadržite handle-ove ka svakom direktorijumu/objektu koji kreirate kako biste kasnije mogli da pozovete `NtMakeTemporaryObject`/`NtClose`. Neograničeni directory chain-ovi bi u suprotnom mogli da opstanu nakon reboot-a.
- **File-system race-ovi** – Ako se vulnerable path na kraju razrešava kroz NTFS, možete postaviti Oplock (npr. `SetOpLock.exe` iz istog toolkit-a) nad backing file-om dok OM slowdown traje, zamrzavajući consumer na dodatne milisekunde bez izmene OM graph-a.<sup>[[2]](#references)</sup>

## Defensive notes

- Kernel code koji se oslanja na named objects treba ponovo da validira security-sensitive state *nakon* open operacije ili da uzme reference pre provere (čime se zatvara TOCTOU gap).
- Nametnite gornje granice za OM path depth/length pre dereferenciranja user-controlled name-ova. Odbacivanje predugačkih name-ova vraća napadače u microsecond window.
- Instrumentujte rast Object Manager namespace-a (ETW `Microsoft-Windows-Kernel-Object`) kako biste otkrili sumnjive chains sa hiljadama komponenti ispod `\BaseNamedObjects`.

## References

- [1] [Project Zero – Tehnike Windows Exploitation-a: Pobeđivanje race condition-a pomoću path lookup-a](https://projectzero.google/2025/12/windows-exploitation-techniques.html)
- [2] [googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)
- [3] [MSNightmare/ShieldBreak](https://github.com/MSNightmare/ShieldBreak)
- [4] [ShieldBreak.cpp (commit be016d8)](https://github.com/MSNightmare/ShieldBreak/blob/be016d8c18c8355a12753286c1ce9d5a48a0dab4/ShieldBreak.cpp)
- [5] [FalconFlank.cpp (commit 702b574)](https://github.com/MSNightmare/FalconFlank/blob/702b57477a9f0a99ddabef56e7ebe6c1e99c2435/FalconFlank.cpp)
- [6] [MSNightmare/FalconFlank](https://github.com/MSNightmare/FalconFlank)
- [7] [Microsoft Learn - FSCTL_REQUEST_OPLOCK](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_request_oplock)
- [8] [Microsoft Learn - FSCTL_SET_REPARSE_POINT_EX](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point-ex)
- [9] [Microsoft Learn - Kako koristiti Transactional NTFS](https://learn.microsoft.com/en-us/windows/win32/fileio/how-to-use-transactional-ntfs)
{{#include ../../banners/hacktricks-training.md}}
