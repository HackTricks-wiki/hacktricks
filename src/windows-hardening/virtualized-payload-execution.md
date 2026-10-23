# Virtuelizovano izvršavanje payload-a i izbegavanje prilagođenog VM-a

{{#include ../banners/hacktricks-training.md}}

Virtuelizacija payload-a kompajlira ofanzivnu logiku u skup instrukcija za guest i izvršava je pomoću native interpreter-a. Za razliku od packer-a, koji na kraju mora da izloži originalne native instrukcije u memoriji, virtuelizovani payload može da zadrži zaštićenu logiku u obliku bytecode-a tokom čitavog svog životnog veka. Time se uklanja taj konkretan prozor za raspakivanje, ali se **ne** skrivaju ponašanja vidljiva host-u, kao što su syscall-ovi, mrežna aktivnost ili granica između VM-a i native poziva.<sup>[[2]](#references)[[3]](#references)</sup>

## Ponovno hostovanje WebAssembly-ja radi izbegavanja statičke analize

Umesto menjanja Go alata sa brojnim signature-ama, može se kompajlirati kao `wasip1` guest i ugraditi u zaseban native loader. Guest se gradi pomoću zakrpljenog GOROOT-a, u kom nepodržane operacije kao što su `net.Dial`, `net.Listen`, `os/exec` i `os.Pipe` delegiraju preko `//go:wasmimport`; Wazero host modul zatim implementira socket-e, operacije nad procesima, Win32 pozive i macOS framework pozive. Time se zadržava upotreba Go API-ja u originalnom projektu, dok se većina njegove logike premešta u šifrovani WASM modul koji statički PE alati možda neće razumeti.<sup>[[4]](#references)</sup>

### Povezivanje linearne memorije sa native API-jima

Guest pointer je 32-bitni pomeraj u WASM linearnoj memoriji, a ne host virtuelna adresa. Pre native poziva, bridge može da prevede argument samo ako je označen kao lokalni pointer i nalazi se u opsegu `0x10000 <= value < wasmMemorySize`, čime se dobija `wasmMemoryBase + value`. Donja granica sprečava prepravljanje malih handle-ova, flag-ova i `nil` vrednosti; maske za pojedinačne API-je generisane iz `win32metadata` razlikuju stvarne pointer-e od handle-ova, veličina i adresa udaljenih procesa, uz izuzetke za netačne ili nejasne metapodatke.<sup>[[4]](#references)</sup>

Native API-ji mogu i da vrate host pointer-e kroz guest izlazne bafer-e. Tabela mirror objekata može takvim objektima da dodeli guest memorijske reprezentacije i da sačuva obrnuto mapiranje na originalnu host adresu. COM zahteva preslikavanje i interfejsa i njegove vtable: pokazivači na podatke mogu da se prate i preslikaju, dok izvršni pointer-i u regionima `MEM_IMAGE` moraju da ostanu neprozirni token-i, jer WASM ne može da izvršava native instrukcije. Ovaj model ne podržava direktno host-to-guest callback API-je kao što su `EnumWindows` ili `SetWindowsHookEx`.<sup>[[4]](#references)</sup>

### Polimorfizam WASM VM-a pri svakoj izgradnji

Runtime i payload mogu zajedno da se transformišu pri svakoj izgradnji: izmešati opcode-to-handler tabelu, prepisati svaki guest opcode prema novom mapiranju, nasumično menjati identifikatore sekcija, zameniti standardni `\0asm` magic oznakom specifičnom za izgradnju i promeniti magic vrednost runtime keša. Isti izvorni kod tada daje module različite na nivou bajtova, a obični WASM alati ne mogu da parsiraju payload dok analitičar ne otkrije prilagođeno mapiranje i uokviravanje iz host loader-a.<sup>[[4]](#references)</sup>

Pri reverse engineering-u, počnite od native host-a umesto da tražite samo `\0asm`: utvrdite kompajliranu oznaku, putanju dešifrovanja modula, opcode dispatch tabelu i `env` host-function registracije, pa zatim rekonstrušite standardni modul ili instrumentirajte import granicu. Bridge ostaje korisna tačka za praćenje ponašanja, jer pozivi za umrežavanje, kreiranje procesa, pristup registru, dinamičko učitavanje i generički Win32 dispatch prolaze kroz njega čak i kada se ugrađeni bytecode menja između izgradnji.<sup>[[4]](#references)</sup>

### Kamufliranje spoljnog Go executable-a

Sama promena guest-a i dalje ostavlja prepoznatljiv loader. Prikazane transformacije spoljnog binary-ja umeću guste profile simbola preuzete iz legitimnih Go projekata u `gopclntab`, rotiraju mali skup verovatnih DLL import-a i menjaju PE `VERSIONINFO` i Authenticode identifikacione stringove. Ove transformacije ciljaju statičke i machine-learning karakteristike kontejnera; ne uklanjaju runtime ponašanje koje otkrivaju host shim-ovi.<sup>[[4]](#references)</sup>

## Model izvršavanja

Kompaktan virtuelizovani loader može da podeli izvršavanje na sledeće slojeve.<sup>[[3]](#references)</sup>

1. Kompajlirati freestanding C, BOF izvorni kod ili runtime biblioteke pomoću LLVM-a u prilagođeni bytecode ISA.
2. Pokrenuti mali native interpreter i inicijalizovati mapiranje opcode-a specifično za izgradnju.
3. Izvršiti sam PE linker-loader kao bytecode: parsirati headere, mapirati sekcije, primeniti relokacije, razrešiti import-e i popuniti IAT.
4. Zadržati guest-to-guest pozive unutar interpreter-a. Ciljeve izvan bytecode region-a, kao što su import-ovane DLL funkcije, usmeriti kroz native host-call thunk.
5. Premestiti pomoćne funkcije kao što su HTTP uokviravanje, TLS i delovi C runtime-a iza iste granice interpretacije.

Ovaj model izbegava alokaciju zasebnog native code region-a za svaki plugin i sprečava da se originalni payload pojavi kao prepoznatljiv tok x86-64 instrukcija. I dalje je reč o granici za izbegavanje detekcije/ofuskaciju, a ne o bezbednosnoj granici: native interpreter i svaki spoljašnji efekat ostaju vidljivi.<sup>[[2]](#references)[[3]](#references)</sup>

## Host bridge sa deljenom memorijom

Izolovani VM predstavlja pointer-e kao pomeraje u guest baferu, pa svaki prelazak preko host API-ja zahteva prevođenje pointer-a i posebno rukovanje izlaznim parametrima. VM sa deljenom memorijom umesto toga koristi guest adrese koje su validne host-process adrese. Zato čitanja i upisi mogu da koriste operacije nalik na `memcpy`, a pointer koji vrati native alokacioni ECALL može bytecode direktno da dereferencira. RISC-Y Business je pokazao da ovaj dizajn može da svede bridge na pribavljanje PEB-a i izvršavanje proizvoljnih host poziva.<sup>[[1]](#references)</sup>

Za Windows x64, virtuelni register fajl može da oponaša ABI: prva četiri celobrojna argumenta ili pointer-a smeštaju se u `RCX`, `RDX`, `R8` i `R9`, a naredni argumenti i shadow space na stek. Kada se virtuelni `CALL` razreši izvan bytecode opsega, univerzalni thunk prenosi to stanje u native poziv i kopira povratnu vrednost nazad u VM. To omogućava IAT pozive, heap alokaciju i socket operacije bez ispravki pointer-a.<sup>[[2]](#references)[[3]](#references)</sup>

Kompromis je potpuni gubitak izolacije. Oštećenje guest memorije može direktno da utiče na host, native funkcije mogu da zadrže ili menjaju guest pointer-e, a interpreter mora da tretira bytecode kao potpuno pouzdan. Native-to-VM callback-ovi takođe zahtevaju obrnuti bridge; VM koji podržava samo izlazne pozive ne može direktno da podrži API-je zasnovane na callback-ovima, kao što je `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Polimorfizam ISA pri svakoj izgradnji

Prilagođeni ISA fiksne širine pojednostavljuje dekodiranje, dispatch, relokaciju i mapiranje virtuelnih registara. Centurion koristi format instrukcija od 18 bajtova, inspirisan x86-64, čime se gustina koda menja za predvidljivo parsiranje, a ostavlja se i mogući put za prevođenje postojećih x86-64 artefakata u bytecode.<sup>[[3]](#references)</sup>

Nasumična promena mapiranja opcode-to-handler pri svakoj izgradnji čini da identična guest logika daje različite nizove bajtova. Šifrovanje tabele mapiranja i njeno pribavljanje tek tokom runtime-a dodatno uklanja stabilan opcode rečnik sa diska. To otežava korišćenje fiksnih signature-a i ponovo upotrebljivih pravila za disasembliranje, ali samo po sebi ne menja native dispatcher, rutinu za dešifrovanje tabele ni host-call granicu.<sup>[[3]](#references)</sup>

## Premeštanje okruženja za izvršavanje unutar VM-a

Host process može da se svede na memoriju, syscall i socket primitive, dok freestanding biblioteke pružaju usluge višeg nivoa unutar VM-a. Na primer, FreeRTOS coreHTTP može da obavlja HTTP uokviravanje, a mbedTLS TLS, bez pozivanja WinHTTP-a ili TLS API-ja operativnog sistema. Raw socket-i preko `afd.sys` ili sličnog interfejsa tada postaju uska native granica za umrežavanje.<sup>[[3]](#references)</sup>

Ovaj dizajn **Bring Your Own Execution Environment (BYOEE)** može da smesti i PE učitavanje, runtime podršku i in-memory fajl sistem iza interpreter-a. Smanjuje broj prepoznatljivih native implementacija umesto da eliminiše telemetriju: raw socket operacije ostaju vidljive, a okruženja koja zahtevaju eksplicitne proxy-je ili TLS presretanje mogu sprečiti funkcionisanje ovog dizajna za umrežavanje.<sup>[[3]](#references)</sup>

## Selektivno native ubrzavanje

Interpretacija svake instrukcije posebno je skupa kod kriptografije sa javnim ključem. Praktična podela koristi mbedTLS `MBEDTLS_ALT` hook-ove kao interfejs softverskog koprocesora: zadržati TLS stanje, parsiranje sertifikata, pregovaranje, alokaciju i bignum kod višeg nivoa u bytecode-u, ali hot aritmetička jezgra iz `bignum_core.c` pozivati preko native ECALL-ova. U Centurion prototipu, `bignum.c`, `bignum_mod.c` i `bignum_mod_raw.c` ostali su virtuelizovani, dok su se unutrašnje petlje izvršavale native, čime je ECDHE rukovanje skraćeno sa nekoliko minuta na nekoliko sekundi.<sup>[[3]](#references)</sup>

Ubrzivače učinite opcionim kako bi ih payload-i kojima TLS nije potreban izostavili, zajedno sa dodatnim native ulaznim tačkama. Ovaj obrazac se može primeniti na svako opterećenje interpreter-a: prvo profilisati, a zatim izložiti najmanju moguću native primitivu umesto premeštanja celog podsistema izvan VM-a.<sup>[[3]](#references)</sup>

Centurion je potvrdio ceo lanac pomoću TLS 1.2 bind shell-a: bytecode loader je mapirao PE, socket pozivi su prolazili kroz univerzalni thunk, mbedTLS je obrađivao protokol unutar VM-a, a native ECALL-ovi su ubrzavali ECDHE aritmetiku. Native interpreter od približno 18 KB tako je podržavao šifrovani komandni kanal bez materijalizovanja payload-a kao native x86-64 koda.<sup>[[3]](#references)</sup>

## Tačke oslonca za reverse engineering i detekciju

Slede praktične tačke oslonca za analizu izvedene iz arhitekture; virtuelizacija menja mesta na kojima analitičari posmatraju ponašanje, ali ga ne uklanja.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Identifikujte fetch/decode/dispatch petlju, virtuelni programski brojač, register fajl i ponavljano pomeranje kroz instrukcije fiksne širine.
- Ispraznite opcode tabelu nakon runtime dešifrovanja i mapirajte adrese handler-a nazad na semantičke operacije umesto da tražite šifrovani bytecode na disku.
- Postavite breakpoint na univerzalni thunk ili ECALL dispatcher da biste zabeležili native cilj, virtuelne argument registre, argumente na steku i povratnu vrednost.
- Pratite pristup PEB-u, razrešavanje export-a, parsiranje PE header-a, upise relokacija i popunjavanje IAT-a čak i kada je sama implementacija loader-a bytecode.
- Povežite kreiranje socket-a i `afd.sys` saobraćaj sa odsustvom očekivanih WinHTTP ili native TLS poziva; nedostatak import-a višeg nivoa jeste nagoveštaj, ali ne i dokaz benignog ponašanja.
- Tretirajte native aritmetičke ubrzivače kao semantička uska grla: pozivaoci mogu da otkriju razmenu ključeva i aktivnost validacije sertifikata dok okolna TLS mašina stanja ostaje virtuelizovana.

Za analitičke radne tokove koji počinju od dispatcher-a, a ne od originalnog grafa kontrolnog toka, pogledajte [uputstvo za analizu malware-a i virtuelizaciju packer-a](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Operativna ograničenja

Virtuelizacija uvodi troškove interpretacije, povećava složenost toolchain-a i ABI-ja i ne rešava detekciju zasnovanu na ponašanju. Deljena memorija je po dizajnu nebezbedna, umrežavanje preko raw socket-a može da zakaže iza obaveznih proxy-ja, a Win32 API-ji koji intenzivno koriste callback-ove zahtevaju native-to-VM trampoline. Interpreter, syscall bridge i svi native ubrzivači takođe ostaju uobičajen native footprint koji odbrambeni sistemi mogu da potpisuju ili instrumentiraju.<sup>[[2]](#references)[[3]](#references)</sup>

## Povezane stranice

Za analizu VMProtect 3.x pakovanja pogledajte [emulisano raspakivanje i popravku import-a](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#vmprotect-3x-emulated-unpacking-and-import-repair).

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Izrada RISC-V virtuelne mašine za ofuskaciju payload-a](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red teaming u eri EDR-a — izbegavanje detekcije kroz virtuelizaciju malware-a](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — obezbedite sopstveno okruženje za izvršavanje](https://praetorian.com/blog/virtualized-loader-centurion/)
- [4] [Praetorian - Ulazak u WasmForge: kompajliranje Sliver-a u WebAssembly](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
