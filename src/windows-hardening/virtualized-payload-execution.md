# Virtuelizovano izvršavanje payload-a i izbegavanje detekcije prilagođenim VM-om

{{#include ../banners/hacktricks-training.md}}

Virtuelizacija payload-a kompajlira ofanzivnu logiku u skup instrukcija za guest okruženje i izvršava je pomoću native interpreter-a. Za razliku od packer-a, koji na kraju mora da izloži originalne native instrukcije u memoriji, virtuelizovani payload može da zadrži zaštićenu logiku kao bytecode tokom celog svog životnog veka. Time se uklanja taj konkretni prozor za raspakivanje, ali se **ne** skrivaju ponašanja vidljiva host-u, kao što su syscall-ovi, mrežna aktivnost ili granica poziva između VM-a i native koda.<sup>[[2]](#references)[[3]](#references)</sup>

## Model izvršavanja

Kompaktan virtuelizovani loader može da podeli izvršavanje na sledeće slojeve.<sup>[[3]](#references)</sup>

1. Kompajlirajte freestanding C, BOF izvorni kod ili runtime biblioteke pomoću LLVM-a u prilagođeni bytecode ISA.
2. Pokrenite mali native interpreter i inicijalizujte mapiranje opcode-ova specifično za build.
3. Izvršavajte sam PE linker-loader kao bytecode: parsirajte zaglavlja, mapirajte sekcije, primenite relokacije, razrešite importe i popunite IAT.
4. Zadržite pozive guest-to-guest unutar interpreter-a. Pozive ka ciljevima izvan bytecode region-a, kao što su funkcije u uvezenim DLL-ovima, usmerite preko native host-call thunk-a.
5. Premestite prateće funkcionalnosti, kao što su HTTP kadriranje, TLS i delovi C runtime-a, iza iste granice interpretacije.

Ovaj model izbegava dodeljivanje posebnog native code region-a za svaki plugin i sprečava da se originalni payload pojavi kao prepoznatljiv x86-64 tok instrukcija. I dalje je reč o granici za izbegavanje detekcije/obfuskaciju, a ne o bezbednosnoj granici: native interpreter i svaki spoljašnji efekat ostaju vidljivi.<sup>[[2]](#references)[[3]](#references)</sup>

## Host bridge sa deljenom memorijom

Izolovani VM predstavlja pokazivače kao pomeraje unutar guest bafera, pa svaki prelazak preko host API-ja zahteva prevođenje pokazivača i posebno rukovanje izlaznim parametrima. VM sa deljenom memorijom, nasuprot tome, omogućava da guest adrese budu važeće adrese u host procesu. Zato se čitanje i upisivanje mogu obavljati operacijama nalik na `memcpy`, a pokazivač vraćen iz native alokacije preko ECALL-a može direktno da se dereferencira iz bytecode-a. RISC-Y Business je pokazao da ovakav dizajn može da svede bridge na pribavljanje PEB-a i izvršavanje proizvoljnih poziva ka host-u.<sup>[[1]](#references)</sup>

Za Windows x64, virtuelni registar može da preslikava ABI: prva četiri celobrojna argumenta ili argumenta pokazivača smestite u `RCX`, `RDX`, `R8` i `R9`, a naredne argumente i shadow space na stek. Kada se virtuelni `CALL` razreši na adresu izvan bytecode opsega, univerzalni thunk prosleđuje to stanje native pozivu i vraća povratnu vrednost VM-u. To omogućava IAT pozive, alokaciju heap-a i socket operacije bez ispravki pokazivača.<sup>[[2]](#references)[[3]](#references)</sup>

Kompromis je potpuni gubitak izolacije. Oštećenje guest memorije može direktno da utiče na host, native funkcije mogu da zadrže ili izmene guest pokazivače, a interpreter mora da tretira bytecode kao potpuno pouzdan. Povratni pozivi iz native koda u VM takođe zahtevaju obrnuti bridge; VM koji podržava samo odlazne pozive ne može direktno da podrži API-je zasnovane na callback-ovima, kao što je `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Polimorfizam ISA-e za svaki build

Prilagođeni ISA fiksne širine pojednostavljuje dekodiranje, dispatch, relokaciju i mapiranje virtuelnih registara. Centurion koristi format instrukcija od 18 bajtova, inspirisan x86-64, čime se gustina koda menja za predvidljivo parsiranje; to takođe ostavlja mogućnost prevođenja postojećih x86-64 artefakata u bytecode.<sup>[[3]](#references)</sup>

Nasumična promena mapiranja opcode-ova na handlere za svaki build čini da ista guest logika proizvodi različite nizove bajtova. Šifrovanje tabele mapiranja i njeno obnavljanje tek tokom izvršavanja dodatno uklanja stabilan rečnik opcode-ova sa diska. To otežava upotrebu fiksnih potpisa i ponovljivih pravila za disasembliranje, ali ne menja automatski polimorfizam native dispatcher-a, rutine za dešifrovanje tabele ili granice host-call-a.<sup>[[3]](#references)</sup>

## Uvođenje izvršnog okruženja u VM

Host proces može da se svede na primitive za memoriju, syscall i socket operacije, dok freestanding biblioteke obezbeđuju usluge višeg nivoa unutar VM-a. Na primer, FreeRTOS coreHTTP može da obrađuje HTTP kadriranje, a mbedTLS može da implementira TLS bez pozivanja WinHTTP-a ili TLS API-ja operativnog sistema. Raw socket-i preko `afd.sys` ili sličnog interfejsa tada postaju uska native granica za mrežno povezivanje.<sup>[[3]](#references)</sup>

Ovaj dizajn **Bring Your Own Execution Environment (BYOEE)** može da smesti PE učitavanje, runtime podršku i filesystem u memoriji iza interpreter-a. Smanjuje broj prepoznatljivih native implementacija, ali ne uklanja telemetriju: raw socket operacije ostaju vidljive, a okruženja koja zahtevaju eksplicitne proxy-je ili TLS presretanje mogu onemogućiti funkcionisanje mrežnog dizajna.<sup>[[3]](#references)</sup>

## Selektivno native ubrzanje

Interpretacija svake instrukcije naročito je skupa kod kriptografije sa javnim ključem. Praktična podela koristi mbedTLS `MBEDTLS_ALT` hook-ove kao interfejs softverskog koprocesora: zadržite TLS stanje, parsiranje sertifikata, pregovaranje, alokaciju i bignum kod višeg nivoa u bytecode-u, a vruća aritmetička jezgra iz `bignum_core.c` pozivajte preko native ECALL-ova. U Centurion prototipu, `bignum.c`, `bignum_mod.c` i `bignum_mod_raw.c` ostali su virtuelizovani, dok su se unutrašnje petlje izvršavale native, čime je ECDHE rukovanje skraćeno sa minuta na sekunde.<sup>[[3]](#references)</sup>

Ubrzivače učinite opcionim, tako da payload-i kojima TLS nije potreban izostave dodatne native ulazne tačke. Ovaj obrazac može da se primeni i na druga opterećenja interpreter-a: prvo profilirajte, a zatim izložite najmanju moguću native primitivu umesto da ceo podsistem premestite izvan VM-a.<sup>[[3]](#references)</sup>

Centurion je proverio ceo lanac pomoću TLS 1.2 bind shell-a: bytecode loader je mapirao PE, socket pozivi su prolazili kroz univerzalni thunk, mbedTLS je obrađivao protokol unutar VM-a, a native ECALL-ovi su ubrzavali ECDHE aritmetiku. Tako je native interpreter od približno 18 KB podržao šifrovani komandni kanal, a da payload nije materijalizovan kao native x86-64 kod.<sup>[[3]](#references)</sup>

## Polazišta za reverse engineering i detekciju

Sledeće su praktična polazišta za analizu izvedena iz arhitekture; virtuelizacija menja gde analitičari posmatraju ponašanje, ali ga ne uklanja.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Pronađite fetch/decode/dispatch petlju, virtuelni programski brojač, registar i ponavljano pomeranje kroz instrukcije fiksne širine.
- Izbacite tabelu opcode-ova nakon runtime dešifrovanja i mapirajte adrese handler-a na semantičke operacije umesto da tražite šifrovani bytecode na disku.
- Postavite breakpoint na univerzalni thunk ili ECALL dispatcher da biste zabeležili native cilj, virtuelne argumente u registrima, argumente na steku i povratnu vrednost.
- Pratite pristup PEB-u, razrešavanje export-a, parsiranje PE zaglavlja, upisivanje relokacija i popunjavanje IAT-a, čak i kada je sam loader implementiran kao bytecode.
- Povežite kreiranje socket-a i `afd.sys` saobraćaj sa odsustvom očekivanih WinHTTP ili native TLS poziva; nedostatak uvezenih funkcija višeg nivoa jeste nagoveštaj, ali ne i dokaz benignog ponašanja.
- Tretirajte native aritmetičke ubrzivače kao semantička uska grla: njihovi pozivaoci mogu da otkriju razmenu ključeva i aktivnost provere sertifikata dok je okolna TLS mašina stanja i dalje virtuelizovana.

Za tokove rada u analizi koji polaze od dispatcher-a, a ne od originalnog grafa toka kontrole, pogledajte [uputstvo za analizu malware-a i virtuelizovane packer-e](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Operativna ograničenja

Virtuelizacija uvodi troškove interpretacije, povećava složenost toolchain-a i ABI-ja i ne rešava detekciju ponašanja. Deljena memorija je po dizajnu nebezbedna, raw socket umrežavanje može da zakaže iza obaveznih proxy-ja, a Win32 API-ji koji intenzivno koriste callback-ove zahtevaju native-to-VM trampoline. Interpreter, syscall bridge i svi native ubrzivači takođe ostaju uobičajeni native otisak koji branioci mogu da potpisuju ili instrumentiraju.<sup>[[2]](#references)[[3]](#references)</sup>

## Povezane stranice

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Izrada RISC-V virtuelne mašine za obfuskaciju payload-a](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red teaming u eri EDR-a — izbegavanje detekcije kroz virtuelizaciju malware-a](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion — obezbedite sopstveno izvršno okruženje](https://praetorian.com/blog/virtualized-loader-centurion/)
{{#include ../banners/hacktricks-training.md}}
