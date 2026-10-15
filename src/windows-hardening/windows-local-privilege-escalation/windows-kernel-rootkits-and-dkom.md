# Windows kernel rootkit-i i DKOM

{{#include ../../banners/hacktricks-training.md}}

## Opseg

Implant nakon kompromitovanja može da učita potpisani drajver jezgra kao servis i izloži kontrolni sloj u user-mode-u preko `IRP_MJ_DEVICE_CONTROL`. Potpisivanje drajvera samo potvrđuje da Windows prihvata binarni fajl; ne čini bezbednim autorizaciju IOCTL-a, operacije nad memorijom, callback-ove ni hook-ove. Jedan analizirani rootkit koristio je tri handler-a tokom uobičajenog rada, ali je izlagao na desetine dodatnih primitiva za post-exploitation, pa reverse engineering mora da obuhvati ceo dispatcher, a ne samo zahteve zabeležene u tragu malware-a.<sup>[[1]](#references)</sup>

## Triage potpisanog drajvera i IOCTL-a

Počnite od `DriverEntry`, zabeležite objekte uređaja i DOS simboličke linkove, pronađite rutinu `MajorFunction[IRP_MJ_DEVICE_CONTROL]` i mapirajte svako poređenje/stavku tabele koja vodi do handler-a. Uporedite nazive koje otvara user-mode kod sa nazivima koje drajver zaista kreira: jedan zabeleženi lanac otvorio je `\\.\msagent`, dok je njegov drajver kreirao `\Device\ToolTool` i `\DosDevices\ToolTool`. Ovo neslaganje može da ukaže na drugi uzorak/konfiguraciju, nedostajuću logiku za podešavanje ili nedoslednost u analizi.<sup>[[1]](#references)</sup>

Dekodirajte svaki kontrolni kod pre nego što rekonstrušete njegovu ulaznu strukturu.<sup>[[1]](#references)</sup>

```python
def decode_ioctl(code):
    return {
        "device_type": code >> 16,
        "access": (code >> 14) & 3,
        "function": (code >> 2) & 0xfff,
        "method": code & 3,
    }

for code in (0x2220F0, 0x222120, 0x2221E0):
    print(hex(code), decode_ioctl(code))
```

Ova tri koda dekodiraju se kao `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` i `METHOD_BUFFERED`. To **ne** dokazuje da im neprivilegovani pozivalac može pristupiti: proverite i DACL uređaja, rutine za kreiranje/otvaranje, provere pozivaoca po zahtevu, očekivane dužine bafera, ugrađene pokazivače, rukovanje životnim ciklusom PID-a i to da li handler veruje PID-u ili zastavici koju dostavlja pozivalac.<sup>[[1]](#references)</sup>

Kada implant koristi samo podskup komandi, preostale handlere grupišite prema primitivu, umesto da ih odbacite kao neaktivan kod. Jedan višenamenski driver izložio je sve sledeće klase:<sup>[[1]](#references)</sup>

- **Kontrola/konfiguracija:** uključivanje ili isključivanje stanja rootkit-a; dodavanje, uklanjanje, upit o zaštićenim putanjama, procesima i C2 adresama ili njihovo brisanje.
- **Manipulacija procesima:** terminiranje PID-a, odmapiranje njegove slike, ubacivanje pomoću `NtCreateThreadEx`, skrivanje/vraćanje procesa ili korisničkih modula i uklanjanje PPL zaštite.
- **Manipulacija kernel-om:** uklanjanje učitanog driver-а iz liste, nabrajanje/onemogućavanje/obnavljanje callback-ova za obaveštenja, ručno mapiranje drugog driver-а i upis na proizvoljnu kernel adresu.
- **Manipulacija objektima:** brisanje/desifrovanje datoteka i kreiranje ili menjanje vrednosti registra.

## Ručno mapiranje kernel-a kroz ranjivi potpisani driver

Potpisani driver sa operacijama čitanja/upisa kernel memorije može poslužiti kao loader za nepotpisanu sliku driver-а, ohne da traži od Windows-a da učita tu sliku kao običan driver.<sup>[[2]](#references)[[7]](#references)</sup> Primer LocalStranger otvara postojeći uređaj `\\.\WinNotify`; njegov izvorni kod ne pokazuje da neprivilegovani korisnik može instalirati, pokrenuti ili otvoriti driver na proizvoljnom host-u.<sup>[[2]](#references)[[3]](#references)</sup> Mapper prima putanju do slike, pribavlja baznu adresu učitanog kernel-a i koristi IOCTL-ove uređaja za čitanje/upis virtuelne memorije.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup>

Da bi taj pristup čitanju/upisu pretvorio u poziv kernel funkcije, mapper čita immediate vrednost PTE baze iz `MmGetVirtualForPhysical` i prolazi kroz unose za straničenje koji pokrivaju `NtAddAtom`.<sup>[[5]](#references)[[7]](#references)</sup> Njegov proračun PTE-a je `PteBase + ((VA >> 9) & 0x7FFFFFFFF8)`; kod proverava i da li postoji veliki PDE.<sup>[[5]](#references)[[7]](#references)</sup> Privremeno omogućava upis u pokrivajući unos, zamenjuje syscall unos skokom do željene kernel funkcije, poziva korisnički stub `NtAddAtom`, a zatim vraća i izvorne bajtove i unos stranice.<sup>[[6]](#references)</sup>

Mapper koristi taj put poziva za `ExAllocatePool`, mapira PE sekcije, importe i relokacije u sliku, upisuje je u alokaciju i poziva njenu ulaznu tačku.<sup>[[7]](#references)[[8]](#references)</sup> Ova implementacija prihvata samo x64 PE slike sa relokacijama; čitanje PTE baze takođe pretpostavlja fiksni raspored `MmGetVirtualForPhysical + 34`.<sup>[[5]](#references)[[8]](#references)</sup> Smatrajte je zavisnom od verzije build-а, a ne nezavisnim zaobilaženjem KASLR-а ili dokazom da HVCI ili PatchGuard dozvoljavaju mapiranje.<sup>[[5]](#references)[[8]](#references)</sup> Za upotrebu kernel R/W samo nad podacima pogledajte [krađu SYSTEM token-а](arbitrary-kernel-rw-token-theft.md).

## Izuzeci za pouzdane procese

Korisna projektna šema je IOCTL koji registruje PID zajedno sa zastavicom **trusted**. Ista provera poverenja zatim se primenjuje u filterima za datoteke, registar, procese i niti: nepouzdani alati dobijaju filtrirane rezultate nabrajanja, smanjena prava na handle-ove ili `STATUS_ACCESS_DENIED`, dok implant i dalje može da ažurira sopstvene skrivene objekte. Tretirajte ovo kao granicu autorizacije i proverite kako se unosi autentifikuju i sinhronizuju, kao i kako se uklanjaju nakon izlaska procesa ili ponovne upotrebe PID-a.<sup>[[1]](#references)</sup>

Rootkit-i mogu da čuvaju pravila u vrednostima `REG_MULTI_SZ` i da liste datoteka, direktorijuma, registarskih ključeva, registarskih vrednosti, ignorisanih slika, zaštićenih slika i skrivenih slika učitavaju u AVL stabla. Tokom analize pratite svakog čitaoca i upisivača u ta zajednička stabla; ona povezuju konfiguraciju registra, IOCTL-ove, callback-ove i logiku filtriranja čak i kada su nazivi funkcija uklonjeni.<sup>[[1]](#references)</sup>

## Skrivanje procesa i modula pomoću DKOM-а

### `EPROCESS.ActiveProcessLinks`

Pomaci `ActiveProcessLinks` razlikuju se među Windows build-ovima. Rootkit otporan na različite verzije može proveriti poznate kandidate, a zatim pretražiti `EPROCESS` u potrazi za samodoslednim `LIST_ENTRY` čiji susedi pokazuju nazad na kandidata. Čuva pronađeni pomak, skriva proces ponovnim povezivanjem `Flink`/`Blink` pokazivača njegovih suseda i zadržava stanje kako bi kasnije ponovo povezao unos. Proces nastavlja da radi, ali nestaje iz enumeratora koji prolaze kroz listu aktivnih procesa.<sup>[[1]](#references)</sup>

Ovo je **DKOM**, a ne terminiranje. Detekcija treba da uporedi rezultate zasnovane na listi sa nezavisnim dokazima kao što su pool/object skeniranja, vlasništvo nad nitima, tabele handle-ova, artefakti scheduler-а i pregled kernel memorije. Proces koji je vidljiv pri skeniranju, ali ga nema u kanonskoj listi, značajniji je od bilo kog pojedinačnog prikaza.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Ekvivalentni primitiv za skrivanje modula pronalazi ciljni unos u `PsLoadedModuleList` i menja susedne `Flink`/`Blink` pokazivače. Driver ostaje mapiran i izvršiv, ali upiti za module zasnovani na listi ga izostavljaju. Uporedite listu loader-а sa izvršivim kernel mapiranjima, pool tag-ovima, device/driver objektima, service ključevima, callback adresama i dispatch pokazivačima koji upućuju izvan navedenih slika.<sup>[[1]](#references)</sup>

## Zaštita i prikrivanje pomoću callback-ова

Rootkit može da kombinuje dokumentovane callback okvire sa DKOM-om i hook-ovima:<sup>[[1]](#references)</sup>

- Pre-operation handler-и `ObRegisterCallbacks` za `PsProcessType` i `PsThreadType` uklanjaju prava koja se koriste za terminiranje, VM pristup, dupliranje ili manipulaciju nitima kada nepouzdani pozivalac otvori zaštićeni cilj. Zabeležite callback altitude i utvrdite modul kojem pripada svaka callback adresa.
- `PsSetCreateProcessNotifyRoutineEx` и `PsSetLoadImageNotifyRoutine` održavaju stanje zaštićenih/ignorisanih/skrivenih procesa dok se procesi i slike pojavljuju; jednokratni prolaz kroz procese može dopuniti objekte koji su postojali pre registracije.
- Minifilter sistema datoteka uskraćuje pristup konfigurisanim putanjama. Neuobičajena implementacija može kreirati svoj `Instances` ključ, dinamički izabrati altitude i povećavati ga uz ponovni pokušaj kada `FltRegisterFilter` prijavi koliziju.
- Rutina `CmRegisterCallbackEx` može potisnuti zaštićena imena iz enumeracije i odbiti direktno otvaranje, preimenovanje, postavljanje ili brisanje, uz izuzeće registrovanih pouzdanih procesa.

Povežite registracije `ObRegisterCallbacks`, altitude callback-а registra, izlaz `fltmc filters`, service `Instances` ključeve i callback adrese. Ako se rezultati normalnih alata filtriraju, pregledajte ove strukture iz offline memory image-а ili drugog pouzdanog sloja za prikupljanje podataka.<sup>[[1]](#references)</sup>

## Filtriranje rezultata Nsiproxy-ja

Mrežno prikrivanje može ciljati `\Driver\Nsiproxy`: pribaviti driver objekat pomoću `ObReferenceObjectByName`, sačuvati pokazivač handler-а, zameniti ga wrapper-ом i ukloniti vraćene IPv4 zapise koji se podudaraju sa C2 listom kojom upravljaju IOCTL-ovi pre nego što podaci stignu do user mode-а. Aplikacije koje koriste filtrirane NSI podatke možda više neće prikazivati vezu, iako saobraćaj i dalje postoji.<sup>[[1]](#references)</sup>

Uporedite prikaze veza na host-u sa packet capture-ом, WFP/ETW telemetrijom i mrežnim objektima iz kernel memorije. Takođe pregledajte dispatch/handler pokazivače `Nsiproxy` и potvrdite da svaki pokazuje unutar očekivanog potpisanog modula; pokazivač ka nemapiranju koje nije na listi može povezati mrežno filtriranje sa DKOM-om `PsLoadedModuleList`.<sup>[[1]](#references)</sup>

## Kontrolna lista za istragu

Najjači signal je neslaganje između slojeva, a ne jedno ime datoteke ili hash. Povežite:<sup>[[1]](#references)</sup>

1. Kreiranje kernel service-а i potpisani driver čija starost sertifikata, izdavač ili putanja nisu u skladu sa instaliranim proizvodom.
2. Kreiranje uređaja, DOS veze i IOCTL saobraćaj, uključujući nepodudaranje naziva uređaja u user mode-u i kernel-u.
3. Zahtev za registraciju PID-a nakon kojeg drugi procesi ne uspevaju da otvore, nabroje, izmene ili obrišu iste objekte.
4. Callback-ovi za objekte/registar/procese/slike, minifilter instance i hook-ovi čije adrese ne pripadaju normalno nabrojanom driver-у.
5. Razlike između inventara procesa, modula, callback-ова i mreže zasnovanih na listama i onih zasnovanih na skeniranju.

## References

- [1] [Kaspersky Securelist - HoneyMyte unapređuje CoolClient pomoću potpisanog Windows kernel rootkit-а](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [2] [LocalStranger README datoteka](https://github.com/nbs32k/LocalStranger/blob/master/README.md)
- [3] [Inicijalizacija LocalStranger driver-а](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/init.c)
- [4] [Komandna linija LocalStranger mapper-а](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/main.cpp)
- [5] [Razrešavanje kernel export-а i PTE baze u LocalStranger-у](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/utils.cpp)
- [6] [Trampoline za pozive kernel-а u LocalStranger-у](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.h)
- [7] [Alokacija i pozivanje ulazne tačke u LocalStranger mapper-у](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.cpp)
- [8] [PE mapiranje u LocalStranger-у](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/pe.cpp)
- [9] [Kontekst kernel-а i syscall-a u LocalStranger-у](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/context.cpp)
- [10] [Wrapper-i za IOCTL virtuelne memorije u LocalStranger-у](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/virtual.c)
{{#include ../../banners/hacktricks-training.md}}
