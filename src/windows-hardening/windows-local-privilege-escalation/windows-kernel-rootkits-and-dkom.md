# Windows Kernel Rootkits and DKOM

{{#include ../../banners/hacktricks-training.md}}

## Opseg

Implant nakon kompromitovanja može učitati potpisani kernel driver kao servis i izložiti user-mode control plane preko `IRP_MJ_DEVICE_CONTROL`. Potpisivanje drivera samo potvrđuje da Windows prihvata image; ono ne čini IOCTL autorizaciju, memorijske operacije, callback-ove ili hook-ove bezbednim. Jedan analizirani rootkit koristio je tri handler-a tokom normalnog rada, ali je izlagao desetine dodatnih post-exploitation primitives, zbog čega reverse engineering mora obuhvatiti kompletan dispatcher, a ne samo zahteve uočene u malware trace-u.<sup>[[1]](#references)</sup>

## Triage potpisanog drivera i IOCTL-a

Počnite od `DriverEntry`, zabeležite device objects i DOS simboličke linkove, pronađite rutinu `MajorFunction[IRP_MJ_DEVICE_CONTROL]` i mapirajte svako poređenje/unos u tabeli koji vodi do handler-a. Uporedite imena koja user mode otvara sa imenima koja driver zapravo kreira: jedan uočeni lanac otvarao je `\\.\msagent`, dok je njegov driver kreirao `\Device\ToolTool` i `\DosDevices\ToolTool`. Ovo neslaganje može ukazivati na drugi sample/configuration, nedostajuću logiku inicijalizacije ili nedoslednost analize.<sup>[[1]](#references)</sup>

Dekodirajte svaki control code pre rekonstrukcije njegove ulazne strukture.<sup>[[1]](#references)</sup>
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
Ova tri koda se dekodiraju kao `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS` i `METHOD_BUFFERED`. To **ne dokazuje** da neprivilegovan pozivalac može da im pristupi: takođe proverite DACL uređaja, create/open dispatch, provere pozivaoca za svaki zahtev, očekivane dužine bafera, ugrađene pokazivače, rukovanje životnim vekom PID-a i da li handler veruje PID-u ili zastavici koju je dostavio pozivalac.<sup>[[1]](#references)</sup>

Kada implant koristi samo podskup komandi, grupišite preostale handlere prema primitivu umesto da ih odbacite kao mrtav kod. Jedan multifunkcionalni drajver je izložio sve sledeće klase:<sup>[[1]](#references)</sup>

- **Kontrola/konfiguracija:** uključivanje ili isključivanje stanja rootkita; dodavanje, uklanjanje, ispitivanje ili brisanje zaštićenih putanja, procesa i C2 adresa.
- **Manipulacija procesima:** terminiranje PID-a, uklanjanje njegove slike iz memorije, injektovanje pomoću `NtCreateThreadEx`, skrivanje/obnavljanje procesa ili user modula i uklanjanje PPL zaštite.
- **Manipulacija kernelom:** uklanjanje učitanog drajvera iz povezane liste, nabrajanje/onemogućavanje/obnavljanje notification callback-ova, ručno mapiranje drugog drajvera i upisivanje na proizvoljnu kernel adresu.
- **Manipulacija objektima:** brisanje/dešifrovanje datoteka i kreiranje ili menjanje vrednosti registra.

## Izuzeci za pouzdane procese

Korisni obrazac dizajna je IOCTL koji registruje PID zajedno sa zastavicom **trusted**. Ista provera poverenja se zatim koristi u file, registry, process i thread filterima: nepouzdani alati dobijaju filtrirane rezultate nabrajanja, smanjena prava nad handle-ovima ili `STATUS_ACCESS_DENIED`, dok implant i dalje može da ažurira sopstvene skrivene objekte. Tretirajte ovo kao granicu autorizacije i proverite kako se unosi autentifikuju, sinhronizuju i uklanjaju nakon izlaska procesa ili ponovne upotrebe PID-a.<sup>[[1]](#references)</sup>

Rootkit-i mogu da čuvaju policy u `REG_MULTI_SZ` vrednostima i da liste datoteka, direktorijuma, ključeva registra, vrednosti registra, ignorisanih image-a, zaštićenih image-a i skrivenih image-a kompajliraju u AVL stabla. Tokom analize pratite svakog čitača i upisivača ovih deljenih stabala; to povezuje konfiguraciju registra, IOCTL-ove, callback-ove i filtering logiku čak i kada su imena funkcija uklonjena.<sup>[[1]](#references)</sup>

## DKOM skrivanje procesa i modula

### `EPROCESS.ActiveProcessLinks`

Offset-i za `ActiveProcessLinks` razlikuju se između Windows build-ova. Rootkit koji je tolerantan na verzije može da testira poznate kandidate, a zatim skenira `EPROCESS` u potrazi za samodoslednim `LIST_ENTRY` čiji susedi pokazuju nazad na kandidata. On zadržava otkriveni offset, skriva proces ponovnim povezivanjem `Flink`/`Blink` pokazivača njegovih suseda i čuva stanje kako bi kasnije ponovo povezao unos. Proces nastavlja da radi, ali nestaje iz enumeratora koji prolaze kroz listu aktivnih procesa.<sup>[[1]](#references)</sup>

Ovo je **DKOM**, a ne terminacija. Detekcija treba da uporedi rezultate zasnovane na listama sa nezavisnim dokazima, kao što su pool/object skenovi, vlasništvo nad thread-ovima, handle tabele, artefakti scheduler-a i inspekcija kernel memorije. Proces koji je vidljiv pri skeniranju, ali odsutan iz kanonske liste, značajniji je od bilo kog od ta dva prikaza posmatranog zasebno.<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Ekvivalentni primitiv za skrivanje modula pronalazi ciljnu stavku u `PsLoadedModuleList` i menja susedne `Flink`/`Blink` pokazivače. Drajver ostaje mapiran i izvršiv, ali upiti o modulima zasnovani na listi ga izostavljaju. Uporedite loader listu sa izvršivim kernel mapiranjima, pool tag-ovima, device/driver objektima, service ključevima, callback adresama i dispatch pokazivačima koji vode izvan navedenog image-a.<sup>[[1]](#references)</sup>

## Zaštita i prikrivanje zasnovano na callback-ovima

Rootkit može da kombinuje dokumentovane callback framework-e sa DKOM-om i hook-ovima:<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks` pre-operation handler-i za `PsProcessType` i `PsThreadType` uklanjaju prava koja se koriste za terminaciju, VM pristup, dupliranje ili manipulaciju thread-ovima kada nepouzdani pozivalac otvori zaštićeni cilj. Zabeležite callback altitude i razrešite adresu svakog callback-a do modula koji ga poseduje.
- `PsSetCreateProcessNotifyRoutineEx` i `PsSetLoadImageNotifyRoutine` održavaju stanje zaštićenih/ignorisanih/skrivenih procesa dok se procesi i image-i pojavljuju; jednokratno skeniranje procesa može naknadno da popuni objekte koji su postojali pre registracije.
- Filesystem minifilter odbija pristup konfigurisanim putanjama. Neuobičajena implementacija može da kreira svoj `Instances` ključ, dinamički izabere altitude i povećava vrednost/pokušava ponovo kada `FltRegisterFilter` prijavi koliziju.
- `CmRegisterCallbackEx` rutina može da potisne zaštićena imena iz enumeracije i odbije direktno otvaranje, preimenovanje, postavljanje ili brisanje operacija, dok izuzima registrovane pouzdane procese.

Povežite registracije `ObRegisterCallbacks`, registry-callback altitude vrednosti, izlaz komande `fltmc filters`, service `Instances` ključeve i callback adrese. Ako se normalni alati filtriraju, pregledajte ove strukture iz offline memory image-a ili drugog pouzdanog sloja za prikupljanje podataka.<sup>[[1]](#references)</sup>

## Filtriranje Nsiproxy rezultata

Mrežno prikrivanje može ciljati `\Driver\Nsiproxy`: pribavite objekat drajvera pomoću `ObReferenceObjectByName`, sačuvajte pokazivač na handler, zamenite ga wrapper-om i uklonite vraćene IPv4 zapise koji odgovaraju C2 listi kojom upravlja IOCTL, pre nego što ih user mode primi. Aplikacije koje koriste filtrirane NSI podatke možda više neće prikazivati konekciju iako saobraćaj i dalje postoji.<sup>[[1]](#references)</sup>

Uporedite prikaze konekcija hosta sa packet capture-om, WFP/ETW telemetrijom i mrežnim objektima u kernel memoriji. Takođe pregledajte dispatch/handler pokazivače za `Nsiproxy` i potvrdite da se svaki razrešava unutar očekivanog potpisanog modula; pokazivač koji vodi u nenavedeno mapiranje može povezati mrežno filtriranje sa DKOM-om nad `PsLoadedModuleList`.<sup>[[1]](#references)</sup>

## Kontrolna lista za istragu

Najjači signal je neslaganje između slojeva, a ne jedno ime datoteke ili hash. Povežite:<sup>[[1]](#references)</sup>

1. Kreiranje kernel servisa i potpisani drajver čija su starost sertifikata, izdavač ili putanja neusaglašeni sa instaliranim proizvodom.
2. Kreiranje uređaja, DOS linkove i IOCTL saobraćaj, uključujući neusaglašena imena uređaja u user mode-u i kernelu.
3. Zahtev za registraciju PID-a nakon kojeg slede neuspesi drugih procesa da otvore, nabroje, izmene ili obrišu iste objekte.
4. Object/registry/process/image callback-ove, minifilter instance i hook-ove čije adrese ne pripadaju normalno enumeriranom drajveru.
5. Razlike između inventara procesa, modula, callback-ova i mreže zasnovanih na listama i onih zasnovanih na skeniranju.

## References

- [1] [Kaspersky Securelist - HoneyMyte unapređuje CoolClient potpisanim Windows kernel rootkit-om](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
