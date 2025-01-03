# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

U početku, **`task_threads()`** funkcija se poziva na task portu da bi se dobila lista niti iz udaljenog taska. Niti se bira za preuzimanje. Ovaj pristup se razlikuje od konvencionalnih metoda injekcije koda jer je kreiranje nove udaljene niti zabranjeno zbog nove mitigacije koja blokira `thread_create_running()`.

Da bi se kontrolisala nit, poziva se **`thread_suspend()`**, zaustavljajući njeno izvršavanje.

Jedine operacije dozvoljene na udaljenoj niti uključuju **zaustavljanje** i **pokretanje** nje, **dobijanje** i **modifikovanje** njenih registarskih vrednosti. Udaljeni pozivi funkcija se iniciraju postavljanjem registara `x0` do `x7` na **argumente**, konfigurišući **`pc`** da cilja željenu funkciju, i aktivirajući nit. Osiguranje da nit ne sruši nakon povratka zahteva detekciju povratka.

Jedna strategija uključuje **registraciju handler-a za izuzetke** za udaljenu nit koristeći `thread_set_exception_ports()`, postavljajući `lr` registar na nevažeću adresu pre poziva funkcije. Ovo pokreće izuzetak nakon izvršenja funkcije, šaljući poruku na port izuzetaka, omogućavajući inspekciju stanja niti da se povrati povratna vrednost. Alternativno, kao što je preuzeto iz Ian Beer-ovog triple_fetch exploit-a, `lr` se postavlja da se beskonačno ponavlja. Registri niti se zatim kontinuirano prate dok **`pc` ne ukazuje na tu instrukciju**.

## 2. Mach ports for communication

Sledeća faza uključuje uspostavljanje Mach portova za olakšavanje komunikacije sa udaljenom niti. Ovi portovi su ključni za prenos proizvoljnih prava slanja i primanja između taskova.

Za dvosmernu komunikaciju, kreiraju se dva Mach prava primanja: jedno u lokalnom i drugo u udaljenom tasku. Nakon toga, pravo slanja za svaki port se prenosi u odgovarajući task, omogućavajući razmenu poruka.

Fokusirajući se na lokalni port, pravo primanja drži lokalni task. Port se kreira sa `mach_port_allocate()`. Izazov leži u prenosu prava slanja na ovaj port u udaljeni task.

Strategija uključuje korišćenje `thread_set_special_port()` da se postavi pravo slanja na lokalni port u `THREAD_KERNEL_PORT` udaljene niti. Zatim, udaljenoj niti se naređuje da pozove `mach_thread_self()` da bi dobila pravo slanja.

Za udaljeni port, proces se suštinski obrće. Udaljena nit se usmerava da generiše Mach port putem `mach_reply_port()` (jer `mach_port_allocate()` nije prikladan zbog svog mehanizma vraćanja). Nakon kreiranja porta, `mach_port_insert_right()` se poziva u udaljenoj niti da uspostavi pravo slanja. Ovo pravo se zatim čuva u kernelu koristeći `thread_set_special_port()`. Ponovo u lokalnom tasku, `thread_get_special_port()` se koristi na udaljenoj niti da bi se steklo pravo slanja na novokreirani Mach port u udaljenom tasku.

Završetak ovih koraka rezultira uspostavljanjem Mach portova, postavljajući temelje za dvosmernu komunikaciju.

## 3. Basic Memory Read/Write Primitives

U ovom odeljku, fokus je na korišćenju izvršnog primitiva za uspostavljanje osnovnih primitiva za čitanje i pisanje u memoriju. Ovi inicijalni koraci su ključni za sticanje veće kontrole nad udaljenim procesom, iako primitivi u ovoj fazi neće služiti mnogim svrhama. Ubrzo će biti unapređeni na naprednije verzije.

### Memory Reading and Writing Using Execute Primitive

Cilj je izvršiti čitanje i pisanje u memoriju koristeći specifične funkcije. Za čitanje memorije koriste se funkcije koje podsećaju na sledeću strukturu:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
I za pisanje u memoriju koriste se funkcije slične ovoj strukturi:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Ove funkcije odgovaraju datim asembler instrukcijama:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identifying Suitable Functions

Skeneranje uobičajenih biblioteka otkrilo je odgovarajuće kandidate za ove operacije:

1. **Reading Memory:**
Funkcija `property_getName()` iz [Objective-C runtime library](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) je identifikovana kao pogodna funkcija za čitanje memorije. Funkcija je opisana u nastavku:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Ova funkcija efikasno deluje kao `read_func` vraćajući prvo polje `objc_property_t`.

2. **Pisanje u Memoriju:**
Pronalaženje unapred izgrađene funkcije za pisanje u memoriju je izazovnije. Međutim, funkcija `_xpc_int64_set_value()` iz libxpc je odgovarajući kandidat sa sledećom disasembly:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Da biste izvršili 64-bitno pisanje na specifičnu adresu, daleki poziv je strukturiran kao:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Sa ovim postavljenim primitivima, scena je postavljena za kreiranje deljene memorije, što predstavlja značajan napredak u kontroli udaljenog procesa.

## 4. Postavljanje Deljene Memorije

Cilj je uspostaviti deljenu memoriju između lokalnih i udaljenih zadataka, pojednostavljujući prenos podataka i olakšavajući pozivanje funkcija sa više argumenata. Pristup uključuje korišćenje `libxpc` i njegovog `OS_xpc_shmem` tipa objekta, koji se zasniva na Mach memorijskim unosima.

### Pregled Procesa:

1. **Alokacija Memorije**:

- Alocirajte memoriju za deljenje koristeći `mach_vm_allocate()`.
- Koristite `xpc_shmem_create()` za kreiranje `OS_xpc_shmem` objekta za alociranu memorijsku oblast. Ova funkcija će upravljati kreiranjem Mach memorijskog unosa i čuvati Mach send pravo na offsetu `0x18` objekta `OS_xpc_shmem`.

2. **Kreiranje Deljene Memorije u Udaljenom Procesu**:

- Alocirajte memoriju za `OS_xpc_shmem` objekat u udaljenom procesu sa udaljenim pozivom na `malloc()`.
- Kopirajte sadržaj lokalnog `OS_xpc_shmem` objekta u udaljeni proces. Međutim, ova inicijalna kopija će imati netačne nazive Mach memorijskih unosa na offsetu `0x18`.

3. **Ispravljanje Mach Memorijskog Unosa**:

- Iskoristite metodu `thread_set_special_port()` da umetnete send pravo za Mach memorijski unos u udaljeni zadatak.
- Ispravite polje Mach memorijskog unosa na offsetu `0x18` prepisivanjem sa imenom udaljenog memorijskog unosa.

4. **Finalizacija Postavljanja Deljene Memorije**:
- Validirajte udaljeni `OS_xpc_shmem` objekat.
- Uspostavite mapiranje deljene memorije sa udaljenim pozivom na `xpc_shmem_remote()`.

Prateći ove korake, deljena memorija između lokalnih i udaljenih zadataka biće efikasno postavljena, omogućavajući jednostavne prenose podataka i izvršavanje funkcija koje zahtevaju više argumenata.

## Dodatni Kodni Snippets

Za alokaciju memorije i kreiranje objekta deljene memorije:
```c
mach_vm_allocate();
xpc_shmem_create();
```
Za kreiranje i ispravljanje objekta deljene memorije u udaljenom procesu:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Zapamtite da pravilno obradite detalje Mach portova i imena ulaza u memoriju kako biste osigurali da podešavanje deljene memorije funkcioniše ispravno.

## 5. Postizanje Potpunog Kontrola

Nakon uspešnog uspostavljanja deljene memorije i sticanja sposobnosti proizvoljnog izvršavanja, suštinski smo stekli potpunu kontrolu nad ciljnim procesom. Ključne funkcionalnosti koje omogućavaju ovu kontrolu su:

1. **Proizvoljne Operacije sa Memorijom**:

- Izvršite proizvoljna čitanja iz memorije pozivajući `memcpy()` da kopirate podatke iz deljene oblasti.
- Izvršite proizvoljna pisanja u memoriju koristeći `memcpy()` za prenos podataka u deljenu oblast.

2. **Obrada Poziva Funkcija sa Više Argumenta**:

- Za funkcije koje zahtevaju više od 8 argumenata, rasporedite dodatne argumente na steku u skladu sa konvencijom pozivanja.

3. **Prenos Mach Portova**:

- Prenesite Mach portove između zadataka putem Mach poruka preko prethodno uspostavljenih portova.

4. **Prenos Fajl Deskriptora**:
- Prenesite fajl deskriptore između procesa koristeći fileports, tehniku koju je istakao Ian Beer u `triple_fetch`.

Ova sveobuhvatna kontrola je obuhvaćena unutar [threadexec](https://github.com/bazad/threadexec) biblioteke, koja pruža detaljnu implementaciju i korisnički prijateljski API za interakciju sa procesom žrtve.

## Važne Napomene:

- Osigurajte pravilnu upotrebu `memcpy()` za operacije čitanja/pisanja u memoriju kako biste održali stabilnost sistema i integritet podataka.
- Prilikom prenosa Mach portova ili fajl deskriptora, pridržavajte se pravilnih protokola i odgovorno rukujte resursima kako biste sprečili curenje ili nepredviđeni pristup.

Pridržavanjem ovih smernica i korišćenjem `threadexec` biblioteke, može se efikasno upravljati i interagovati sa procesima na granularnom nivou, postižući potpunu kontrolu nad ciljnim procesom.

## Reference

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

{{#include ../../../../banners/hacktricks-training.md}}
