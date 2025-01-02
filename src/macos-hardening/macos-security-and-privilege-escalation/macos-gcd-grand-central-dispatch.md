# macOS GCD - Grand Central Dispatch

{{#include ../../banners/hacktricks-training.md}}

## Osnovne informacije

**Grand Central Dispatch (GCD),** poznat i kao **libdispatch** (`libdispatch.dyld`), dostupan je i na macOS-u i na iOS-u. To je tehnologija koju je razvila Apple kako bi optimizovala podršku aplikacijama za konkurentno (multithreaded) izvršavanje na višekore hardveru.

**GCD** pruža i upravlja **FIFO redovima** u koje vaša aplikacija može **slati zadatke** u obliku **blok objekata**. Blokovi poslati u redove za raspodelu se **izvršavaju na skupu niti** koje u potpunosti upravlja sistem. GCD automatski kreira niti za izvršavanje zadataka u redovima za raspodelu i zakazuje te zadatke da se izvrše na dostupnim jezgrama.

> [!TIP]
> Ukratko, da bi se izvršio kod u **paraleli**, procesi mogu slati **blokove koda GCD-u**, koji će se pobrinuti za njihovo izvršavanje. Stoga, procesi ne kreiraju nove niti; **GCD izvršava dati kod sa svojim sopstvenim skupom niti** (koji se može povećavati ili smanjivati po potrebi).

Ovo je veoma korisno za uspešno upravljanje paralelnim izvršavanjem, značajno smanjujući broj niti koje procesi kreiraju i optimizujući paralelno izvršavanje. Ovo je idealno za zadatke koji zahtevaju **veliki paralelizam** (brute-forcing?) ili za zadatke koji ne bi trebali blokirati glavnu nit: Na primer, glavna nit na iOS-u upravlja UI interakcijama, tako da se svaka druga funkcionalnost koja bi mogla da uzrokuje zamrzavanje aplikacije (pretraga, pristup vebu, čitanje datoteke...) upravlja na ovaj način.

### Blokovi

Blok je **samostalna sekcija koda** (poput funkcije sa argumentima koja vraća vrednost) i može takođe specificirati vezane promenljive.\
Međutim, na nivou kompajlera blokovi ne postoje, oni su `os_object`s. Svaki od ovih objekata se sastoji od dve strukture:

- **blok literal**:&#x20;
- Počinje sa **`isa`** poljem, koje pokazuje na klasu bloka:
- `NSConcreteGlobalBlock` (blokovi iz `__DATA.__const`)
- `NSConcreteMallocBlock` (blokovi u heap-u)
- `NSConcreateStackBlock` (blokovi u steku)
- Ima **`flags`** (koji označavaju polja prisutna u opisu bloka) i neka rezervisana bajta
- Pokazivač na funkciju koja se poziva
- Pokazivač na opis bloka
- Uvezene promenljive bloka (ako ih ima)
- **opis bloka**: Njegova veličina zavisi od podataka koji su prisutni (kako je naznačeno u prethodnim flagovima)
- Ima neka rezervisana bajta
- Njegova veličina
- Obično će imati pokazivač na Objective-C stil potpis kako bi znao koliko prostora je potrebno za parametre (flag `BLOCK_HAS_SIGNATURE`)
- Ako su promenljive referencirane, ovaj blok će takođe imati pokazivače na pomoćnika za kopiranje (kopiranje vrednosti na početku) i pomoćnika za oslobađanje (oslobađanje).

### Redovi

Red za raspodelu je imenovani objekat koji pruža FIFO redosled blokova za izvršavanje.

Blokovi se postavljaju u redove za izvršavanje, a ovi podržavaju 2 moda: `DISPATCH_QUEUE_SERIAL` i `DISPATCH_QUEUE_CONCURRENT`. Naravno, **serijski** neće imati probleme sa trkačkim uslovima jer blok neće biti izvršen dok prethodni ne završi. Ali **drugi tip reda može imati**.

Podrazumevani redovi:

- `.main-thread`: Iz `dispatch_get_main_queue()`
- `.libdispatch-manager`: GCD-ov upravitelj redova
- `.root.libdispatch-manager`: GCD-ov upravitelj redova
- `.root.maintenance-qos`: Zadaci najniže prioriteta
- `.root.maintenance-qos.overcommit`
- `.root.background-qos`: Dostupno kao `DISPATCH_QUEUE_PRIORITY_BACKGROUND`
- `.root.background-qos.overcommit`
- `.root.utility-qos`: Dostupno kao `DISPATCH_QUEUE_PRIORITY_NON_INTERACTIVE`
- `.root.utility-qos.overcommit`
- `.root.default-qos`: Dostupno kao `DISPATCH_QUEUE_PRIORITY_DEFAULT`
- `.root.background-qos.overcommit`
- `.root.user-initiated-qos`: Dostupno kao `DISPATCH_QUEUE_PRIORITY_HIGH`
- `.root.background-qos.overcommit`
- `.root.user-interactive-qos`: Najviši prioritet
- `.root.background-qos.overcommit`

Obratite pažnju da će sistem odlučiti **koje niti upravljaju kojim redovima u svakom trenutku** (više niti može raditi u istom redu ili ista nit može raditi u različitim redovima u nekom trenutku)

#### Atributi

Kada kreirate red sa **`dispatch_queue_create`** treći argument je `dispatch_queue_attr_t`, koji obično može biti ili `DISPATCH_QUEUE_SERIAL` (što je zapravo NULL) ili `DISPATCH_QUEUE_CONCURRENT` koji je pokazivač na `dispatch_queue_attr_t` strukturu koja omogućava kontrolu nekih parametara reda.

### Objekti za raspodelu

Postoji nekoliko objekata koje libdispatch koristi, a redovi i blokovi su samo 2 od njih. Moguće je kreirati ove objekte sa `dispatch_object_create`:

- `block`
- `data`: Blokovi podataka
- `group`: Grupa blokova
- `io`: Asinhroni I/O zahtevi
- `mach`: Mach portovi
- `mach_msg`: Mach poruke
- `pthread_root_queue`: Red sa pthread nitnim bazenom i ne radnim redovima
- `queue`
- `semaphore`
- `source`: Izvor događaja

## Objective-C

U Objective-C postoje različite funkcije za slanje bloka za izvršavanje u paraleli:

- [**dispatch_async**](https://developer.apple.com/documentation/dispatch/1453057-dispatch_async): Podnosi blok za asinhrono izvršavanje na redu za raspodelu i odmah se vraća.
- [**dispatch_sync**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync): Podnosi blok objekat za izvršavanje i vraća se nakon što taj blok završi sa izvršavanjem.
- [**dispatch_once**](https://developer.apple.com/documentation/dispatch/1447169-dispatch_once): Izvršava blok objekat samo jednom tokom trajanja aplikacije.
- [**dispatch_async_and_wait**](https://developer.apple.com/documentation/dispatch/3191901-dispatch_async_and_wait): Podnosi radni predmet za izvršavanje i vraća se samo nakon što završi sa izvršavanjem. Za razliku od [**`dispatch_sync`**](https://developer.apple.com/documentation/dispatch/1452870-dispatch_sync), ova funkcija poštuje sve atribute reda kada izvršava blok.

Ove funkcije očekuju sledeće parametre: [**`dispatch_queue_t`**](https://developer.apple.com/documentation/dispatch/dispatch_queue_t) **`queue,`** [**`dispatch_block_t`**](https://developer.apple.com/documentation/dispatch/dispatch_block_t) **`block`**

Ovo je **struktura Bloka**:
```c
struct Block {
void *isa; // NSConcreteStackBlock,...
int flags;
int reserved;
void *invoke;
struct BlockDescriptor *descriptor;
// captured variables go here
};
```
I ovo je primer korišćenja **paralelizma** sa **`dispatch_async`**:
```objectivec
#import <Foundation/Foundation.h>

// Define a block
void (^backgroundTask)(void) = ^{
// Code to be executed in the background
for (int i = 0; i < 10; i++) {
NSLog(@"Background task %d", i);
sleep(1);  // Simulate a long-running task
}
};

int main(int argc, const char * argv[]) {
@autoreleasepool {
// Create a dispatch queue
dispatch_queue_t backgroundQueue = dispatch_queue_create("com.example.backgroundQueue", NULL);

// Submit the block to the queue for asynchronous execution
dispatch_async(backgroundQueue, backgroundTask);

// Continue with other work on the main queue or thread
for (int i = 0; i < 10; i++) {
NSLog(@"Main task %d", i);
sleep(1);  // Simulate a long-running task
}
}
return 0;
}
```
## Swift

**`libswiftDispatch`** je biblioteka koja pruža **Swift vezu** za Grand Central Dispatch (GCD) okvir koji je prvobitno napisan u C.\
Biblioteka **`libswiftDispatch`** obavija C GCD API-je u interfejs koji je više prilagođen Swift-u, olakšavajući i čineći intuitivnijim rad za Swift programere sa GCD-om.

- **`DispatchQueue.global().sync{ ... }`**
- **`DispatchQueue.global().async{ ... }`**
- **`let onceToken = DispatchOnce(); onceToken.perform { ... }`**
- **`async await`**
- **`var (data, response) = await URLSession.shared.data(from: URL(string: "https://api.example.com/getData"))`**

**Primer koda**:
```swift
import Foundation

// Define a closure (the Swift equivalent of a block)
let backgroundTask: () -> Void = {
for i in 0..<10 {
print("Background task \(i)")
sleep(1)  // Simulate a long-running task
}
}

// Entry point
autoreleasepool {
// Create a dispatch queue
let backgroundQueue = DispatchQueue(label: "com.example.backgroundQueue")

// Submit the closure to the queue for asynchronous execution
backgroundQueue.async(execute: backgroundTask)

// Continue with other work on the main queue
for i in 0..<10 {
print("Main task \(i)")
sleep(1)  // Simulate a long-running task
}
}
```
## Frida

Sledeći Frida skript može se koristiti za **hook-ovanje u nekoliko `dispatch`** funkcija i ekstrakciju imena reda, backtrace-a i bloka: [**https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js**](https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js)
```bash
frida -U <prog_name> -l libdispatch.js

dispatch_sync
Calling queue: com.apple.UIKit._UIReusePool.reuseSetAccess
Callback function: 0x19e3a6488 UIKitCore!__26-[_UIReusePool addObject:]_block_invoke
Backtrace:
0x19e3a6460 UIKitCore!-[_UIReusePool addObject:]
0x19e3a5db8 UIKitCore!-[UIGraphicsRenderer _enqueueContextForReuse:]
0x19e3a57fc UIKitCore!+[UIGraphicsRenderer _destroyCGContext:withRenderer:]
[...]
```
## Ghidra

Trenutno Ghidra ne razume ni ObjectiveC **`dispatch_block_t`** strukturu, ni **`swift_dispatch_block`**.

Dakle, ako želite da ih razume, možete ih jednostavno **deklarisati**:

<figure><img src="../../images/image (1160).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1162).png" alt="" width="563"><figcaption></figcaption></figure>

<figure><img src="../../images/image (1163).png" alt="" width="563"><figcaption></figcaption></figure>

Zatim, pronađite mesto u kodu gde se **koriste**:

> [!TIP]
> Zabeležite sve reference na "block" da biste razumeli kako možete da shvatite da se struktura koristi.

<figure><img src="../../images/image (1164).png" alt="" width="563"><figcaption></figcaption></figure>

Desni klik na promenljivu -> Ponovno definiši promenljivu i izaberite u ovom slučaju **`swift_dispatch_block`**:

<figure><img src="../../images/image (1165).png" alt="" width="563"><figcaption></figcaption></figure>

Ghidra će automatski prepraviti sve:

<figure><img src="../../images/image (1166).png" alt="" width="563"><figcaption></figcaption></figure>

## References

- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../banners/hacktricks-training.md}}
