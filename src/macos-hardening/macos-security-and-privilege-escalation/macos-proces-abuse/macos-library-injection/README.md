# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Kod **dyld-a je open source** i može se pronaći na adresi [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) i može se preuzeti kao tar arhiva pomoću **URL-a kao što je** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Pogledajte kako Dyld učitava biblioteke unutar binarnih datoteka na adresi:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Ovo je slično promenljivoj [**LD_PRELOAD na Linuxu**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Omogućava da se procesu koji će biti pokrenut zada učitavanje određene biblioteke sa putanje (ako je env var omogućen).

Ova tehnika se takođe može **koristiti kao ASEP tehnika**, pošto svaka instalirana aplikacija ima plist pod nazivom "Info.plist", koji omogućava **dodeljivanje environmental variables** pomoću ključa pod nazivom `LSEnvironmental`.

> [!TIP]
> Od 2012. godine, **Apple je drastično smanjio moć** promenljive **`DYLD_INSERT_LIBRARIES`**.
>
> Idite do koda i **proverite `src/dyld.cpp`**. U funkciji **`pruneEnvironmentVariables`** možete videti da se promenljive **`DYLD_*`** uklanjaju.
>
> U funkciji **`processRestricted`** postavlja se razlog ograničenja. Proverom tog koda možete videti da su razlozi sledeći:
>
> - Binarna datoteka je `setuid/setgid`
> - Postoji sekcija `__RESTRICT/__restrict` u macho binarnoj datoteci.
> - Software ima entitlements (hardened runtime) bez entitlementa [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
>  - Proverite **entitlements** binarne datoteke pomoću: `codesign -dv --entitlements :- </path/to/bin>`
>
> U novijim verzijama ovu logiku možete pronaći u drugom delu funkcije **`configureProcessRestrictions`.** Međutim, u novijim verzijama se izvršavaju **početne provere funkcije** (možete ukloniti if-ove povezane sa iOS-om ili simulacijom, jer se neće koristiti u macOS-u).

### Library Validation

Čak i ako binarna datoteka dozvoljava korišćenje env var promenljive **`DYLD_INSERT_LIBRARIES`**, ako binarna datoteka proverava potpis biblioteke koju treba učitati, neće učitati prilagođenu biblioteku.

Da bi učitala prilagođenu biblioteku, binarna datoteka mora imati **jedan od sledećih entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ili binarna datoteka **ne sme** imati **hardened runtime flag** ili **library validation flag**.

Možete proveriti da li binarna datoteka ima **hardened runtime** pomoću `codesign --display --verbose <bin>`, proverom runtime flag-a u **`CodeDirectory`**, kao u primeru: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Biblioteku možete učitati i ako je **potpisana istim sertifikatom kao binarna datoteka**.

Primer kako se ovo može (zlo)upotrebiti i kako proveriti ograničenja pronađite na adresi:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Zapamtite da se **prethodna Library Validation ograničenja takođe primenjuju** na izvođenje Dylib hijacking napada.

Kao i u Windows-u, u MacOS-u takođe možete izvršiti **hijacking dylib-ova** kako biste naterali **aplikacije** da **izvrše** **arbitrary** **code** (zapravo, običan user to možda neće moći da uradi jer može biti potrebna TCC dozvola za upisivanje unutar `.app` bundle-a i hijacking biblioteke).\
Međutim, način na koji **MacOS** aplikacije **učitavaju** biblioteke je **ograničeniji** nego u Windows-u. To znači da **malware** developeri i dalje mogu koristiti ovu tehniku za **stealth**, ali je verovatnoća da će moći da je **zloupotrebe za privilege escalation** mnogo manja.

Pre svega, **češće** je da **MacOS binarne datoteke navode punu putanju** do biblioteka koje treba učitati. Drugo, **MacOS nikada ne pretražuje** foldere iz promenljive **$PATH** za biblioteke.

**Glavni** deo **koda** povezanog sa ovom funkcionalnošću nalazi se u funkciji **`ImageLoader::recursiveLoadLibraries`** u datoteci `ImageLoader.cpp`.

Postoje **4 različite header Commands** koje macho binarna datoteka može koristiti za učitavanje biblioteka:

- Komanda **`LC_LOAD_DYLIB`** je uobičajena komanda za učitavanje dylib-a.
- Komanda **`LC_LOAD_WEAK_DYLIB`** funkcioniše kao prethodna, ali ako dylib nije pronađen, izvršavanje se nastavlja bez greške.
- Komanda **`LC_REEXPORT_DYLIB`** prosleđuje (ili ponovo izlaže) simbole iz druge biblioteke.
- Komanda **`LC_LOAD_UPWARD_DYLIB`** koristi se kada dve biblioteke zavise jedna od druge (to se naziva _upward dependency_).

Međutim, postoje **2 tipa dylib hijacking-a**:

- **Missing weak linked libraries**: To znači da će aplikacija pokušati da učita biblioteku koja ne postoji, a koja je konfigurisana pomoću **LC_LOAD_WEAK_DYLIB**. Zatim, **ako attacker postavi dylib tamo gde se očekuje, ona će biti učitana**.
- Činjenica da je link "weak" znači da će aplikacija nastaviti sa radom čak i ako biblioteka nije pronađena.
- **Kod povezan** sa ovim nalazi se u funkciji `ImageLoaderMachO::doGetDependentLibraries` u datoteci `ImageLoaderMachO.cpp`, gde je `lib->required` postavljen na `false` samo kada je **LC_LOAD_WEAK_DYLIB** postavljen na `true`.
- **Pronađite weak linked libraries** u binarnim datotekama pomoću sledeće komande (kasnije je prikazan primer kako kreirati hijacking biblioteke):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Konfigurisano pomoću @rpath**: Mach-O binarne datoteke mogu imati komande **`LC_RPATH`** i **`LC_LOAD_DYLIB`**. Na osnovu **vrednosti** ovih komandi, **biblioteke** će biti **učitane** iz **različitih direktorijuma**.
- **`LC_RPATH`** sadrži putanje do foldera koji se koriste za učitavanje biblioteka binarnom datotekom.
- **`LC_LOAD_DYLIB`** sadrži putanju do konkretnih biblioteka koje treba učitati. Ove putanje mogu sadržati **`@rpath`**, koji će biti **zamenjen** vrednostima iz **`LC_RPATH`**. Ako postoji više putanja u **`LC_RPATH`**, svaka od njih će biti korišćena za pretragu biblioteke koju treba učitati. Primer:
- Ako **`LC_LOAD_DYLIB`** sadrži `@rpath/library.dylib`, a **`LC_RPATH`** sadrži `/application/app.app/Contents/Framework/v1/` i `/application/app.app/Contents/Framework/v2/`, oba foldera će biti korišćena za učitavanje `library.dylib`**.** Ako biblioteka ne postoji u `[...]/v1/`, attacker bi mogao da je postavi tamo i hijack-uje učitavanje biblioteke iz `[...]/v2/`, pošto se prati redosled putanja u **`LC_LOAD_DYLIB`**.
- **Pronađite rpath putanje i biblioteke** u binarnim datotekama pomoću: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: To je **putanja** do direktorijuma koji sadrži **glavnu izvršnu datoteku**.
>
> **`@loader_path`**: To je **putanja** do **direktorijuma** koji sadrži **Mach-O binarnu datoteku** koja sadrži load command.
>
> - Kada se koristi u executable-u, **`@loader_path`** je praktično isto što i **`@executable_path`**.
> - Kada se koristi u **dylib-u**, **`@loader_path`** daje **putanju** do **dylib-a**.

Način za **escalate privileges** zloupotrebom ove funkcionalnosti postojao bi u retkom slučaju kada **aplikacija** koju izvršava **root** **traži** neku **biblioteku u folderu u koji attacker ima dozvolu upisa**.

> [!TIP]
> Dobar **scanner** za pronalaženje **missing libraries** u aplikacijama je [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ili [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> Dobar **report sa tehničkim detaljima** o ovoj tehnici možete pronaći [**ovde**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Zapamtite da se **prethodna Library Validation ograničenja takođe primenjuju** na izvođenje Dlopen hijacking napada.

Iz **`man dlopen`**:

- Kada **path ne sadrži slash karakter** (tj. samo je leaf name), **dlopen() će pretraživati**. Ako je **`$DYLD_LIBRARY_PATH`** postavljen prilikom pokretanja, dyld će prvo **proveriti taj direktorijum**. Zatim, ako pozivajući mach-o fajl ili glavna izvršna datoteka navode **`LC_RPATH`**, dyld će **proveriti te** direktorijume. Zatim, ako je proces **unrestricted**, dyld će pretraživati trenutni working directory. Na kraju, za stare binarne datoteke, dyld će pokušati određene fallback opcije. Ako je **`$DYLD_FALLBACK_LIBRARY_PATH`** postavljen prilikom pokretanja, dyld će pretraživati **te direktorijume**, u suprotnom će dyld proveriti **`/usr/local/lib/`** (ako je proces unrestricted), a zatim **`/usr/lib/`** (ove informacije su preuzete iz **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Ako ime ne sadrži slash, postoje 2 načina za hijacking:
>
> - Ako je neki **`LC_RPATH`** **writable** (ali se potpis proverava, pa je za ovo potrebno i da binarna datoteka bude unrestricted)
> - Ako je binarna datoteka **unrestricted**, pa je moguće učitati nešto iz CWD-a (ili zloupotrebiti neku od navedenih env promenljivih)

- Kada path **izgleda kao framework** putanja (npr. `/stuff/foo.framework/foo`), ako je **`$DYLD_FRAMEWORK_PATH`** postavljen prilikom pokretanja, dyld će prvo proveriti taj direktorijum za **partial path framework-a** (npr. `foo.framework/foo`). Zatim će dyld pokušati **prosleđenu putanju kakva jeste** (koristeći trenutni working directory za relativne putanje). Na kraju, za stare binarne datoteke, dyld će pokušati određene fallback opcije. Ako je **`$DYLD_FALLBACK_FRAMEWORK_PATH`** postavljen prilikom pokretanja, dyld će pretraživati te direktorijume. U suprotnom, pretražiće **`/Library/Frameworks`** (na macOS-u ako je proces unrestricted), a zatim **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. prosleđena putanja (koristi trenutni working directory za relativne putanje ako je proces unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Ako je u pitanju framework path, način za hijacking bio bi:
>
> - Ako je proces **unrestricted**, zloupotrebom **relativne putanje iz CWD-a** ili navedenih env promenljivih (čak i ako u dokumentaciji nije navedeno, kada je proces restricted, DYLD\_\* env promenljive se uklanjaju)

- Kada **path sadrži slash, ali nije framework path** (tj. puna putanja ili partial path do dylib-a), dlopen() prvo proverava (ako je postavljena) **`$DYLD_LIBRARY_PATH`** (sa leaf delom putanje). Zatim dyld **pokušava prosleđenu putanju** (koristeći trenutni working directory za relativne putanje, ali samo za unrestricted procese). Na kraju, za starije binarne datoteke, dyld će pokušati fallback opcije. Ako je **`$DYLD_FALLBACK_LIBRARY_PATH`** postavljen prilikom pokretanja, dyld će pretraživati te direktorijume, u suprotnom će proveriti **`/usr/local/lib/`** (ako je proces unrestricted), a zatim **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. prosleđena putanja (koristi trenutni working directory za relativne putanje ako je proces unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Ako ime sadrži slash i nije framework, način za hijacking bio bi:
>
> - Ako je binarna datoteka **unrestricted**, moguće je učitati nešto iz CWD-a ili `/usr/local/lib` (ili zloupotrebom neke od navedenih env promenljivih)

> [!TIP]
> Napomena: Ne postoje configuration files za **kontrolu dlopen pretrage**.
>
> Napomena: Ako je glavna izvršna datoteka **set\[ug]id binary** ili potpisana pomoću entitlements, sve environment variables se ignorišu i može se koristiti samo puna putanja ([proverite DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) za detaljnije informacije).
>
> Napomena: Apple platforme koriste "universal" fajlove za kombinovanje 32-bitnih i 64-bitnih biblioteka. To znači da ne postoje odvojene 32-bitne i 64-bitne search paths.
>
> Napomena: Na Apple platformama većina OS dylib-ova je objedinjena u **dyld cache** i ne postoji na disku. Zbog toga pozivanje **`stat()`** za proveru da li OS dylib postoji **neće funkcionisati**. Međutim, **`dlopen_preflight()`** koristi iste korake kao **`dlopen()`** za pronalaženje kompatibilnog mach-o fajla.

**Check paths**

Proverimo sve opcije pomoću sledećeg koda:
```c
// gcc dlopentest.c -o dlopentest -Wl,-rpath,/tmp/test
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
void* handle;

fprintf("--- No slash ---\n");
handle = dlopen("just_name_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative framework ---\n");
handle = dlopen("a/framework/rel_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs framework ---\n");
handle = dlopen("/a/abs/framework/abs_framework_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Relative Path ---\n");
handle = dlopen("a/folder/rel_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

fprintf("--- Abs Path ---\n");
handle = dlopen("/a/abs/folder/abs_folder_dlopentest.dylib",1);
if (!handle) {
fprintf(stderr, "Error loading: %s\n\n\n", dlerror());
}

return 0;
}
```
Ako ga kompajlirate i izvršite, možete videti **gde je svaka biblioteka neuspešno tražena**. Takođe, mogli biste da **filtrirate FS logove**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Hijacking relativne putanje

Ako **privilegovani binarni fajl/aplikacija** (kao što je SUID ili neki binarni fajl sa moćnim entitlements) **učitava biblioteku preko relativne putanje** (na primer, koristeći `@executable_path` ili `@loader_path`) i ima onemogućen **Library Validation**, moguće je premestiti binarni fajl na lokaciju na kojoj attacker može da **izmeni biblioteku učitanu preko relativne putanje** i zloupotrebi je za ubacivanje koda u proces.

## Uklanjanje `DYLD_*` i `LD_LIBRARY_PATH` env promenljivih

U fajlu `dyld-dyld-832.7.1/src/dyld2.cpp` moguće je pronaći funkciju **`pruneEnvironmentVariables`**, koja uklanja sve env promenljive koje **počinju sa `DYLD_`** i **`LD_LIBRARY_PATH=`**.

Takođe će postaviti na **null** konkretno env promenljive **`DYLD_FALLBACK_FRAMEWORK_PATH`** i **`DYLD_FALLBACK_LIBRARY_PATH`** za **suid** i **sgid** binarne fajlove.

Ova funkcija se poziva iz funkcije **`_main`** u istom fajlu ako je cilj OSX, na sledeći način:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
i te boolean zastavice se u kodu postavljaju u istoj datoteci:
```cpp
#if TARGET_OS_OSX
// support chrooting from old kernel
bool isRestricted = false;
bool libraryValidation = false;
// any processes with setuid or setgid bit set or with __RESTRICT segment is restricted
if ( issetugid() || hasRestrictedSegment(mainExecutableMH) ) {
isRestricted = true;
}
bool usingSIP = (csr_check(CSR_ALLOW_TASK_FOR_PID) != 0);
uint32_t flags;
if ( csops(0, CS_OPS_STATUS, &flags, sizeof(flags)) != -1 ) {
// On OS X CS_RESTRICT means the program was signed with entitlements
if ( ((flags & CS_RESTRICT) == CS_RESTRICT) && usingSIP ) {
isRestricted = true;
}
// Library Validation loosens searching but requires everything to be code signed
if ( flags & CS_REQUIRE_LV ) {
isRestricted = false;
libraryValidation = true;
}
}
gLinkContext.allowAtPaths                = !isRestricted;
gLinkContext.allowEnvVarsPrint           = !isRestricted;
gLinkContext.allowEnvVarsPath            = !isRestricted;
gLinkContext.allowEnvVarsSharedCache     = !libraryValidation || !usingSIP;
gLinkContext.allowClassicFallbackPaths   = !isRestricted;
gLinkContext.allowInsertFailures         = false;
gLinkContext.allowInterposing         	 = true;
```
Što u osnovi znači da je, ako je binarni fajl **suid** ili **sgid**, ili ima segment **RESTRICT** u zaglavljima, ili je potpisan sa zastavicom **CS_RESTRICT**, tada **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** tačno, pa se promenljive okruženja uklanjaju.

Imajte na umu da, ako je CS_REQUIRE_LV tačno, promenljive neće biti uklonjene, ali će validacija biblioteke proveriti da li koriste isti sertifikat kao originalni binarni fajl.

## Provera ograničenja

### SUID i SGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### Sekcija `__RESTRICT` sa segmentom `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Kreirajte novi sertifikat u Keychain-u i upotrebite ga za potpisivanje binarnog fajla:
```bash
# Apply runtime proetction
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello #Library won't be injected

# Apply library validation
codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert (signs must be from a valid Apple-signed developer certificate)

# Sign it
## If the signature is from an unverified developer the injection will still work
## If it's from a verified developer, it won't
codesign -f -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed

# Apply CS_RESTRICT protection
codesign -f -s <cert-name> --option=restrict hello-signed
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-signed # Won't work
```
> [!CAUTION]
> Imajte na umu da čak i binarni fajlovi potpisani zastavicama **`0x0(none)`** mogu dinamički dobiti zastavicu **`CS_RESTRICT`** prilikom izvršavanja, pa ova tehnika u njima neće funkcionisati.
>
> Možete proveriti da li proc ima ovu zastavicu pomoću (preuzmite [**csops ovde**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> a zatim proverite da li je zastavica 0x800 omogućena.

## Reference

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
