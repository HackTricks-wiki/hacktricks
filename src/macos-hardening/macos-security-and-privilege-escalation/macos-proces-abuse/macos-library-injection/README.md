# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Kod **dyld je otvorenog koda** i može se pronaći na [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) i može se preuzeti kao tar koristeći **URL kao što je** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Proces**

Pogledajte kako Dyld učitava biblioteke unutar binarnih datoteka u:

{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Ovo je kao [**LD_PRELOAD na Linuxu**](../../../../linux-hardening/privilege-escalation/#ld_preload). Omogućava da se naznači proces koji će se pokrenuti da učita određenu biblioteku sa putanje (ako je env var omogućena)

Ova tehnika se takođe može **koristiti kao ASEP tehnika** jer svaka aplikacija koja je instalirana ima plist pod nazivom "Info.plist" koji omogućava **dodeljivanje promenljivih okruženja** koristeći ključ pod nazivom `LSEnvironmental`.

> [!NOTE]
> Od 2012. **Apple je drastično smanjio moć** **`DYLD_INSERT_LIBRARIES`**.
>
> Idite na kod i **proverite `src/dyld.cpp`**. U funkciji **`pruneEnvironmentVariables`** možete videti da su **`DYLD_*`** promenljive uklonjene.
>
> U funkciji **`processRestricted`** postavljen je razlog ograničenja. Proverom tog koda možete videti da su razlozi:
>
> - Binarna datoteka je `setuid/setgid`
> - Postojanje `__RESTRICT/__restrict` sekcije u macho binarnoj datoteci.
> - Softver ima ovlašćenja (hardened runtime) bez [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables) ovlašćenja
>   - Proverite **ovlašćenja** binarne datoteke sa: `codesign -dv --entitlements :- </path/to/bin>`
>
> U novijim verzijama možete pronaći ovu logiku u drugom delu funkcije **`configureProcessRestrictions`.** Međutim, ono što se izvršava u novijim verzijama su **provere na početku funkcije** (možete ukloniti if-ove vezane za iOS ili simulaciju jer se ti neće koristiti u macOS.

### Validacija biblioteka

Čak i ako binarna datoteka dozvoljava korišćenje **`DYLD_INSERT_LIBRARIES`** env promenljive, ako binarna datoteka proverava potpis biblioteke za učitavanje, neće učitati prilagođenu.

Da bi se učitala prilagođena biblioteka, binarna datoteka mora imati **jedno od sledećih ovlašćenja**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ili binarna datoteka **ne bi trebala** imati **hardened runtime flag** ili **flag za validaciju biblioteka**.

Možete proveriti da li binarna datoteka ima **hardened runtime** sa `codesign --display --verbose <bin>` proveravajući flag runtime u **`CodeDirectory`** kao: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Takođe možete učitati biblioteku ako je **potpisana istim sertifikatom kao i binarna datoteka**.

Pronađite primer kako da (zlo)upotrebite ovo i proverite ograničenja u:

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Zapamtite da **prethodna ograničenja validacije biblioteka takođe važe** za izvođenje Dylib hijacking napada.

Kao i na Windows-u, u MacOS-u takođe možete **oteti dylibs** da bi **aplikacije** **izvršavale** **arbitrarni** **kod** (pa, zapravo, od običnog korisnika to možda neće biti moguće jer bi vam mogla biti potrebna TCC dozvola da pišete unutar `.app` paketa i otmete biblioteku).\
Međutim, način na koji **MacOS** aplikacije **učitavaju** biblioteke je **više ograničen** nego na Windows-u. To implicira da **malver** programeri i dalje mogu koristiti ovu tehniku za **neprimetnost**, ali je verovatnoća da će moći da **zloupotrebe ovo za eskalaciju privilegija mnogo manja**.

Prvo, **češće je** pronaći da **MacOS binarne datoteke ukazuju na punu putanju** do biblioteka koje treba učitati. I drugo, **MacOS nikada ne pretražuje** u folderima **$PATH** za biblioteke.

**Glavni** deo **koda** vezan za ovu funkcionalnost je u **`ImageLoader::recursiveLoadLibraries`** u `ImageLoader.cpp`.

Postoje **4 različite komande zaglavlja** koje macho binarna datoteka može koristiti za učitavanje biblioteka:

- **`LC_LOAD_DYLIB`** komanda je uobičajena komanda za učitavanje dylib-a.
- **`LC_LOAD_WEAK_DYLIB`** komanda funkcioniše kao prethodna, ali ako dylib nije pronađen, izvršavanje se nastavlja bez greške.
- **`LC_REEXPORT_DYLIB`** komanda proksira (ili ponovo izvozi) simbole iz druge biblioteke.
- **`LC_LOAD_UPWARD_DYLIB`** komanda se koristi kada dve biblioteke zavise jedna od druge (ovo se naziva _uzlazna zavisnost_).

Međutim, postoje **2 tipa dylib hijacking**:

- **Nedostajuće slabo povezane biblioteke**: To znači da će aplikacija pokušati da učita biblioteku koja ne postoji konfigurisana sa **LC_LOAD_WEAK_DYLIB**. Tada, **ako napadač postavi dylib gde se očekuje da će biti učitan**.
- Činjenica da je veza "slaba" znači da će aplikacija nastaviti da radi čak i ako biblioteka nije pronađena.
- **Kod vezan** za ovo je u funkciji `ImageLoaderMachO::doGetDependentLibraries` u `ImageLoaderMachO.cpp` gde je `lib->required` samo `false` kada je `LC_LOAD_WEAK_DYLIB` true.
- **Pronađite slabo povezane biblioteke** u binarnim datotekama sa (kasnije imate primer kako da kreirate biblioteke za otmicu):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Konfigurisano sa @rpath**: Mach-O binarne datoteke mogu imati komande **`LC_RPATH`** i **`LC_LOAD_DYLIB`**. Na osnovu **vrednosti** tih komandi, **biblioteke** će biti **učitane** iz **različitih direktorijuma**.
- **`LC_RPATH`** sadrži putanje nekih foldera koji se koriste za učitavanje biblioteka od strane binarne datoteke.
- **`LC_LOAD_DYLIB`** sadrži putanju do specifičnih biblioteka koje treba učitati. Ove putanje mogu sadržati **`@rpath`**, koje će biti **zamenjene** vrednostima u **`LC_RPATH`**. Ako postoji više putanja u **`LC_RPATH`**, sve će se koristiti za pretragu biblioteke za učitavanje. Primer:
- Ako **`LC_LOAD_DYLIB`** sadrži `@rpath/library.dylib` i **`LC_RPATH`** sadrži `/application/app.app/Contents/Framework/v1/` i `/application/app.app/Contents/Framework/v2/`. Obe mape će se koristiti za učitavanje `library.dylib`**.** Ako biblioteka ne postoji u `[...]/v1/` i napadač bi mogao da je postavi tamo da otme učitavanje biblioteke u `[...]/v2/` jer se redosled putanja u **`LC_LOAD_DYLIB`** poštuje.
- **Pronađite rpath putanje i biblioteke** u binarnim datotekama sa: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Je **putanja** do direktorijuma koji sadrži **glavnu izvršnu datoteku**.
>
> **`@loader_path`**: Je **putanja** do **direktorijuma** koji sadrži **Mach-O binarnu datoteku** koja sadrži komandu za učitavanje.
>
> - Kada se koristi u izvršnoj datoteci, **`@loader_path`** je zapravo **isto** kao **`@executable_path`**.
> - Kada se koristi u **dylib**, **`@loader_path`** daje **putanju** do **dylib**.

Način za **escalaciju privilegija** zloupotrebom ove funkcionalnosti bio bi u retkom slučaju kada neka **aplikacija** koja se izvršava **od** **root-a traži** neku **biblioteku u nekom folderu gde napadač ima dozvole za pisanje.**

> [!TIP]
> Lep **skener** za pronalaženje **nedostajućih biblioteka** u aplikacijama je [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ili [**CLI verzija**](https://github.com/pandazheng/DylibHijack).\
> Lep **izveštaj sa tehničkim detaljima** o ovoj tehnici može se pronaći [**ovde**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Primer**

{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Zapamtite da **prethodna ograničenja validacije biblioteka takođe važe** za izvođenje Dlopen hijacking napada.

Iz **`man dlopen`**:

- Kada putanja **ne sadrži znak kose crte** (tj. to je samo naziv lista), **dlopen() će pretraživati**. Ako je **`$DYLD_LIBRARY_PATH`** postavljen prilikom pokretanja, dyld će prvo **gledati u toj direktoriji**. Zatim, ako pozivajući mach-o fajl ili glavna izvršna datoteka specificiraju **`LC_RPATH`**, dyld će **gledati u tim** direktorijumima. Zatim, ako je proces **neograničen**, dyld će pretraživati u **trenutnom radnom direktorijumu**. Na kraju, za stare binarne datoteke, dyld će pokušati neke rezervne opcije. Ako je **`$DYLD_FALLBACK_LIBRARY_PATH`** postavljen prilikom pokretanja, dyld će pretraživati u **tim direktorijumima**, inače, dyld će gledati u **`/usr/local/lib/`** (ako je proces neograničen), a zatim u **`/usr/lib/`** (ove informacije su preuzete iz **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(ako je neograničen)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (ako je neograničen)
6. `/usr/lib/`

> [!CAUTION]
> Ako nema kose crte u imenu, postoje 2 načina da se izvrši otmica:
>
> - Ako je bilo koji **`LC_RPATH`** **pisan** (ali se potpis proverava, tako da za ovo takođe treba da binarna datoteka bude neograničena)
> - Ako je binarna datoteka **neograničena** i tada je moguće učitati nešto iz CWD (ili zloupotrebiti jednu od pomenutih env promenljivih)

- Kada putanja **izgleda kao putanja okvira** (npr. `/stuff/foo.framework/foo`), ako je **`$DYLD_FRAMEWORK_PATH`** postavljen prilikom pokretanja, dyld će prvo tražiti u toj direktoriji za **delimičnu putanju okvira** (npr. `foo.framework/foo`). Zatim, dyld će pokušati **datu putanju onako kako jeste** (koristeći trenutni radni direktorijum za relativne putanje). Na kraju, za stare binarne datoteke, dyld će pokušati neke rezervne opcije. Ako je **`$DYLD_FALLBACK_FRAMEWORK_PATH`** postavljen prilikom pokretanja, dyld će pretraživati te direktorijume. Inače, pretražiće **`/Library/Frameworks`** (na macOS-u ako je proces neograničen), zatim **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. data putanja (koristeći trenutni radni direktorijum za relativne putanje ako je neograničen)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (ako je neograničen)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Ako je putanja okvira, način da se otme bi bio:
>
> - Ako je proces **neograničen**, zloupotrebljavajući **relativnu putanju iz CWD** pomenutih env promenljivih (čak i ako nije rečeno u dokumentaciji, ako je proces ograničen DYLD\_\* env varijable su uklonjene)

- Kada putanja **sadrži kosu crtu, ali nije putanja okvira** (tj. puna putanja ili delimična putanja do dylib-a), dlopen() prvo gleda u (ako je postavljeno) **`$DYLD_LIBRARY_PATH`** (sa delom lista iz putanje). Zatim, dyld **pokušava datu putanju** (koristeći trenutni radni direktorijum za relativne putanje (ali samo za neograničene procese)). Na kraju, za starije binarne datoteke, dyld će pokušati rezervne opcije. Ako je **`$DYLD_FALLBACK_LIBRARY_PATH`** postavljen prilikom pokretanja, dyld će pretraživati u tim direktorijumima, inače, dyld će gledati u **`/usr/local/lib/`** (ako je proces neograničen), a zatim u **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. data putanja (koristeći trenutni radni direktorijum za relativne putanje ako je neograničen)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (ako je neograničen)
5. `/usr/lib/`

> [!CAUTION]
> Ako su u imenu kose crte i nije okvir, način da se otme bi bio:
>
> - Ako je binarna datoteka **neograničena** i tada je moguće učitati nešto iz CWD ili `/usr/local/lib` (ili zloupotrebiti jednu od pomenutih env promenljivih)

> [!NOTE]
> Napomena: Ne postoje **konfiguracione datoteke** za **kontrolu pretrage dlopen**.
>
> Napomena: Ako je glavna izvršna datoteka **set\[ug]id binarna datoteka ili je potpisana sa ovlašćenjima**, tada se **sve promenljive okruženja ignorišu**, i može se koristiti samo puna putanja ([proverite ograničenja DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) za detaljnije informacije)
>
> Napomena: Apple platforme koriste "univerzalne" datoteke za kombinovanje 32-bitnih i 64-bitnih biblioteka. To znači da ne postoje **odvojene 32-bitne i 64-bitne putanje pretrage**.
>
> Napomena: Na Apple platformama većina OS dylib-ova je **kombinovana u dyld keš** i ne postoje na disku. Stoga, pozivanje **`stat()`** da se proveri da li OS dylib postoji **neće raditi**. Međutim, **`dlopen_preflight()`** koristi iste korake kao **`dlopen()`** da pronađe kompatibilnu mach-o datoteku.

**Proverite putanje**

Hajde da proverimo sve opcije sa sledećim kodom:
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
Ako ga kompajlirate i izvršite, možete videti **gde je svaka biblioteka neuspešno pretražena**. Takođe, možete **filtrirati FS logove**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Ako **privilegovani binarni/program** (kao SUID ili neki binarni sa moćnim ovlašćenjima) **učitava biblioteku sa relativnom putanjom** (na primer koristeći `@executable_path` ili `@loader_path`) i ima **onemogućenu validaciju biblioteka**, može biti moguće premestiti binarni fajl na lokaciju gde napadač može **modifikovati biblioteku učitanu sa relativnom putanjom**, i zloupotrebiti je za injekciju koda u proces.

## Prune `DYLD_*` i `LD_LIBRARY_PATH` env varijable

U fajlu `dyld-dyld-832.7.1/src/dyld2.cpp` moguće je pronaći funkciju **`pruneEnvironmentVariables`**, koja će ukloniti svaku env varijablu koja **počinje sa `DYLD_`** i **`LD_LIBRARY_PATH=`**.

Takođe će postaviti na **null** specifično env varijable **`DYLD_FALLBACK_FRAMEWORK_PATH`** i **`DYLD_FALLBACK_LIBRARY_PATH`** za **suid** i **sgid** binarne fajlove.

Ova funkcija se poziva iz **`_main`** funkcije istog fajla ako se cilja na OSX na sledeći način:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
i ti boolean zastavice su postavljene u istoj datoteci u kodu:
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
Što u suštini znači da ako je binarni fajl **suid** ili **sgid**, ili ima **RESTRICT** segment u zaglavljima ili je potpisan sa **CS_RESTRICT** oznakom, tada je **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** tačno i env varijable su uklonjene.

Napomena: ako je CS_REQUIRE_LV tačno, tada varijable neće biti uklonjene, ali će validacija biblioteke proveriti da li koriste istu sertifikat kao originalni binarni fajl.

## Proveri Ograničenja

### SUID & SGID
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

Kreirajte novi sertifikat u Keychain-u i koristite ga za potpisivanje binarnog fajla:
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
> Imajte na umu da čak i ako postoje binarni fajlovi potpisani sa oznakama **`0x0(none)`**, mogu dobiti **`CS_RESTRICT`** oznaku dinamički kada se izvrše i stoga ova tehnika neće raditi na njima.
>
> Možete proveriti da li proces ima ovu oznaku sa (uzmite [**csops ovde**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> i zatim proverite da li je oznaka 0x800 omogućena.

## References

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
