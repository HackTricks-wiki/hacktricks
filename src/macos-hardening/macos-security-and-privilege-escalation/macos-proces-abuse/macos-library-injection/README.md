# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Kod **dyld-a je open source** i može se pronaći na [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) i može se preuzeti kao tar pomoću **URL-a kao što je** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Pogledajte kako Dyld učitava biblioteke unutar binarnih datoteka na:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Ovo je slično kao [**LD_PRELOAD na Linux-u**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Omogućava navođenje procesa koji će biti pokrenut da učita određenu biblioteku sa putanje (ako je env var omogućen).

Ova tehnika se takođe može **koristiti kao ASEP tehnika**, pošto svaka instalirana aplikacija ima plist pod nazivom "Info.plist", koji omogućava **dodeljivanje environment varijabli** pomoću ključa `LSEnvironmental`.

> [!TIP]
> Od 2012. godine **Apple je drastično smanjio moć** promenljive **`DYLD_INSERT_LIBRARIES`**. Proces se smatra **restricted** — nakon čega `dyld` briše svaku `DYLD_*` promenljivu iz njegovog okruženja — kada važi bilo koji od sledećih uslova:
>
> - Binarna datoteka je `setuid/setgid`
> - Mach-O ima sekciju **`__RESTRICT/__restrict`**
> - Binarna datoteka je potpisana hardened runtime-om, a AMFI joj ne daje dozvole "path/print variables", odnosno nedostaje joj [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - Proverite **entitlements** binarne datoteke pomoću: `codesign -dv --entitlements :- </path/to/bin>`
>
> U aktuelnom `dyld`-u ovo više ne određuje samo `dyld`: `ProcessConfig::Security::Security()` poziva **AMFI** preko `amfi_check_dyld_policy_self()`, a zatim poziva `pruneEnvVars()`. Tačan kod je objašnjen u odeljku [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) ispod.

### Library Validation

Čak i ako binarna datoteka dozvoljava korišćenje env promenljive **`DYLD_INSERT_LIBRARIES`**, ako binarna datoteka proverava potpis biblioteke koju treba učitati, neće učitati prilagođenu biblioteku.

Da bi učitala prilagođenu biblioteku, binarna datoteka mora da ima **jedan od sledećih entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ili binarna datoteka **ne sme** da ima **hardened runtime flag** ili **library validation flag**.

Možete proveriti da li binarna datoteka ima **hardened runtime** pomoću `codesign --display --verbose <bin>`, proveravajući runtime flag u **`CodeDirectory`**, na primer: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Biblioteku možete učitati i ako je **potpisana istim sertifikatom kao binarna datoteka**.

Primer kako se ovo može zloupotrebiti i kako proveriti ograničenja pronađite na:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Zapamtite da se **prethodna Library Validation ograničenja takođe primenjuju** pri izvođenju Dylib hijacking napada.

Kao i u Windows-u, i u MacOS-u možete **hijack-ovati dylib-ove** kako biste omogućili da **aplikacije** **izvrše** proizvoljan **kod** (zapravo, običan korisnik ovo možda ne bi mogao da uradi, jer može biti potrebna TCC dozvola za upisivanje unutar `.app` bundle-a i hijack-ovanje biblioteke).\
Međutim, način na koji **MacOS** aplikacije **učitavaju** biblioteke je **ograničeniji** nego u Windows-u. To znači da **malware** developeri i dalje mogu koristiti ovu tehniku za **stealth**, ali je verovatnoća da će se ova tehnika moći **zloupotrebiti za eskalaciju privilegija mnogo manja**.

Pre svega, mnogo je **češće** da **MacOS binarne datoteke navode punu putanju** do biblioteka koje treba učitati. Drugo, **MacOS nikada ne pretražuje** foldere iz **$PATH** za biblioteke.

Glavni deo **koda** povezanog sa ovom funkcionalnošću nalazi se u funkciji **`ImageLoader::recursiveLoadLibraries`** u `ImageLoader.cpp`.

Postoje **4 različite header Commands** koje macho binarna datoteka može koristiti za učitavanje biblioteka:

- Komanda **`LC_LOAD_DYLIB`** je uobičajena komanda za učitavanje dylib-a.
- Komanda **`LC_LOAD_WEAK_DYLIB`** radi kao prethodna, ali ako dylib nije pronađen, izvršavanje se nastavlja bez greške.
- Komanda **`LC_REEXPORT_DYLIB`** prosleđuje (ili ponovo izlaže) simbole iz druge biblioteke.
- Komanda **`LC_LOAD_UPWARD_DYLIB`** koristi se kada dve biblioteke zavise jedna od druge (ovo se naziva _upward dependency_).

Međutim, postoje **2 tipa dylib hijacking-a**:

- **Missing weak linked libraries**: Ovo znači da će aplikacija pokušati da učita biblioteku koja ne postoji, a konfigurisana je pomoću **LC_LOAD_WEAK_DYLIB**. Zatim, **ako attacker postavi dylib na očekivano mesto, ona će biti učitana**.
- Činjenica da je link "weak" znači da će aplikacija nastaviti sa radom čak i ako biblioteka nije pronađena.
- **Kod povezan** sa ovim nalazi se u funkciji `ImageLoaderMachO::doGetDependentLibraries` u `ImageLoaderMachO.cpp`, gde je `lib->required` jednako `false` samo kada je **LC_LOAD_WEAK_DYLIB** true.
- **Pronađite weak linked libraries** u binarnim datotekama pomoću (kasnije imate primer kako da kreirate hijacking biblioteke):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Konfigurisano pomoću @rpath**: Mach-O binarne datoteke mogu imati komande **`LC_RPATH`** i **`LC_LOAD_DYLIB`**. Na osnovu **vrednosti** tih komandi, **biblioteke** će biti **učitane** iz **različitih direktorijuma**.
- **`LC_RPATH`** sadrži putanje do foldera koji se koriste za učitavanje biblioteka binarnom datotekom.
- **`LC_LOAD_DYLIB`** sadrži putanju do konkretnih biblioteka koje treba učitati. Ove putanje mogu sadržati **`@rpath`**, koji će biti **zamenjen** vrednostima iz **`LC_RPATH`**. Ako postoji više putanja u **`LC_RPATH`**, svaka od njih će biti korišćena za pretragu biblioteke koju treba učitati. Primer:
- Ako **`LC_LOAD_DYLIB`** sadrži `@rpath/library.dylib`, a **`LC_RPATH`** sadrži `/application/app.app/Contents/Framework/v1/` i `/application/app.app/Contents/Framework/v2/`. Oba foldera će biti korišćena za učitavanje `library.dylib`**.** Ako biblioteka ne postoji u `[...]/v1/`, attacker bi mogao da je postavi tamo i hijack-uje učitavanje biblioteke iz `[...]/v2/`, jer se prati redosled putanja u **`LC_LOAD_DYLIB`**.
- **Pronađite rpath putanje i biblioteke** u binarnim datotekama pomoću: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: To je **putanja** do direktorijuma koji sadrži **glavnu izvršnu datoteku**.
>
> **`@loader_path`**: To je **putanja** do **direktorijuma** koji sadrži **Mach-O binarnu datoteku** koja sadrži load command.
>
> - Kada se koristi u izvršnoj datoteci, **`@loader_path`** je praktično isto što i **`@executable_path`**.
> - Kada se koristi u **dylib-u**, **`@loader_path`** daje **putanju** do **dylib-a**.

Način za **eskalaciju privilegija** zloupotrebom ove funkcionalnosti postojao bi u retkom slučaju kada **aplikacija** koju izvršava **root** traži **biblioteku u folderu u koji attacker ima dozvolu upisa**.

> [!TIP]
> Dobar **scanner** za pronalaženje **missing libraries** u aplikacijama je [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ili [**CLI verzija**](https://github.com/pandazheng/DylibHijack).\
> Dobar [**izveštaj sa tehničkim detaljima**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) o ovoj tehnici možete pronaći [**ovde**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Primer**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Zapamtite da se **prethodna Library Validation ograničenja takođe primenjuju** pri izvođenju Dlopen hijacking napada.

Iz **`man dlopen`**:

- Kada **putanja ne sadrži slash karakter** (odnosno, predstavlja samo leaf name), **dlopen() će pretraživati**. Ako je **`$DYLD_LIBRARY_PATH`** bio postavljen pri pokretanju, dyld će prvo **tražiti u tom direktorijumu**. Zatim, ako pozivajući mach-o fajl ili glavna izvršna datoteka navode **`LC_RPATH`**, dyld će **tražiti u tim** direktorijumima. Zatim, ako je proces **unrestricted**, dyld će pretraživati trenutni radni direktorijum. Na kraju, za stare binarne datoteke, dyld će pokušati neke fallback opcije. Ako je **`$DYLD_FALLBACK_LIBRARY_PATH`** bio postavljen pri pokretanju, dyld će pretraživati **te direktorijume**, u suprotnom će dyld tražiti u **`/usr/local/lib/`** (ako je proces unrestricted), a zatim u **`/usr/lib/`** (ove informacije su preuzete iz **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(ako je unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (ako je unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Ako nema slash-ova u imenu, postoje 2 načina za hijacking:
>
> - Ako je bilo koji **`LC_RPATH`** writable (ali se potpis proverava, pa je za ovo potrebno i da binarna datoteka bude unrestricted)
> - Ako je binarna datoteka **unrestricted**, pa je moguće učitati nešto iz CWD-a (ili zloupotrebom neke od pomenutih env promenljivih)

- Kada putanja **izgleda kao** framework putanja (npr. `/stuff/foo.framework/foo`), ako je **`$DYLD_FRAMEWORK_PATH`** bio postavljen pri pokretanju, dyld će prvo tražiti framework partial path u tom direktorijumu (npr. `foo.framework/foo`). Zatim će dyld pokušati **prosleđenu putanju bez izmena** (koristeći trenutni radni direktorijum za relativne putanje). Na kraju, za stare binarne datoteke, dyld će pokušati neke fallback opcije. Ako je **`$DYLD_FALLBACK_FRAMEWORK_PATH`** bio postavljen pri pokretanju, dyld će pretraživati te direktorijume. U suprotnom, pretraživaće **`/Library/Frameworks`** (na macOS-u ako je proces unrestricted), a zatim **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. prosleđena putanja (koristeći trenutni radni direktorijum za relativne putanje ako je unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (ako je unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Ako je u pitanju framework putanja, način za hijack bio bi:
>
> - Ako je proces **unrestricted**, zloupotrebom **relativne putanje iz CWD-a** ili pomenutih env promenljivih (čak i ako to nije navedeno u dokumentaciji, ako je proces restricted, DYLD\_\* env promenljive se uklanjaju)

- Kada **putanja sadrži slash, ali nije framework putanja** (odnosno, puna putanja ili partial path do dylib-a), dlopen() prvo traži (ako je postavljeno) u **`$DYLD_LIBRARY_PATH`** (sa leaf delom putanje). Zatim dyld **pokušava sa prosleđenom putanjom** (koristeći trenutni radni direktorijum za relativne putanje, ali samo za unrestricted procese). Na kraju, za starije binarne datoteke, dyld će pokušati fallback opcije. Ako je **`$DYLD_FALLBACK_LIBRARY_PATH`** bio postavljen pri pokretanju, dyld će pretraživati te direktorijume, u suprotnom će tražiti u **`/usr/local/lib/`** (ako je proces unrestricted), a zatim u **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. prosleđena putanja (koristeći trenutni radni direktorijum za relativne putanje ako je unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (ako je unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Ako ime sadrži slash i nije framework, način za hijack bio bi:
>
> - Ako je binarna datoteka **unrestricted**, moguće je učitati nešto iz CWD-a ili `/usr/local/lib` (ili zloupotrebom neke od pomenutih env promenljivih)

> [!TIP]
> Napomena: Ne postoje konfiguracioni fajlovi za **kontrolisanje dlopen pretrage**.
>
> Napomena: Ako je glavna izvršna datoteka **set\[ug]id binarna datoteka** ili je codesigned sa entitlements, sve environment promenljive se ignorišu i može se koristiti samo puna putanja ([proverite DYLD_INSERT_LIBRARIES ograničenja](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) za detaljnije informacije)
>
> Napomena: Apple platforme koriste "universal" fajlove za kombinovanje 32-bitnih i 64-bitnih biblioteka. To znači da ne postoje odvojene 32-bitne i 64-bitne search putanje.
>
> Napomena: Na Apple platformama većina OS dylib-ova je kombinovana u dyld cache i ne postoji na disku. Zbog toga pozivanje **`stat()`** radi prethodne provere da li OS dylib postoji **neće raditi**. Međutim, **`dlopen_preflight()`** koristi iste korake kao **`dlopen()`** za pronalaženje kompatibilnog mach-o fajla.

**Provera putanja**

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
Ako ga kompajlirate i izvršite, možete videti **gde je svaka biblioteka neuspešno tražena**. Takođe, možete **filtrirati FS logove**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Ako **privileged binary/app** (kao što je SUID ili neki binary sa moćnim entitlements) **učitava biblioteku preko relativne putanje** (na primer, koristeći `@executable_path` ili `@loader_path`) i ima onemogućen **Library Validation**, moguće je premestiti binary na lokaciju na kojoj attacker može da **izmeni biblioteku učitanu preko relativne putanje** i iskoristi je za ubacivanje koda u proces.

## Uklanjanje `DYLD_*` env variables

Starije verzije `dyld`-a (`dyld2.cpp`) donosile su ovu odluku unutar procesa pomoću `issetugid()`, `hasRestrictedSegment()` i `csops(CS_OPS_STATUS)`. U **trenutnom `dyld`-u odluka se delegira AMFI-ju**, a kod se nalazi u `ProcessConfig::Security::Security()` u `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
```cpp
const uint64_t amfiFlags = getAMFI(process, syscall);
this->allowAtPaths              = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_AT_PATH);
this->allowEnvVarsPrint         = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS);
this->allowEnvVarsPath          = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS);
this->allowEnvVarsSharedCache   = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE);
this->allowClassicFallbackPaths = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS);
this->allowInsertFailures       = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION);
this->allowInterposing          = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING);
this->allowEmbeddedVars         = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_EMBEDDED_VARS);
this->allowDevelopmentVars      = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_DEVELOPMENT_VARS);
this->allowLibSystemOverrides   = (amfiFlags & AMFI_DYLD_OUTPUT_ALLOW_LIBSYSTEM_OVERRIDE);
...
// env vars are only pruned on macOS
switch ( process.platform.value() ) {
case PLATFORM_MACOS:
case PLATFORM_IOSMAC:
case PLATFORM_DRIVERKIT:
break;
default:
return;
}

// env vars are only pruned when process is restricted
if ( this->allowEnvVarsPrint || this->allowEnvVarsPath || this->allowEnvVarsSharedCache )
return;

this->pruneEnvVars(process);
```
Iz ovoga vredi izdvojiti dve stvari:

- Uklanjanje se dešava samo na **macOS / Mac Catalyst / DriverKit** — i samo kada AMFI nije odobrio nijednu od opcija `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- AMFI upit dobija svojstva samog izvršnog fajla:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
gde je `isRestricted()` bukvalno provera segmenta `__RESTRICT` (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` zatim uklanja **svaku** promenljivu čiji naziv počinje sa `DYLD_` i pomera parametre `apple[]` nadole, tako da ih ni procesi-potomci ograničenog procesa ne nasleđuju:
```cpp
// For security, setuid programs ignore DYLD_* environment variables.
// Additionally, the DYLD_* enviroment variables are removed
// from the environment, so that any child processes doesn't see them.
for ( const char* const* s = proc.envp; *s != NULL; s++ ) {
if ( strncmp(*s, "DYLD_", 5) != 0 ) {
*d++ = *s;
}
...
```
> [!TIP]
> Praktična posledica: **`DYLD_*` se uklanja kada je proces ograničen** — setuid/setgid, odeljkom `__RESTRICT/__restrict` ili hardened-runtime/entitled binarnim fajlovima kojima AMFI odbija da dodeli path/print flags. Ako proces umesto toga ima samo **library validation** (`CS_REQUIRE_LV`), promenljive opstaju, ali ubačeni dylib mora biti potpisan istim **Team ID**-jem (ili od strane Apple-a), tako da vam je potreban jedan od entitlements za onemogućavanje library validation da biste zaista ubacili kod.

Pošto je odluka sada na AMFI-ju, najbrži način da saznate šta će određeni binarni fajl dobiti jeste da proverite na šta se AMFI oslanja — entitlements i signing flags — umesto da posmatrate sam `dyld`:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
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
### Odeljak `__RESTRICT` sa segmentom `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Kreirajte novi sertifikat u Keychain-u i koristite ga za potpisivanje binarne datoteke:
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
> Imajte na umu da čak i binarne datoteke potpisane sa **`0x0(none)`** flagovima mogu dinamički dobiti **`CS_RESTRICT`** flag prilikom izvršavanja, pa ova tehnika neće raditi kod njih.
>
> Možete proveriti da li proc ima ovaj flag pomoću (preuzmite [**csops ovde**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> a zatim proverite da li je flag 0x800 omogućen.

## Reference

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` check)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (pokretanje procesa i umetanje biblioteka)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
