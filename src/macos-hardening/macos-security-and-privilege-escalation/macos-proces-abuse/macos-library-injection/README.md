# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Kod **dyld** je open source i može se pronaći na [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) i može se preuzeti kao tar pomoću **URL-a kao što je** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Pogledajte kako Dyld učitava libraries unutar binaries na:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Ovo je slično kao [**LD_PRELOAD on Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Omogućava da se procesu koji će biti pokrenut navede da učita određenu library sa određene putanje (ako je env var omogućen)<sup>[[4]](#references)</sup>

Ova tehnika se takođe može **koristiti kao ASEP tehnika**, pošto svaka instalirana aplikacija ima plist pod nazivom "Info.plist", koji omogućava **dodeljivanje environmental variables** pomoću ključa `LSEnvironmental`.

> [!TIP]
> Od 2012. godine **Apple je drastično smanjio moć** promenljive **`DYLD_INSERT_LIBRARIES`**. Proces se smatra **restricted** — nakon čega `dyld` briše svaku `DYLD_*` promenljivu iz njegovog environment-a — kada važi bilo šta od sledećeg:
>
> - Binary je `setuid/setgid`
> - Mach-O ima sekciju **`__RESTRICT/__restrict`**
> - Binary je potpisan sa hardened runtime-om, a AMFI mu ne dodeljuje dozvole "path/print variables", odnosno nema [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - **Entitlements** binary-ja možete proveriti pomoću: `codesign -dv --entitlements :- </path/to/bin>`
>
> U trenutnom `dyld`-u ovo više ne odlučuje samo `dyld`: `ProcessConfig::Security::Security()` poziva **AMFI** preko `amfi_check_dyld_policy_self()`, a zatim poziva `pruneEnvVars()`. Tačan kod je objašnjen u odeljku [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) u nastavku.

### Library Validation

Čak i ako binary dozvoljava environment variable **`DYLD_INSERT_LIBRARIES`**, neće učitati custom library ako proverava njen signature.

Da bi učitao custom library, binary mora imati **jedan od sledećih entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ili binary **ne sme** imati **hardened runtime flag** ili **library validation flag**.

Da li binary ima **hardened runtime** možete proveriti pomoću `codesign --display --verbose <bin>`, proverom runtime flag-a u **`CodeDirectory`**, na primer: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Library možete učitati i ako je **potpisana istim certificate-om kao binary**.

Primer kako ovo (zlo)upotrebiti i proveriti restrictions pronađite na:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Zapamtite da se **prethodna Library Validation ograničenja takođe primenjuju** pri izvođenju Dylib hijacking attacks.

Kao i u Windows-u, i u MacOS-u možete **hijack-ovati dylibs** kako biste naterali **applications** da **izvrše** **arbitrary** **code** (zapravo, običan user ovo možda ne bi mogao, pošto je za upisivanje unutar `.app` bundle-a i hijack-ovanje library-ja možda potrebna TCC permission).\
Međutim, način na koji **MacOS** applications **učitavaju** libraries je **restriktivniji** nego u Windows-u. To znači da **malware** developers i dalje mogu koristiti ovu tehniku za **stealth**, ali je verovatnoća da će moći da je **zloupotrebe za privilege escalation** mnogo manja.

Pre svega, mnogo je **češće** da **MacOS binaries navode punu putanju** do libraries koje treba učitati. Drugo, **MacOS nikada ne pretražuje** folders iz **$PATH** za libraries.

**Glavni** deo **code-a** povezanog sa ovom funkcionalnošću nalazi se u `ImageLoader::recursiveLoadLibraries` u `ImageLoader.cpp`.

Postoje **4 različite header Commands** koje macho binary može koristiti za učitavanje libraries:

- **`LC_LOAD_DYLIB`** command je uobičajeni command za učitavanje dylib-a.
- **`LC_LOAD_WEAK_DYLIB`** command radi kao prethodni, ali ako dylib nije pronađen, execution se nastavlja bez greške.
- **`LC_REEXPORT_DYLIB`** command proxy-je (ili re-export-uje) symbols iz druge library.
- **`LC_LOAD_UPWARD_DYLIB`** command se koristi kada dve libraries zavise jedna od druge (ovo se naziva _upward dependency_).

Međutim, postoje **2 types dylib hijacking-a**:

- **Missing weak linked libraries**: Ovo znači da će application pokušati da učita library koja ne postoji, a konfigurisana je pomoću **LC_LOAD_WEAK_DYLIB**. Zatim, **ako attacker postavi dylib tamo gde se očekuje, ona će biti učitana**.
- Činjenica da je link "weak" znači da će application nastaviti da radi čak i ako library nije pronađena.
- **Code povezan** sa ovim nalazi se u funkciji `ImageLoaderMachO::doGetDependentLibraries` u `ImageLoaderMachO.cpp`, gde je `lib->required` postavljen na `false` samo kada je `LC_LOAD_WEAK_DYLIB` true.
- **Weak linked libraries** u binaries možete pronaći pomoću sledećeg (kasnije postoji primer kako kreirati hijacking libraries):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Mach-O binaries mogu imati commands **`LC_RPATH`** i **`LC_LOAD_DYLIB`**. Na osnovu **values** tih commands, **libraries** će biti **učitane** iz **različitih direktorijuma**.
- **`LC_RPATH`** sadrži paths do folders koji binary koristi za učitavanje libraries.
- **`LC_LOAD_DYLIB`** sadrži path do određenih libraries koje treba učitati. Ove paths mogu sadržati **`@rpath`**, koji će biti **zamenjen** vrednostima iz **`LC_RPATH`**. Ako u **`LC_RPATH`** postoji više paths, svaka će biti korišćena za pretragu library koju treba učitati. Primer:
- Ako **`LC_LOAD_DYLIB`** sadrži `@rpath/library.dylib`, a **`LC_RPATH`** sadrži `/application/app.app/Contents/Framework/v1/` i `/application/app.app/Contents/Framework/v2/`, oba folder-a će biti korišćena za učitavanje `library.dylib`**.** Ako library ne postoji u `[...]/v1/`, attacker može tamo da je postavi i hijack-uje učitavanje library iz `[...]/v2/`, pošto se prati redosled paths u **`LC_LOAD_DYLIB`**.
- **Rpath paths i libraries** u binaries možete pronaći pomoću: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: To je **path** do direktorijuma koji sadrži **glavni executable file**.
>
> **`@loader_path`**: To je **path** do **directory-ja** koji sadrži **Mach-O binary** sa load command-om.
>
> - Kada se koristi u executable-u, **`@loader_path`** je efektivno isto što i **`@executable_path`**.
> - Kada se koristi u **dylib-u**, **`@loader_path`** daje **path** do **dylib-a**.

Način za **privilege escalation** zloupotrebom ove funkcionalnosti postojao bi u retkom slučaju kada **application** koju izvršava **root** **traži** neku **library u folder-u u koji attacker ima write permissions.**

> [!TIP]
> Dobar **scanner** za pronalaženje **missing libraries** u applications je [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ili [**CLI version**](https://github.com/pandazheng/DylibHijack).\
> Dobar [**report sa technical details**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) o ovoj tehnici možete pronaći [**ovde**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Example**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Zapamtite da se **prethodna Library Validation ograničenja takođe primenjuju** pri izvođenju Dlopen hijacking attacks.

Iz **`man dlopen`**:

- Kada **path ne sadrži slash karakter** (odnosno, samo je leaf name), **dlopen() će pretraživati**. Ako je **`$DYLD_LIBRARY_PATH`** bio postavljen pri pokretanju, dyld će prvo **tražiti u tom direktorijumu**. Zatim, ako calling mach-o file ili main executable navode **`LC_RPATH`**, dyld će **tražiti u tim** directories. Ako je process **unrestricted**, dyld će zatim pretraživati **trenutni working directory**. Na kraju, kod starih binaries, dyld će pokušati neke fallbacks. Ako je **`$DYLD_FALLBACK_LIBRARY_PATH`** bio postavljen pri pokretanju, dyld će pretraživati **te directories**, u suprotnom će dyld tražiti u **`/usr/local/lib/`** (ako je process unrestricted), a zatim u **`/usr/lib/`** (ove informacije su preuzete iz **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Ako ime ne sadrži slash, postoje 2 načina za hijacking:
>
> - Ako je neki **`LC_RPATH`** **writable** (ali se signature proverava, pa je za ovo potrebno i da binary bude unrestricted)
> - Ako je binary **unrestricted**, tada je moguće učitati nešto iz CWD-a (ili zloupotrebiti neku od pomenutih env variables)

- Kada **path izgleda kao framework** path (npr. `/stuff/foo.framework/foo`), ako je **`$DYLD_FRAMEWORK_PATH`** bio postavljen pri pokretanju, dyld će prvo tražiti framework partial path u tom direktorijumu (npr. `foo.framework/foo`). Zatim će dyld pokušati **datu path** takvu kakva jeste (koristeći current working directory za relative paths). Na kraju, kod starih binaries, dyld će pokušati neke fallbacks. Ako je **`$DYLD_FALLBACK_FRAMEWORK_PATH`** bio postavljen pri pokretanju, dyld će pretraživati te directories. U suprotnom, pretraživaće **`/Library/Frameworks`** (na macOS-u ako je process unrestricted), a zatim **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Ako je u pitanju framework path, način za hijack bio bi:
>
> - Ako je process **unrestricted**, zloupotrebom **relative path-a iz CWD-a** i pomenutih env variables (čak i ako u docs nije navedeno da se, kada je process restricted, DYLD\_\* env vars uklanjaju)

- Kada **path sadrži slash, ali nije framework path** (odnosno, puna path ili partial path do dylib-a), dlopen() prvo traži (ako je postavljeno) u **`$DYLD_LIBRARY_PATH`** (koristeći leaf part iz path-a). Zatim dyld **pokušava datu path** (koristeći current working directory za relative paths (ali samo za unrestricted processes)). Na kraju, kod starijih binaries, dyld će pokušati fallbacks. Ako je **`$DYLD_FALLBACK_LIBRARY_PATH`** bio postavljen pri pokretanju, dyld će pretraživati te directories, u suprotnom će tražiti u **`/usr/local/lib/`** (ako je process unrestricted), a zatim u **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Ako ime sadrži slash i nije framework, način za hijack bio bi:
>
> - Ako je binary **unrestricted**, tada je moguće učitati nešto iz CWD-a ili `/usr/local/lib` (ili zloupotrebiti neku od pomenutih env variables)

> [!TIP]
> Napomena: Ne postoje configuration files za **kontrolisanje dlopen pretrage**.
>
> Napomena: Ako je main executable **set\[ug]id binary** ili codesigned sa entitlements, sve environment variables se ignorišu i može se koristiti samo puna path ([proverite DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) za detaljnije informacije).
>
> Napomena: Apple platforms koriste "universal" files za kombinovanje 32-bitnih i 64-bitnih libraries. To znači da ne postoje odvojene 32-bitne i 64-bitne search paths.
>
> Napomena: Na Apple platforms većina OS dylibs je kombinovana u **dyld cache** i ne postoji na disku. Zbog toga pozivanje **`stat()`** radi pre-flight provere da li OS dylib postoji **neće raditi**. Međutim, **`dlopen_preflight()`** koristi iste korake kao **`dlopen()`** za pronalaženje kompatibilnog mach-o file-a.

**Check paths**

Proverimo sve options pomoću sledećeg code-a:
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

Ako **privileged binary/app** (kao što je SUID ili neki binary sa moćnim entitlements) **učitava** library sa **relative path** putanjom (na primer koristeći `@executable_path` ili `@loader_path`) i ako je **Library Validation** onemogućen, moguće je premestiti binary na lokaciju na kojoj bi attacker mogao da **izmeni library učitan pomoću relative path** putanje i zloupotrebi ga za injektovanje koda u proces.

## Uklanjanje `DYLD_*` env variables

Starije verzije `dyld`-a (`dyld2.cpp`) donosile su ovu odluku unutar procesa pomoću `issetugid()`, `hasRestrictedSegment()` i `csops(CS_OPS_STATUS)`. U **trenutnom `dyld`-u odluku delegira AMFI**, a kod se nalazi u `ProcessConfig::Security::Security()` u `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
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
Dve stvari je vredno izdvojiti iz ovoga:

- Uklanjanje se dešava samo na **macOS / Mac Catalyst / DriverKit** — i samo kada AMFI nije odobrio nijednu od opcija `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- AMFI upit koristi sopstvena svojstva izvršne datoteke:
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
`pruneEnvVars()` zatim uklanja **svaku** promenljivu čiji naziv počinje sa `DYLD_` i pomera parametre `apple[]` naniže, tako da ih ni deca ograničenog procesa ne nasleđuju:
```cpp
// For security, setuid programs ignore DYLD_* environment variables.
// Additionally, the DYLD_* environment variables are removed
// from the environment, so that any child processes doesn't see them.
for ( const char* const* s = proc.envp; *s != NULL; s++ ) {
if ( strncmp(*s, "DYLD_", 5) != 0 ) {
*d++ = *s;
}
...
```
> [!TIP]
> Praktična posledica: **`DYLD_*` se uklanja kada je proces ograničen** — setuid/setgid, odeljkom `__RESTRICT/__restrict` ili hardened-runtime/entitled binarnim datotekama kojima AMFI odbija da dodeli path/print flags. Ako proces umesto toga ima samo **library validation** (`CS_REQUIRE_LV`), promenljive opstaju, ali ubačeni dylib mora biti potpisan istim **Team ID**-jem (ili od strane Apple-a), tako da vam je potreban jedan od entitlements koji onemogućavaju library validation da biste zaista ubacili kod.

Pošto je odluka sada na AMFI-ju, najbrži način da saznate šta će određena binarna datoteka dobiti jeste da pogledate na šta se AMFI oslanja — entitlements i signing flags — umesto da posmatrate sam `dyld`:
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
### Sekcija `__RESTRICT` sa segmentom `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Kreirajte novi sertifikat u Keychain-u i upotrebite ga za potpisivanje binarnog fajla:
```bash
# Apply runtime protection
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
> Imajte na umu da čak i ako postoje binarni fajlovi potpisani zastavicama **`0x0(none)`**, oni mogu dinamički dobiti zastavicu **`CS_RESTRICT`** prilikom izvršavanja, pa ova tehnika u njima neće funkcionisati.
>
> Možete proveriti da li proc ima ovu zastavicu pomoću (preuzmite [**csops ovde**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> a zatim proverite da li je zastavica 0x800 omogućena.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / provera `__RESTRICT`)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (pokretanje procesa i ubacivanje biblioteka)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
