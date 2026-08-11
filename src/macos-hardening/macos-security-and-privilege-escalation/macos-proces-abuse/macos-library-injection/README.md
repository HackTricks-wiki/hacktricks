# macOS Library Injection

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Kod **dyld** je open source i može se pronaći na [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) i može se preuzeti kao tar arhiva pomoću **URL-a kao što je** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Dyld Process**

Pogledajte kako Dyld učitava biblioteke unutar binarnih datoteka na:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Ovo je slično mehanizmu [**LD_PRELOAD na Linuxu**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Omogućava da se procesu koji će biti pokrenut navede učitavanje određene biblioteke sa određene putanje (ako je env var omogućen)<sup>[[4]](#references)</sup>

Ova tehnika se takođe može **koristiti kao ASEP tehnika**, jer svaka instalirana aplikacija ima plist pod nazivom "Info.plist", koji omogućava **dodeljivanje environmental variables** pomoću ključa pod nazivom `LSEnvironmental`.

> [!TIP]
> Od 2012. godine **Apple je drastično smanjio moć** promenljive **`DYLD_INSERT_LIBRARIES`**. Proces se smatra **restricted** — nakon čega `dyld` briše svaku `DYLD_*` promenljivu iz svog okruženja — kada važi bilo šta od sledećeg:
>
> - Binarna datoteka je `setuid/setgid`
> - Mach-O ima odeljak **`__RESTRICT/__restrict`**
> - Binarna datoteka je potpisana pomoću hardened runtime-a, a AMFI joj ne dodeljuje dozvole "path/print variables", odnosno nedostaje joj [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[[3]](#references)</sup>
>   - **Entitlements** binarne datoteke možete proveriti pomoću: `codesign -dv --entitlements :- </path/to/bin>`
>
> U aktuelnom `dyld`-u ovo više ne određuje samo `dyld`: `ProcessConfig::Security::Security()` poziva **AMFI** preko `amfi_check_dyld_policy_self()`, a zatim poziva `pruneEnvVars()`. Tačan kod je objašnjen u odeljku [Prune `DYLD_*` env variables](#prune-dyld_-env-variables) u nastavku.

### Library Validation

Čak i ako binarna datoteka dozvoljava **`DYLD_INSERT_LIBRARIES`** env var, neće učitati custom biblioteku ako proverava njen potpis.

Da bi učitala custom biblioteku, binarna datoteka mora imati **jedan od sledećih entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

ili binarna datoteka **ne sme** imati **hardened runtime flag** ili **library validation flag**.

Da li binarna datoteka ima **hardened runtime** možete proveriti pomoću `codesign --display --verbose <bin>`, proverom runtime flag-a u **`CodeDirectory`**, kao u primeru: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Biblioteku možete učitati i ako je **potpisana istim sertifikatom kao binarna datoteka**.

Primer kako ovo (zlo)upotrebiti i proveriti ograničenja pronađite na:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Imajte na umu da se **prethodna Library Validation ograničenja takođe primenjuju** na izvođenje Dylib hijacking napada.

Kao i na Windowsu, na macOS-u možete **hijack-ovati dylib-ove** kako biste naterali **aplikacije da izvrše proizvoljan kod**. Iz regularnog korisničkog naloga to možda neće biti moguće, jer pisanje unutar `.app` bundle-a radi hijack-ovanja biblioteke može zahtevati TCC dozvolu.\
Međutim, način na koji **macOS** aplikacije **učitavaju** biblioteke je **ograničeniji** nego na Windowsu. Developeri malware-a i dalje mogu koristiti ovu tehniku za **stealth**, ali je njena zloupotreba za escalation privileges mnogo manje verovatna.

Pre svega, **češće** se dešava da **MacOS binarne datoteke navode punu putanju** do biblioteka koje treba učitati. Drugo, **MacOS nikada ne pretražuje** foldere iz **$PATH** za biblioteke.

**Glavni** deo **koda** povezanog sa ovom funkcionalnošću nalazi se u funkciji **`ImageLoader::recursiveLoadLibraries`** u datoteci `ImageLoader.cpp`.

Postoje **4 različite header Commands** koje macho binarna datoteka može koristiti za učitavanje biblioteka:

- Komanda **`LC_LOAD_DYLIB`** je uobičajena komanda za učitavanje dylib-a.
- Komanda **`LC_LOAD_WEAK_DYLIB`** radi kao prethodna, ali ako dylib nije pronađen, izvršavanje se nastavlja bez greške.
- Komanda **`LC_REEXPORT_DYLIB`** prosleđuje (ili ponovo eksportuje) simbole iz druge biblioteke.
- Komanda **`LC_LOAD_UPWARD_DYLIB`** koristi se kada dve biblioteke zavise jedna od druge (to se naziva _upward dependency_).

Međutim, postoje **2 tipa dylib hijacking-a**:

- **Missing weak linked libraries**: To znači da će aplikacija pokušati da učita biblioteku koja ne postoji, a konfigurisana je pomoću **LC_LOAD_WEAK_DYLIB**. Zatim, **ako attacker postavi dylib tamo gde se očekuje, ona će biti učitana**.
- Činjenica da je link "weak" znači da će aplikacija nastaviti da radi čak i ako biblioteka nije pronađena.
- **Kod povezan** sa ovim nalazi se u funkciji `ImageLoaderMachO::doGetDependentLibraries` datoteke `ImageLoaderMachO.cpp`, gde je `lib->required` samo `false` kada je **LC_LOAD_WEAK_DYLIB** `true`.
- **Weak linked libraries** u binarnim datotekama pronađite pomoću sledeće komande (kasnije imate primer kako da kreirate hijacking biblioteke):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Configured with @rpath**: Mach-O binarne datoteke mogu imati komande **`LC_RPATH`** i **`LC_LOAD_DYLIB`**. Na osnovu **vrednosti** tih komandi, **biblioteke** će biti **učitavane** iz **različitih direktorijuma**.
- **`LC_RPATH`** sadrži putanje do foldera koji se koriste za učitavanje biblioteka pomoću binarne datoteke.
- **`LC_LOAD_DYLIB`** sadrži putanju do konkretnih biblioteka koje treba učitati. Ove putanje mogu sadržati **`@rpath`**, koji će biti **zamenjen** vrednostima iz **`LC_RPATH`**. Ako u **`LC_RPATH`** postoji više putanja, svaka će biti korišćena za pretragu biblioteke koju treba učitati. Primer:
- Ako **`LC_LOAD_DYLIB`** sadrži `@rpath/library.dylib`, a **`LC_RPATH`** sadrži `/application/app.app/Contents/Framework/v1/` i `/application/app.app/Contents/Framework/v2/`, oba foldera će biti korišćena za učitavanje `library.dylib`**.** Ako biblioteka ne postoji u `[...]/v1/`, attacker bi mogao da je postavi tamo kako bi hijack-ovao učitavanje biblioteke iz `[...]/v2/`, jer se prati redosled putanja u **`LC_LOAD_DYLIB`**.
- **Rpath putanje i biblioteke** u binarnim datotekama pronađite pomoću: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Predstavlja **putanju** do direktorijuma koji sadrži **glavnu izvršnu datoteku**.
>
> **`@loader_path`**: Predstavlja **putanju** do **direktorijuma** koji sadrži **Mach-O binarnu datoteku** sa load komandom.
>
> - Kada se koristi u executable-u, **`@loader_path`** je praktično isto što i **`@executable_path`**.
> - Kada se koristi u **dylib-u**, **`@loader_path`** daje **putanju** do **dylib-a**.

Način za **escalate privileges** zloupotrebom ove funkcionalnosti postojao bi u retkom slučaju kada **aplikacija** koju izvršava **root** **traži** neku **biblioteku u folderu u koji attacker ima dozvole upisa**.

> [!TIP]
> Dobar **scanner** za pronalaženje **missing libraries** u aplikacijama je [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) ili [**CLI verzija**](https://github.com/pandazheng/DylibHijack).\
> Dobar **izveštaj sa tehničkim detaljima** o ovoj tehnici možete pronaći [**ovde**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Primer**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Imajte na umu da se **prethodna Library Validation ograničenja takođe primenjuju** na izvođenje Dlopen hijacking napada.

Iz **`man dlopen`**:

- Kada **path ne sadrži slash karakter** (odnosno, samo je leaf name), **dlopen() će pretraživati**. Ako je pri pokretanju postavljen **`$DYLD_LIBRARY_PATH`**, dyld će prvo **tražiti u tom direktorijumu**. Zatim, ako calling mach-o fajl ili glavna izvršna datoteka navode **`LC_RPATH`**, dyld će **tražiti u tim** direktorijumima. Zatim će, ako je proces **unrestricted**, dyld pretražiti **trenutni working directory**. Na kraju će, za stare binarne datoteke, dyld pokušati fallback putanje. Ako je pri pokretanju postavljen **`$DYLD_FALLBACK_LIBRARY_PATH`**, dyld će pretražiti **te direktorijume**, u suprotnom će dyld tražiti u **`/usr/local/lib/`** (ako je proces unrestricted), a zatim u **`/usr/lib/`** (ove informacije preuzete su iz **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Ako ime ne sadrži slash-ove, hijacking se može izvršiti na 2 načina:
>
> - Ako je neki **`LC_RPATH`** writable (ali se potpis proverava, pa je za ovo binarna datoteka takođe potrebna unrestricted)
> - Ako je binarna datoteka **unrestricted**, pa je moguće učitati nešto iz CWD-a (ili zloupotrebom neke od pomenutih env variables)

- Kada path **izgleda kao framework** path (npr. `/stuff/foo.framework/foo`), ako je pri pokretanju postavljen **`$DYLD_FRAMEWORK_PATH`**, dyld će prvo tražiti framework partial path (npr. `foo.framework/foo`) u tom direktorijumu. Zatim će dyld pokušati **prosleđenu putanju kao-is** (koristeći current working directory za relativne putanje). Na kraju će, za stare binarne datoteke, dyld pokušati fallback putanje. Ako je pri pokretanju postavljen **`$DYLD_FALLBACK_FRAMEWORK_PATH`**, dyld će pretražiti te direktorijume. U suprotnom će pretražiti **`/Library/Frameworks`** (na macOS-u ako je proces unrestricted), a zatim **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Ako je u pitanju framework path, hijacking se može izvršiti:
>
> - Ako je proces **unrestricted**, zloupotrebom **relativne putanje iz CWD-a** ili pomenutih env variables (čak i ako u dokumentaciji nije navedeno, ako je proces restricted, DYLD\_\* env vars se uklanjaju)

- Kada **path sadrži slash, ali nije framework path** (odnosno, puna ili delimična putanja do dylib-a), dlopen() prvo traži (ako je postavljen) u **`$DYLD_LIBRARY_PATH`** (koristeći leaf deo putanje). Zatim dyld **pokušava prosleđenu putanju** (koristeći current working directory za relativne putanje, ali samo za unrestricted procese). Na kraju će, za starije binarne datoteke, dyld pokušati fallback putanje. Ako je pri pokretanju postavljen **`$DYLD_FALLBACK_LIBRARY_PATH`**, dyld će pretražiti te direktorijume, u suprotnom će tražiti u **`/usr/local/lib/`** (ako je proces unrestricted), a zatim u **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Ako ime sadrži slash-ove, ali nije framework, hijacking se može izvršiti:
>
> - Ako je binarna datoteka **unrestricted**, pa je moguće učitati nešto iz CWD-a ili `/usr/local/lib` (ili zloupotrebom neke od pomenutih env variables)

> [!TIP]
> Napomena: Ne postoje configuration files za **kontrolu dlopen pretrage**.
>
> Napomena: Ako je glavna izvršna datoteka **set\[ug]id binarna datoteka ili codesigned sa entitlements**, sve environment variables se ignorišu i može se koristiti samo puna putanja ([proverite DYLD_INSERT_LIBRARIES restrictions](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions) za detaljnije informacije).
>
> Napomena: Apple platforme koriste "universal" fajlove za kombinovanje 32-bitnih i 64-bitnih biblioteka. To znači da ne postoje odvojene 32-bitne i 64-bitne search paths.
>
> Napomena: Na Apple platformama većina OS dylib-ova objedinjena je u dyld cache-u i ne postoji na disku. Zato pozivanje **`stat()`** radi provere da li OS dylib postoji **neće raditi**. Međutim, **`dlopen_preflight()`** koristi iste korake kao **`dlopen()`** za pronalaženje kompatibilnog mach-o fajla.

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

Ako **privileged binary/app** (kao što je SUID ili neki binary sa moćnim entitlements) **učitava library preko relativne putanje** (na primer koristeći `@executable_path` ili `@loader_path`) i ima onemogućen **Library Validation**, moglo bi biti moguće premestiti binary na lokaciju na kojoj bi napadač mogao da **izmeni library učitan preko relativne putanje** i zloupotrebi ga za ubacivanje koda u proces.

## Prune `DYLD_*` env variables

Starije verzije `dyld` (`dyld2.cpp`) donosile su ovu odluku unutar procesa pomoću `issetugid()`, `hasRestrictedSegment()` i `csops(CS_OPS_STATUS)`. U **trenutnom `dyld`-u odluku donosi AMFI**, a kod se nalazi u `ProcessConfig::Security::Security()` u `dyld/DyldProcessConfig.cpp`:<sup>[[1]](#references)</sup>
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

- Pruning se dešava samo na **macOS / Mac Catalyst / DriverKit** — i samo kada AMFI nije odobrio nijednu od opcija `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- AMFI upit koristi sopstvena svojstva izvršne datoteke:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
gde je `isRestricted()` doslovno provera segmenta `__RESTRICT` (`mach_o/UnsafeHeader.cpp`):<sup>[[2]](#references)</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` zatim uklanja **svaku** promenljivu čije ime počinje sa `DYLD_` i pomera parametre `apple[]` nadole, tako da ih ni potomci ograničenog procesa ne nasleđuju:
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
> Praktična posledica: **`DYLD_*` se uklanja kada je proces ograničen** — setuid/setgid, odeljkom `__RESTRICT/__restrict` ili hardened-runtime/entitled binarnim fajlovima kojima AMFI odbija da dodeli path/print flags. Ako proces umesto toga ima samo **library validation** (`CS_REQUIRE_LV`), promenljive ostaju, ali umetnuti dylib mora biti potpisan istim **Team ID**-jem (ili od strane Apple-a), tako da su vam potrebni entitlements za onemogućavanje library validation-a da bi kod zaista bio učitan.

Pošto je odluka sada na AMFI-ju, najbrži način da saznate šta će određeni binarni fajl dobiti jeste da proverite na šta se AMFI oslanja — entitlements i signing flags — umesto samog `dyld`-a:
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

Kreirajte novi sertifikat u Keychain-u i upotrebite ga za potpisivanje binarne datoteke:
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
> Imajte na umu da čak i ako postoje binariji potpisani zastavicama **`0x0(none)`**, oni mogu dinamički dobiti zastavicu **`CS_RESTRICT`** prilikom izvršavanja, pa ova tehnika neće raditi u njima.
>
> Možete proveriti da li proc ima ovu zastavicu pomoću (preuzmite [**csops here**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> a zatim proverite da li je zastavica 0x800 omogućena.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` check)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (pokretanje procesa i umetanje library-ja)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)
{{#include ../../../../banners/hacktricks-training.md}}
