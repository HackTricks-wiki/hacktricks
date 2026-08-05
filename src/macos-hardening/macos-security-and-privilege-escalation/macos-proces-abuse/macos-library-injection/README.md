# Wstrzykiwanie bibliotek w macOS

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Kod **dyld jest open source** i można go znaleźć pod adresem [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) oraz pobrać jako archiwum tar za pomocą **URL takiego jak** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Proces Dyld**

Zobacz, jak Dyld ładuje biblioteki wewnątrz plików binarnych:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Działa to podobnie jak [**LD_PRELOAD w Linuxie**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Pozwala wskazać procesowi, który ma zostać uruchomiony, aby załadował określoną bibliotekę ze ścieżki (jeśli zmienna środowiskowa jest włączona).

Technika ta może być również **używana jako technika ASEP**, ponieważ każda zainstalowana aplikacja ma plist o nazwie "Info.plist", który pozwala na **przypisywanie zmiennych środowiskowych** za pomocą klucza `LSEnvironmental`.

> [!TIP]
> Od 2012 roku **Apple znacząco ograniczyło możliwości** **`DYLD_INSERT_LIBRARIES`**. Proces jest uznawany za **restricted** — a następnie `dyld` usuwa ze swojego środowiska każdą zmienną `DYLD_*` — gdy zachodzi którykolwiek z poniższych warunków:
>
> - Plik binarny jest `setuid/setgid`
> - Mach-O zawiera sekcję **`__RESTRICT/__restrict`**
> - Plik binarny jest podpisany z użyciem hardened runtime, a AMFI nie przyznaje mu uprawnień "path/print variables", czyli brakuje mu [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)<sup>[3]</sup>
>   - **Entitlements** pliku binarnego można sprawdzić za pomocą: `codesign -dv --entitlements :- </path/to/bin>`
>
> We współczesnym `dyld` nie jest to już ustalane wyłącznie przez `dyld`: `ProcessConfig::Security::Security()` pyta **AMFI** za pomocą `amfi_check_dyld_policy_self()`, a następnie wywołuje `pruneEnvVars()`. Dokładny kod został omówiony poniżej w sekcji [Prune `DYLD_*` env variables](#prune-dyld_-env-variables).

### Library Validation

Nawet jeśli plik binarny pozwala używać zmiennej środowiskowej **`DYLD_INSERT_LIBRARIES`**, jeżeli sprawdza podpis biblioteki przed jej załadowaniem, nie załaduje niestandardowej biblioteki.

Aby załadować niestandardową bibliotekę, plik binarny musi mieć **jedno z następujących entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

lub plik binarny **nie powinien** mieć **flagi hardened runtime** ani **flagi library validation**.

Możesz sprawdzić, czy plik binarny ma **hardened runtime**, za pomocą `codesign --display --verbose <bin>`, sprawdzając flagę runtime w **`CodeDirectory`**, na przykład: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Możesz również załadować bibliotekę, jeśli jest **podpisana tym samym certyfikatem co plik binarny**.

Przykład wykorzystania tej funkcji i sprawdzania ograniczeń znajdziesz tutaj:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Pamiętaj, że **wcześniejsze ograniczenia Library Validation również mają zastosowanie** podczas przeprowadzania ataków Dylib hijacking.

Podobnie jak w Windows, w MacOS można również **przejąć dylib**, aby nakłonić **aplikacje** do **wykonania** **dowolnego** **kodu** (w rzeczywistości zwykły użytkownik może nie być w stanie tego zrobić, ponieważ może być wymagane uprawnienie TCC do zapisu wewnątrz pakietu `.app` i przejęcia biblioteki).\
Jednak sposób, w jaki aplikacje **MacOS** **ładują** biblioteki, jest **bardziej ograniczony** niż w Windows. Oznacza to, że twórcy **malware** nadal mogą używać tej techniki w celu **ukrycia**, ale prawdopodobieństwo wykorzystania jej do eskalacji uprawnień jest znacznie niższe.

Po pierwsze, **pliki binarne MacOS częściej wskazują pełną ścieżkę** do bibliotek, które mają zostać załadowane. Po drugie, **MacOS nigdy nie przeszukuje** folderów znajdujących się w **$PATH** w poszukiwaniu bibliotek.

Główna część **kodu** związana z tą funkcją znajduje się w **`ImageLoader::recursiveLoadLibraries`** w pliku `ImageLoader.cpp`.

Istnieją **4 różne Commands nagłówka**, których macho binary może używać do ładowania bibliotek:

- Polecenie **`LC_LOAD_DYLIB`** jest typowym poleceniem służącym do ładowania dylib.
- Polecenie **`LC_LOAD_WEAK_DYLIB`** działa jak poprzednie, ale jeśli dylib nie zostanie znaleziona, wykonywanie jest kontynuowane bez błędu.
- Polecenie **`LC_REEXPORT_DYLIB`** proxy (lub ponownie eksportuje) symbole z innej biblioteki.
- Polecenie **`LC_LOAD_UPWARD_DYLIB`** jest używane, gdy dwie biblioteki zależą od siebie (nazywa się to _upward dependency_).

Istnieją jednak **2 typy Dylib hijacking**:

- **Brakujące weak linked libraries**: Oznacza to, że aplikacja spróbuje załadować bibliotekę, która nie istnieje, skonfigurowaną za pomocą **LC_LOAD_WEAK_DYLIB**. Następnie **jeśli atakujący umieści dylib w oczekiwanym miejscu, zostanie ona załadowana**.
- Fakt, że link jest "weak", oznacza, że aplikacja będzie działać dalej, nawet jeśli biblioteka nie zostanie znaleziona.
- **Kod związany** z tą funkcją znajduje się w `ImageLoaderMachO::doGetDependentLibraries` w pliku `ImageLoaderMachO.cpp`, gdzie `lib->required` ma wartość `false` tylko wtedy, gdy `LC_LOAD_WEAK_DYLIB` ma wartość true.
- **Znajdź weak linked libraries** w plikach binarnych za pomocą (poniżej znajduje się przykład tworzenia bibliotek hijacking):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Skonfigurowane z użyciem @rpath**: Pliki binarne Mach-O mogą zawierać polecenia **`LC_RPATH`** i **`LC_LOAD_DYLIB`**. Na podstawie **wartości** tych poleceń **biblioteki** będą **ładowane** z **różnych katalogów**.
- **`LC_RPATH`** zawiera ścieżki niektórych folderów używanych przez plik binarny do ładowania bibliotek.
- **`LC_LOAD_DYLIB`** zawiera ścieżkę do konkretnych bibliotek, które mają zostać załadowane. Ścieżki te mogą zawierać **`@rpath`**, które zostanie **zastąpione** wartościami z **`LC_RPATH`**. Jeśli w **`LC_RPATH`** znajduje się kilka ścieżek, każda z nich zostanie użyta do wyszukania biblioteki do załadowania. Przykład:
- Jeśli **`LC_LOAD_DYLIB`** zawiera `@rpath/library.dylib`, a **`LC_RPATH`** zawiera `/application/app.app/Contents/Framework/v1/` oraz `/application/app.app/Contents/Framework/v2/`, oba foldery zostaną użyte do załadowania `library.dylib`**.** Jeśli biblioteka nie istnieje w `[...]/v1/`, a atakujący może ją tam umieścić, możliwe jest przejęcie ładowania biblioteki z `[...]/v2/`, ponieważ zachowywana jest kolejność ścieżek w **`LC_LOAD_DYLIB`**.
- **Znajdź ścieżki rpath i biblioteki** w plikach binarnych za pomocą: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Jest to **ścieżka** do katalogu zawierającego **główny plik wykonywalny**.
>
> **`@loader_path`**: Jest to **ścieżka** do **katalogu** zawierającego **plik binarny Mach-O**, który zawiera polecenie load.
>
> - W przypadku użycia w pliku wykonywalnym **`@loader_path`** jest efektywnie tym samym co **`@executable_path`**.
> - W przypadku użycia w dylib **`@loader_path`** wskazuje **ścieżkę** do **dylib**.

Sposobem na **eskalację uprawnień** poprzez wykorzystanie tej funkcji byłby rzadki przypadek, w którym **aplikacja** uruchamiana **przez** **root** szuka **biblioteki w folderze, do którego atakujący ma uprawnienia zapisu**.

> [!TIP]
> Dobrym **skanerem** do znajdowania **brakujących bibliotek** w aplikacjach jest [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) lub jego [**wersja CLI**](https://github.com/pandazheng/DylibHijack).\
> Dobry [**raport ze szczegółami technicznymi**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) dotyczącymi tej techniki znajduje się [**tutaj**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Przykład**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Pamiętaj, że **wcześniejsze ograniczenia Library Validation również mają zastosowanie** podczas przeprowadzania ataków Dlopen hijacking.

Z **`man dlopen`**:

- Gdy ścieżka **nie zawiera znaku ukośnika** (czyli jest tylko nazwą końcową), **dlopen() przeprowadzi wyszukiwanie**. Jeśli podczas uruchamiania ustawiono **`$DYLD_LIBRARY_PATH`**, dyld najpierw **sprawdzi ten katalog**. Następnie, jeśli wywołujący plik mach-o lub główny plik wykonywalny określa **`LC_RPATH`**, dyld **sprawdzi te** katalogi. Następnie, jeśli proces jest **unrestricted**, dyld przeszuka bieżący katalog roboczy. Na końcu, w przypadku starszych plików binarnych, dyld wypróbuje pewne ścieżki awaryjne. Jeśli podczas uruchamiania ustawiono **`$DYLD_FALLBACK_LIBRARY_PATH`**, dyld przeszuka **te katalogi**, w przeciwnym razie dyld sprawdzi **`/usr/local/lib/`** (jeśli proces jest unrestricted), a następnie **`/usr/lib/`** (informacje pochodzą z **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(if unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (if unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Jeśli nazwa nie zawiera ukośników, hijacking można przeprowadzić na 2 sposoby:
>
> - Jeśli dowolne **`LC_RPATH`** jest zapisywalne (ale podpis jest sprawdzany, więc do tego wymagane jest również, aby plik binarny był unrestricted)
> - Jeśli plik binarny jest **unrestricted**, możliwe jest załadowanie czegoś z CWD (lub wykorzystanie jednej ze wspomnianych zmiennych środowiskowych)

- Gdy ścieżka **wygląda jak** ścieżka frameworka (np. `/stuff/foo.framework/foo`), jeśli podczas uruchamiania ustawiono **`$DYLD_FRAMEWORK_PATH`**, dyld najpierw sprawdzi w tym katalogu **częściową ścieżkę frameworka** (np. `foo.framework/foo`). Następnie dyld spróbuje użyć **podanej ścieżki bez zmian** (używając bieżącego katalogu roboczego dla ścieżek względnych). Na końcu, w przypadku starszych plików binarnych, dyld wypróbuje pewne ścieżki awaryjne. Jeśli podczas uruchamiania ustawiono **`$DYLD_FALLBACK_FRAMEWORK_PATH`**, dyld przeszuka te katalogi. W przeciwnym razie przeszuka **`/Library/Frameworks`** (w macOS, jeśli proces jest unrestricted), a następnie **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (if unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Jeśli jest to ścieżka frameworka, sposobem na jej hijacking byłoby:
>
> - Jeśli proces jest **unrestricted**, wykorzystanie **ścieżki względnej z CWD** lub wspomnianych zmiennych środowiskowych (nawet jeśli dokumentacja tego nie podaje, w przypadku restricted procesu zmienne środowiskowe DYLD\_\* są usuwane)

- Gdy ścieżka **zawiera ukośnik, ale nie jest ścieżką frameworka** (czyli jest pełną lub częściową ścieżką do dylib), dlopen() najpierw sprawdza (jeśli ustawiono) **`$DYLD_LIBRARY_PATH`** (z końcową częścią ścieżki). Następnie dyld **próbuje użyć podanej ścieżki** (używając bieżącego katalogu roboczego dla ścieżek względnych, ale tylko w przypadku procesów unrestricted). Na końcu, w przypadku starszych plików binarnych, dyld wypróbuje ścieżki awaryjne. Jeśli podczas uruchamiania ustawiono **`$DYLD_FALLBACK_LIBRARY_PATH`**, dyld przeszuka te katalogi, w przeciwnym razie dyld sprawdzi **`/usr/local/lib/`** (jeśli proces jest unrestricted), a następnie **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. supplied path (using current working directory for relative paths if unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (if unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Jeśli nazwa zawiera ukośniki i nie jest ścieżką frameworka, sposobem na hijacking byłoby:
>
> - Jeśli plik binarny jest **unrestricted**, możliwe jest załadowanie czegoś z CWD lub `/usr/local/lib` (albo wykorzystanie jednej ze wspomnianych zmiennych środowiskowych)

> [!TIP]
> Uwaga: Nie istnieją **żadne** pliki konfiguracyjne do **sterowania wyszukiwaniem przez dlopen**.
>
> Uwaga: Jeśli główny plik wykonywalny jest plikiem binarnym `set\[ug]id` lub jest podpisany kodem z entitlements, wszystkie zmienne środowiskowe są ignorowane i można użyć wyłącznie pełnej ścieżki ([sprawdź ograniczenia DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions), aby uzyskać więcej informacji).
>
> Uwaga: Platformy Apple używają plików "universal" do łączenia bibliotek 32-bitowych i 64-bitowych. Oznacza to, że nie istnieją oddzielne ścieżki wyszukiwania dla bibliotek 32-bitowych i 64-bitowych.
>
> Uwaga: Na platformach Apple większość systemowych dylib jest połączona w **dyld cache** i nie istnieje na dysku. Dlatego wywołanie **`stat()`** w celu wstępnego sprawdzenia, czy systemowa dylib istnieje, **nie zadziała**. Natomiast **`dlopen_preflight()`** używa tych samych kroków co **`dlopen()`**, aby znaleźć kompatybilny plik mach-o.

**Sprawdzanie ścieżek**

Sprawdźmy wszystkie opcje za pomocą następującego kodu:
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
Jeśli skompilujesz i uruchomisz ten program, zobaczysz, **gdzie bezskutecznie wyszukiwano każdej biblioteki**. Możesz także **filtrować logi FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Relative Path Hijacking

Jeśli **uprzywilejowany binary/app** (na przykład SUID lub dowolny binary z potężnymi entitlementami) **ładuje bibliotekę ze ścieżki względnej** (na przykład za pomocą `@executable_path` lub `@loader_path`) i ma wyłączoną funkcję **Library Validation**, możliwe może być przeniesienie binary do lokalizacji, w której attacker będzie mógł **zmodyfikować bibliotekę ładowaną ze ścieżki względnej** i wykorzystać ją do wstrzyknięcia kodu do procesu.

## Prune `DYLD_*` env variables

Starsze wersje `dyld` (`dyld2.cpp`) podejmowały tę decyzję wewnątrz procesu za pomocą `issetugid()`, `hasRestrictedSegment()` i `csops(CS_OPS_STATUS)`. W **obecnym `dyld` decyzja jest delegowana do AMFI**, a kod znajduje się w `ProcessConfig::Security::Security()` w `dyld/DyldProcessConfig.cpp`:<sup>[1]</sup>
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
Z tego warto wyodrębnić dwie kwestie:

- Usuwanie ma miejsce wyłącznie w **macOS / Mac Catalyst / DriverKit** — i tylko wtedy, gdy AMFI nie przyznało żadnego z uprawnień `allowEnvVarsPrint`, `allowEnvVarsPath`, `allowEnvVarsSharedCache`.
- Zapytanie AMFI otrzymuje właściwości samego pliku wykonywalnego:
```cpp
uint64_t amfiFlags = sys.amfiFlags(proc.mainExecutableHdr->isRestricted(),
proc.mainExecutableHdr->isFairPlayEncrypted(fpTextOffset, fpSize));
```
gdzie `isRestricted()` jest dosłownie sprawdzeniem segmentu `__RESTRICT` (`mach_o/UnsafeHeader.cpp`):<sup>[2]</sup>
```cpp
bool UnsafeHeader::isRestricted() const
{
return this->hasSection("__RESTRICT", "__restrict");
}
```
`pruneEnvVars()` następnie usuwa **każdą** zmienną, której nazwa zaczyna się od `DYLD_`, i przesuwa parametry `apple[]` w dół, dzięki czemu procesy potomne procesu objętego ograniczeniami również ich nie dziedziczą:
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
> Praktyczna konsekwencja: **`DYLD_*` jest usuwane, gdy proces jest ograniczony** — przez setuid/setgid, sekcję `__RESTRICT/__restrict` albo hardened-runtime/entitled binaries, którym AMFI odmawia przyznania flag path/print. Jeśli proces ma tylko **library validation** (`CS_REQUIRE_LV`), zmienne pozostają, ale wstrzykiwany dylib musi być podpisany przez **ten sam Team ID** (albo przez Apple), więc do faktycznego załadowania kodu potrzebujesz jednego z entitlements wyłączających library validation.

Ponieważ decyzja należy teraz do AMFI, najszybszym sposobem sprawdzenia, co otrzyma dany binary, jest sprawdzenie tego, na czym opiera się AMFI — entitlements i flag podpisu — zamiast samego `dyld`:
```bash
BIN=/path/to/bin
codesign -d --entitlements :- "$BIN" 2>/dev/null | \
egrep "allow-dyld-environment-variables|disable-library-validation|clear-library-validation"
codesign -dvvv "$BIN" 2>&1 | egrep "flags=|TeamIdentifier="
otool -l "$BIN" | grep -A2 __RESTRICT
```
## Sprawdzanie ograniczeń

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
### Sekcja `__RESTRICT` z segmentem `__restrict`
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### Hardened runtime

Utwórz nowy certyfikat w Keychain i użyj go do podpisania pliku binarnego:
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
> Należy pamiętać, że nawet jeśli istnieją binary podpisane z flagami **`0x0(none)`**, mogą one dynamicznie otrzymać flagę **`CS_RESTRICT`** podczas uruchamiania, dlatego ta technika nie będzie na nich działać.
>
> Możesz sprawdzić, czy proc ma tę flagę, za pomocą (pobierz [**csops tutaj**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> następnie sprawdź, czy flaga 0x800 jest włączona.

## References

- [1] [dyld — `dyld/DyldProcessConfig.cpp` (`ProcessConfig::Security`, `getAMFI`, `pruneEnvVars`)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/DyldProcessConfig.cpp)
- [2] [dyld — `mach_o/UnsafeHeader.cpp` (`isRestricted()` / `__RESTRICT` check)](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/UnsafeHeader.cpp)
- [3] [Apple Developer — `com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
- [4] [dyld — `dyld/dyldMain.cpp` (process startup and library insertion)](https://github.com/apple-oss-distributions/dyld/blob/main/dyld/dyldMain.cpp)

{{#include ../../../../banners/hacktricks-training.md}}
