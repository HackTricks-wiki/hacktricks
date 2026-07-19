# Wstrzykiwanie bibliotek w macOS

{{#include ../../../../banners/hacktricks-training.md}}

> [!CAUTION]
> Kod **dyld jest open source** i można go znaleźć pod adresem [https://opensource.apple.com/source/dyld/](https://opensource.apple.com/source/dyld/) oraz pobrać jako archiwum tar za pomocą **URL takiego jak** [https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz](https://opensource.apple.com/tarballs/dyld/dyld-852.2.tar.gz)

## **Proces Dyld**

Sprawdź, jak Dyld ładuje biblioteki wewnątrz plików binarnych:


{{#ref}}
macos-dyld-process.md
{{#endref}}

## **DYLD_INSERT_LIBRARIES**

Działa to podobnie jak [**LD_PRELOAD on Linux**](../../../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#ld_preload). Pozwala wskazać proces, który zostanie uruchomiony, aby załadować określoną bibliotekę ze wskazanej ścieżki (jeśli zmienna środowiskowa jest włączona).

Technika ta może być również **używana jako technika ASEP**, ponieważ każda zainstalowana aplikacja ma plik plist o nazwie "Info.plist", który umożliwia **przypisywanie zmiennych środowiskowych** za pomocą klucza o nazwie `LSEnvironmental`.

> [!TIP]
> Od 2012 roku **Apple drastycznie ograniczyło możliwości** **`DYLD_INSERT_LIBRARIES`**.
>
> Przejdź do kodu i **sprawdź `src/dyld.cpp`**. W funkcji **`pruneEnvironmentVariables`** widać, że zmienne **`DYLD_*`** są usuwane.
>
> W funkcji **`processRestricted`** ustawiany jest powód ograniczenia. Sprawdzając ten kod, można zobaczyć, że powody to:
>
> - Plik binarny jest `setuid/setgid`
> - Istnienie sekcji `__RESTRICT/__restrict` w pliku binarnym macho.
> - Oprogramowanie ma entitlements (hardened runtime) bez entitlementu [`com.apple.security.cs.allow-dyld-environment-variables`](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_security_cs_allow-dyld-environment-variables)
>  - Sprawdź **entitlements** pliku binarnego za pomocą: `codesign -dv --entitlements :- </path/to/bin>`
>
> W nowszych wersjach tę logikę można znaleźć w drugiej części funkcji **`configureProcessRestrictions`.** Jednak w nowszych wersjach wykonywane są **początkowe sprawdzenia funkcji** (możesz usunąć instrukcje if związane z iOS lub symulacją, ponieważ nie będą używane w macOS).

### Library Validation

Nawet jeśli plik binarny pozwala używać zmiennej środowiskowej **`DYLD_INSERT_LIBRARIES`**, jeśli sprawdza sygnaturę ładowanej biblioteki, nie załaduje niestandardowej biblioteki.

Aby załadować niestandardową bibliotekę, plik binarny musi mieć **jeden z następujących entitlements**:

- [`com.apple.security.cs.disable-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.security.cs.disable-library-validation)
- [`com.apple.private.security.clear-library-validation`](../../macos-security-protections/macos-dangerous-entitlements.md#com.apple.private.security.clear-library-validation)

lub plik binarny **nie powinien** mieć **flagi hardened runtime** ani **flagi library validation**.

Możesz sprawdzić, czy plik binarny ma **hardened runtime**, za pomocą `codesign --display --verbose <bin>`, sprawdzając flagę runtime w **`CodeDirectory`**, np.: **`CodeDirectory v=20500 size=767 flags=0x10000(runtime) hashes=13+7 location=embedded`**

Możesz również załadować bibliotekę, jeśli jest **podpisana tym samym certyfikatem co plik binarny**.

Przykład wykorzystania tej funkcji i sprawdzenia ograniczeń znajdziesz w:


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dylib Hijacking

> [!CAUTION]
> Pamiętaj, że **wcześniej opisane ograniczenia Library Validation mają również zastosowanie** podczas przeprowadzania ataków Dylib hijacking.

Podobnie jak w Windows, w macOS można również **przejmować dylibs**, aby spowodować, że **aplikacje** będą **wykonywać** **dowolny** **kod** (w praktyce zwykły użytkownik może nie mieć takiej możliwości, ponieważ do zapisu wewnątrz pakietu `.app` i przejęcia biblioteki może być wymagane uprawnienie TCC).\
Jednak sposób, w jaki aplikacje **macOS** **ładują** biblioteki, jest **bardziej ograniczony** niż w Windows. Oznacza to, że twórcy **malware** nadal mogą używać tej techniki w celu zapewnienia **stealth**, ale prawdopodobieństwo **wykorzystania jej do eskalacji uprawnień jest znacznie mniejsze**.

Po pierwsze, **pliki binarne macOS częściej zawierają pełną ścieżkę** do ładowanych bibliotek. Po drugie, **macOS nigdy nie wyszukuje** bibliotek w folderach **$PATH**.

Główna część **kodu** powiązanego z tą funkcją znajduje się w **`ImageLoader::recursiveLoadLibraries`** w pliku `ImageLoader.cpp`.

Istnieją **4 różne polecenia nagłówka**, których plik binarny macho może używać do ładowania bibliotek:

- Polecenie **`LC_LOAD_DYLIB`** jest standardowym poleceniem służącym do ładowania dylib.
- Polecenie **`LC_LOAD_WEAK_DYLIB`** działa tak jak poprzednie, ale jeśli dylib nie zostanie znaleziona, wykonanie będzie kontynuowane bez błędu.
- Polecenie **`LC_REEXPORT_DYLIB`** przekazuje (lub ponownie eksportuje) symbole z innej biblioteki.
- Polecenie **`LC_LOAD_UPWARD_DYLIB`** jest używane, gdy dwie biblioteki zależą od siebie (nazywa się to _upward dependency_).

Istnieją jednak **2 typy Dylib hijacking**:

- **Brakujące biblioteki weak linked**: oznacza to, że aplikacja spróbuje załadować bibliotekę, która nie istnieje, skonfigurowaną za pomocą **LC_LOAD_WEAK_DYLIB**. Następnie, **jeśli attacker umieści dylib w oczekiwanym miejscu, zostanie ona załadowana**.
- Fakt, że link jest "weak", oznacza, że aplikacja będzie działać dalej, nawet jeśli biblioteka nie zostanie znaleziona.
- **Kod związany** z tą funkcją znajduje się w funkcji `ImageLoaderMachO::doGetDependentLibraries` pliku `ImageLoaderMachO.cpp`, gdzie `lib->required` ma wartość `false` tylko wtedy, gdy `LC_LOAD_WEAK_DYLIB` ma wartość true.
- **Znajdź weak linked libraries** w plikach binarnych za pomocą (poniżej znajduje się przykład tworzenia bibliotek hijacking):
- ```bash
otool -l </path/to/bin> | grep LC_LOAD_WEAK_DYLIB -A 5 cmd LC_LOAD_WEAK_DYLIB
cmdsize 56
name /var/tmp/lib/libUtl.1.dylib (offset 24)
time stamp 2 Wed Jun 21 12:23:31 1969
current version 1.0.0
compatibility version 1.0.0
```
- **Skonfigurowane za pomocą @rpath**: pliki binarne Mach-O mogą zawierać polecenia **`LC_RPATH`** i **`LC_LOAD_DYLIB`**. Na podstawie **wartości** tych poleceń **biblioteki** będą **ładowane** z **różnych katalogów**.
- **`LC_RPATH`** zawiera ścieżki do folderów używanych przez plik binarny do ładowania bibliotek.
- **`LC_LOAD_DYLIB`** zawiera ścieżkę do konkretnych bibliotek, które należy załadować. Ścieżki te mogą zawierać **`@rpath`**, które zostanie **zastąpione** wartościami z **`LC_RPATH`**. Jeśli w **`LC_RPATH`** znajduje się kilka ścieżek, każda z nich zostanie użyta do wyszukania biblioteki do załadowania. Przykład:
- Jeśli **`LC_LOAD_DYLIB`** zawiera `@rpath/library.dylib`, a **`LC_RPATH`** zawiera `/application/app.app/Contents/Framework/v1/` oraz `/application/app.app/Contents/Framework/v2/`. Oba foldery zostaną użyte do załadowania `library.dylib`**.** Jeśli biblioteka nie istnieje w `[...]/v1/`, attacker może umieścić ją tam, aby przejąć ładowanie biblioteki z `[...]/v2/`, ponieważ kolejność ścieżek w **`LC_LOAD_DYLIB`** jest zachowywana.
- **Znajdź ścieżki rpath i biblioteki** w plikach binarnych za pomocą: `otool -l </path/to/binary> | grep -E "LC_RPATH|LC_LOAD_DYLIB" -A 5`

> [!NOTE] > **`@executable_path`**: Jest to **ścieżka** do katalogu zawierającego **główny plik wykonywalny**.
>
> **`@loader_path`**: Jest to **ścieżka** do **katalogu** zawierającego **plik binarny Mach-O**, który zawiera polecenie load.
>
> - Gdy jest używane w pliku wykonywalnym, **`@loader_path`** jest w praktyce takie samo jak **`@executable_path`**.
> - Gdy jest używane w **dylib**, **`@loader_path`** wskazuje **ścieżkę** do **dylib**.

Sposobem na **eskalację uprawnień** z wykorzystaniem tej funkcji byłby rzadki przypadek, w którym **aplikacja** uruchamiana **przez** **root** **szuka** biblioteki w folderze, do którego attacker ma uprawnienia zapisu.

> [!TIP]
> Dobrym **scannerem** do wyszukiwania **brakujących bibliotek** w aplikacjach jest [**Dylib Hijack Scanner**](https://objective-see.com/products/dhs.html) lub jego [**wersja CLI**](https://github.com/pandazheng/DylibHijack).\
> Dobry [**raport ze szczegółami technicznymi**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x) dotyczący tej techniki znajduje się [**tutaj**](https://www.virusbulletin.com/virusbulletin/2015/03/dylib-hijacking-os-x).

**Przykład**


{{#ref}}
macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

## Dlopen Hijacking

> [!CAUTION]
> Pamiętaj, że **wcześniej opisane ograniczenia Library Validation mają również zastosowanie** podczas przeprowadzania ataków Dlopen hijacking.

Z **`man dlopen`**:

- Gdy ścieżka **nie zawiera znaku ukośnika** (tj. jest tylko nazwą liścia), **dlopen() przeprowadzi wyszukiwanie**. Jeśli podczas uruchamiania ustawiono **`$DYLD_LIBRARY_PATH`**, dyld najpierw **sprawdzi ten katalog**. Następnie, jeśli wywołujący plik mach-o lub główny plik wykonywalny określa **`LC_RPATH`**, dyld **sprawdzi te** katalogi. Następnie, jeśli proces jest **unrestricted**, dyld przeszuka bieżący katalog roboczy. Na końcu, w przypadku starych plików binarnych, dyld wypróbuje mechanizmy fallback. Jeśli podczas uruchamiania ustawiono **`$DYLD_FALLBACK_LIBRARY_PATH`**, dyld przeszuka **te katalogi**; w przeciwnym razie dyld sprawdzi **`/usr/local/lib/`** (jeśli proces jest unrestricted), a następnie **`/usr/lib/`** (informacje pochodzą z **`man dlopen`**).
1. `$DYLD_LIBRARY_PATH`
2. `LC_RPATH`
3. `CWD`(jeśli unrestricted)
4. `$DYLD_FALLBACK_LIBRARY_PATH`
5. `/usr/local/lib/` (jeśli unrestricted)
6. `/usr/lib/`

> [!CAUTION]
> Jeśli nazwa nie zawiera ukośników, hijacking można przeprowadzić na 2 sposoby:
>
> - Jeśli dowolny **`LC_RPATH`** jest zapisywalny (ale sygnatura jest sprawdzana, więc w tym celu plik binarny musi być również unrestricted)
> - Jeśli plik binarny jest **unrestricted**, możliwe jest załadowanie czegoś z CWD (lub wykorzystanie jednej ze wspomnianych zmiennych środowiskowych)

- Gdy ścieżka **wygląda jak ścieżka frameworka** (np. `/stuff/foo.framework/foo`), jeśli podczas uruchamiania ustawiono **`$DYLD_FRAMEWORK_PATH`**, dyld najpierw sprawdzi ten katalog pod kątem **częściowej ścieżki frameworka** (np. `foo.framework/foo`). Następnie dyld spróbuje użyć **podanej ścieżki bez zmian** (dla ścieżek względnych używając bieżącego katalogu roboczego). Na koniec, w przypadku starych plików binarnych, dyld wypróbuje mechanizmy fallback. Jeśli podczas uruchamiania ustawiono **`$DYLD_FALLBACK_FRAMEWORK_PATH`**, dyld przeszuka te katalogi. W przeciwnym razie przeszuka **`/Library/Frameworks`** (w macOS, jeśli proces jest unrestricted), a następnie **`/System/Library/Frameworks`**.
1. `$DYLD_FRAMEWORK_PATH`
2. podana ścieżka (dla ścieżek względnych używany jest bieżący katalog roboczy, jeśli proces jest unrestricted)
3. `$DYLD_FALLBACK_FRAMEWORK_PATH`
4. `/Library/Frameworks` (jeśli unrestricted)
5. `/System/Library/Frameworks`

> [!CAUTION]
> Jeśli jest to ścieżka frameworka, hijacking można przeprowadzić:
>
> - Jeśli proces jest **unrestricted**, wykorzystując **ścieżkę względną z CWD** lub wspomniane zmienne środowiskowe (nawet jeśli nie jest to określone w dokumentacji, zmienne środowiskowe DYLD\_\* są usuwane, gdy proces jest restricted)

- Gdy **ścieżka zawiera ukośnik, ale nie jest ścieżką frameworka** (tj. jest pełną lub częściową ścieżką do dylib), dlopen() najpierw sprawdza (jeśli ustawiono) **`$DYLD_LIBRARY_PATH`** (z częścią liścia ze ścieżki). Następnie dyld **próbuje użyć podanej ścieżki** (dla ścieżek względnych używając bieżącego katalogu roboczego, ale tylko dla procesów unrestricted). Na końcu, w przypadku starszych plików binarnych, dyld wypróbuje mechanizmy fallback. Jeśli podczas uruchamiania ustawiono **`$DYLD_FALLBACK_LIBRARY_PATH`**, dyld przeszuka te katalogi; w przeciwnym razie dyld sprawdzi **`/usr/local/lib/`** (jeśli proces jest unrestricted), a następnie **`/usr/lib/`**.
1. `$DYLD_LIBRARY_PATH`
2. podana ścieżka (dla ścieżek względnych używany jest bieżący katalog roboczy, jeśli proces jest unrestricted)
3. `$DYLD_FALLBACK_LIBRARY_PATH`
4. `/usr/local/lib/` (jeśli unrestricted)
5. `/usr/lib/`

> [!CAUTION]
> Jeśli nazwa zawiera ukośniki i nie jest frameworkiem, hijacking można przeprowadzić:
>
> - Jeśli plik binarny jest **unrestricted**, możliwe jest załadowanie czegoś z CWD lub `/usr/local/lib` (albo wykorzystanie jednej ze wspomnianych zmiennych środowiskowych)

> [!TIP]
> Uwaga: Nie istnieją pliki konfiguracyjne służące do **kontrolowania wyszukiwania dlopen**.
>
> Uwaga: Jeśli główny plik wykonywalny jest plikiem binarnym **set\[ug]id** lub jest podpisany kodem z entitlements, wszystkie zmienne środowiskowe są ignorowane i można użyć wyłącznie pełnej ścieżki ([sprawdź ograniczenia DYLD_INSERT_LIBRARIES](macos-dyld-hijacking-and-dyld_insert_libraries.md#check-dyld_insert_librery-restrictions), aby uzyskać więcej informacji).
>
> Uwaga: Platformy Apple używają plików "universal" do łączenia bibliotek 32-bitowych i 64-bitowych. Oznacza to, że nie istnieją oddzielne ścieżki wyszukiwania dla bibliotek 32-bitowych i 64-bitowych.
>
> Uwaga: Na platformach Apple większość systemowych dylib jest **połączona w pamięci podręcznej dyld** i nie istnieje na dysku. Dlatego wywołanie **`stat()`** w celu wstępnego sprawdzenia, czy systemowa dylib istnieje, **nie zadziała**. Jednak **`dlopen_preflight()`** używa tych samych kroków co **`dlopen()`**, aby znaleźć zgodny plik mach-o.

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
Jeśli skompilujesz i uruchomisz ten kod, możesz zobaczyć, **gdzie bezskutecznie szukano każdej biblioteki**. Możesz również **filtrować logi FS**:
```bash
sudo fs_usage | grep "dlopentest"
```
## Hijacking ścieżki względnej

Jeśli **uprzywilejowany binary/app** (na przykład SUID lub jakiś binary z potężnymi entitlements) **ładuje bibliotekę ze ścieżki względnej** (na przykład za pomocą `@executable_path` lub `@loader_path`) i ma wyłączoną **Library Validation**, możliwe może być przeniesienie binary do lokalizacji, w której attacker mógłby **zmodyfikować bibliotekę ładowaną ze ścieżki względnej**, a następnie wykorzystać ją do wstrzyknięcia code do procesu.

## Usuwanie zmiennych środowiskowych `DYLD_*` i `LD_LIBRARY_PATH`

W pliku `dyld-dyld-832.7.1/src/dyld2.cpp` można znaleźć funkcję **`pruneEnvironmentVariables`**, która usunie każdą zmienną środowiskową, której nazwa **zaczyna się od `DYLD_`**, oraz **`LD_LIBRARY_PATH=`**.

Ustawi również konkretnie wartość **null** dla zmiennych środowiskowych **`DYLD_FALLBACK_FRAMEWORK_PATH`** i **`DYLD_FALLBACK_LIBRARY_PATH`** w przypadku binary **suid** i **sgid**.

Ta funkcja jest wywoływana z funkcji **`_main`** w tym samym pliku, jeśli celem jest OSX, w następujący sposób:
```cpp
#if TARGET_OS_OSX
if ( !gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache ) {
pruneEnvironmentVariables(envp, &apple);
```
a te flagi logiczne są ustawiane w tym samym pliku w kodzie:
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
Co zasadniczo oznacza, że jeśli binary ma **suid** lub **sgid**, zawiera segment **RESTRICT** w nagłówkach albo został podpisany z flagą **CS_RESTRICT**, wtedy warunek **`!gLinkContext.allowEnvVarsPrint && !gLinkContext.allowEnvVarsPath && !gLinkContext.allowEnvVarsSharedCache`** jest prawdziwy, a zmienne środowiskowe są usuwane.

Należy zauważyć, że jeśli CS_REQUIRE_LV ma wartość true, zmienne nie zostaną usunięte, ale library validation sprawdzi, czy używają tego samego certyfikatu co oryginalny binary.

## Sprawdzanie ograniczeń

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
> Należy pamiętać, że nawet jeśli istnieją binaria podpisane flagami **`0x0(none)`**, mogą one dynamicznie otrzymać flagę **`CS_RESTRICT`** podczas uruchamiania, dlatego ta technika nie będzie w ich przypadku działać.
>
> Możesz sprawdzić, czy proc ma tę flagę, używając ([**csops here**](https://github.com/axelexic/CSOps)):
>
> ```bash
> csops -status <pid>
> ```
>
> Następnie sprawdź, czy flaga 0x800 jest włączona.

## Referencje

- [https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/](https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/)
- [**\*OS Internals, Volume I: User Mode. By Jonathan Levin**](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{{#include ../../../../banners/hacktricks-training.md}}
