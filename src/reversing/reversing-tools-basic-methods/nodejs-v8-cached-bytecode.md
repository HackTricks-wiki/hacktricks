# Node.js/V8 캐시 바이트코드의 정적 디옵스케이션

{{#include ../../banners/hacktricks-training.md}}

V8 캐시 데이터는 JavaScript 소스도, 일반적인 네이티브 실행 파일도 아닌 **버전에 따라 달라지는 손실성 표현**입니다. 따라서 유용한 정적 분석 워크플로는 바깥쪽 패킹을 제거하고, 일치하는 V8 빌드로 캐시를 디스어셈블한 다음, 중간 의사 코드 모델로 변환하고, 샘플을 실행하지 않은 채 종속성을 고려한 변환을 적용하는 것입니다. [View8](https://github.com/suleram/View8)과 [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)는 `javascript-obfuscator`로 보호된 Node.js 페이로드에 이 접근 방식을 구현합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## 캐시 획득 및 디스어셈블

먼저 모든 `.jsc` 파일의 래퍼가 동일하다고 가정하지 말고 preload/launcher를 살펴봅니다. 예를 들어 `node.exe -r preflight.js app.jsc`와 같은 launcher는 메인 모듈보다 먼저 `preflight.js`를 실행합니다. 분석한 샘플 계열에서는 preload가 Brotli 계층을 제거했습니다. 압축을 푼 다음 번들된 런타임으로 정확한 Node.js/V8 세대를 확인합니다. 한 V8 버전에서 생성된 캐시는 다른 버전에서 거부되거나 잘못 디코딩될 수 있으므로, 해당 V8 태그에 맞는 `v8dasm`을 빌드하거나 구하고 필요한 View8 패치와 문자열 출력 패치를 적용합니다.<sup>[[1]](#references)[[2]](#references)</sup>

이 툴킷의 비실행 워크플로는 다음과 같습니다.<sup>[[2]](#references)</sup>

```bash
brotli -d app.jsc -o app.decompressed.jsc
/path/to/matching-v8dasm app.decompressed.jsc > app.jsc.disasm.txt
mkdir -p decompiled deobfuscated
python3 View8/view8.py --input_format disassembled \
  --inp app.jsc.disasm.txt --normalize \
  --out decompiled/app.dec.txt \
  --export_format decompiled serialized
python3 deobf_all.py --inp decompiled/app.dec.pkl \
  --out deobfuscated/app.deobf.txt \
  --export_format decompiled serialized
```

`--normalize`는 생성된 함수에 실행마다 안정적인 식별자를 부여합니다. 텍스트 출력은 검사에 사용하고, 직렬화된 객체 그래프를 사용하면 독립적인 패스에서 함수, 선언자, 스코프 및 메타데이터 간의 관계를 보존할 수 있습니다. 이는 **재구성된 JavaScript도 아니고 실행 가능한 JavaScript도 아닙니다**.<sup>[[1]](#references)[[2]](#references)</sup>

### V8을 빌드하지 않고 캐시 분류하기

원시 캐시나 Brotli로 래핑된 캐시의 경우, `jscd`는 Node.js에서 샘플을 로드하지 않고도 헤더를 식별하고 상수와 함수를 열거할 수 있습니다. 먼저 버전 테이블이 해당 파일을 지원하는지 확인하고, 더 전문적인 View8 난독화 해제 패스에 앞서 우선순위를 정할 함수를 추리는 데 사용하세요.<sup>[[4]](#references)</sup>

버전 해시는 식별을 위한 단서일 뿐, 독립형 디스어셈블러가 생성 도구와 동일한 플래그나 읽기 전용 스냅샷을 사용한다는 증거는 아닙니다.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm`은 View8 호환 listing을 출력하므로, 캐시가 지원되는 경우 위의 View8 명령에서 `v8dasm` 대신 해당 출력을 사용할 수 있습니다. 함수 트리와 함께 문자열을 살펴 decoder 호출과 유력한 진입점을 찾으세요. `jscd`의 근사치인 JavaScript 출력을 원본 소스로 취급하지 마세요. 도구가 버전을 거부하거나 읽기 전용 힙 placeholder를 남기면, 추측으로 프로퍼티 이름을 정하지 말고 일치하는 V8 빌드로 돌아가거나 같은 빌드의 name map을 제공하세요.<sup>[[4]](#references)</sup>

Electron 애플리케이션 내의 캐시라면 먼저 [ASAR를 추출하고 main 및 preload 진입점을 살펴보세요](../../desktop-application-security/electron-desktop-apps/). V8 버전 문자열이 같더라도 Electron과 Node의 캐시는 snapshot 및 pointer-compression 레이아웃이 다를 수 있습니다.<sup>[[4]](#references)</sup>

### View8 pseudocode를 IR로 읽기

일반적인 이름은 `func_<name>_0x<address>`이고, 인수는 `a0...aN`, 가상 레지스터는 `r0...rN`이며, `ACCU`는 V8의 accumulator입니다. `start`는 루트 declarer이고, `Scope[...]`, 전역 변수와 사전은 중첩 함수가 캡처하거나 공유하는 값을 나타냅니다. 모든 표현식을 JavaScript 문법으로 해석하지 마세요. 예를 들어 View8의 `!r6 === "0"`은 비교 전체를 부정한 것(`r6 !== "0"`)을 나타내며, 이는 분기를 재구성할 때 중요합니다.<sup>[[1]](#references)[[3]](#references)</sup>

## 의존성을 고려한 deobfuscation

다음 pass에 필요한 입력이 드러나도록 순서대로 변환을 적용하고, 출력이 안정될 때까지 propagation을 반복하세요. 실용적인 순서는 다음과 같습니다.<sup>[[1]](#references)[[2]](#references)</sup>

1. declarer 계층을 순회하고 전역 변수, 레지스터, 사전 및 `Scope[...]` 참조의 값을 propagation합니다.
2. string-decoder 인수를 복구하고 암호화된 호출을 평문으로 대체합니다.
3. 인접한 문자열 청크를 결합합니다. 이렇게 얻은 프로퍼티 이름과 dispatcher 순서 문자열을 통해 이후 pass를 진행할 수 있습니다.
4. control flow를 unflatten하고, call proxy와 atomic-operation wrapper를 인라인하며, 사전에 저장된 함수 참조를 확인합니다.
5. 확인된 각 문자열, 키 또는 proxy가 다른 간접 참조 계층을 드러낼 수 있으므로 다시 propagation합니다.
6. 호출 지점이 확인된 후에만, 한 번 실행되는 것으로 식별된 초기화 thunk를 축약하고 사용되지 않는 helper를 제거합니다.

### Shift된 RC4 문자열 배열을 블랙박스로 복구하기

일반적인 `javascript-obfuscator` 레이아웃은 하나의 배열에 Base64로 인코딩된 RC4 청크를 저장합니다. Decoder wrapper는 숫자 offset과 짧은 key를 제공하며, 인수 순서가 뒤바뀌는 경우도 있습니다. 그런 다음 closure scope에서 캡처한 상수를 더하거나 뺍니다. 루트 decoder가 너무 심하게 obfuscation된 경우, 전체 함수를 재구성하는 대신 알 수 없는 배열 인덱스 shift를 실험적으로 복구하세요.<sup>[[1]](#references)</sup>

청크가 `N`개인 배열과 같은 decoder를 호출하는 여러 지점에 대해:<sup>[[1]](#references)</sup>

```text
for each observed (numeric_argument, rc4_key):
    candidates = {}
    for shift in 0 .. N-1:
        index = apply_observed_sign(numeric_argument, shift)
        plaintext = RC4(Base64Decode(chunks[index]), rc4_key)
        if plaintext passes encoding/printability checks:
            candidates.add(shift)
root_shift = intersection(candidate_sets)
```

단일 printable 복호화 결과만으로는 수용하지 마세요. 잘못된 ciphertext도 우연히 printable하게 보일 수 있습니다. 서로 다른 관측 결과를 최소 세 개 사용하고, 모두 그럴듯한 텍스트를 생성하는 shift가 하나뿐일 때만 수용하세요. 그런 다음 wrapper/declarer 그래프를 순회하며 각 덧셈 또는 뺄셈을 누적하고, 숫자 인자가 먼저 오는지도 기록하세요. 이 metadata를 샘플별로 캐시하고, decoder 호출을 대체한 다음, 인접한 plaintext 청크를 이어 붙이고 문자열은 triage용으로 별도 export하세요.<sup>[[1]](#references)[[2]](#references)</sup>

### 언플래튼할 때 의미 보존하기

`3|2|1|0|4`와 같은 문자열로 제어되는 dispatcher 루프에서는 순서 문자열을 디코딩하고, 각 state 비교를 해당 블록에 매핑하고, View8의 부정 조건 표기를 고려한 다음, dispatcher 순서대로 블록을 출력하세요. 중첩된 `continue`는 일반적인 fall-through가 아니라 dispatcher로 되돌아가는 조기 점프일 수 있습니다. 루프를 제거할 때는 해당 `continue`를 삭제하고, 이를 둘러싼 `if` 뒤에 원래 있던 문장들을 생성된 `else` 분기로 옮기세요. dispatcher만 삭제하면 동작이 달라집니다.<sup>[[1]](#references)</sup>

### 프록시, 연산, 지연 thunk 인라인 처리하기

호출 지점을 직접 호출로 대체하기 전에 `return a0(a1, a2)`와 같은 전달 helper를 정규화하세요. 뺄셈, 나눗셈, 비교, 멤버십 테스트 또는 호출을 위한 wrapper도 마찬가지로 처리하세요. helper 참조 자체가 복호화된 dictionary key나 closure 값 뒤에 저장되어 있을 수 있으므로, 인라인 처리 전후에 문자열 및 구조 전파를 실행하세요.<sup>[[1]](#references)</sup>

저장된 함수를 한 번 호출하고 참조를 지운 뒤 결과를 캐시하며, 이후 호출에서는 그 캐시를 반환하는 closure도 찾아내세요. 초기화 지점에서 이러한 thunk를 축약하면 내부 dispatcher 또는 capability function이 드러납니다. 다만 원래 실행이 매번 새로 호출되는 방식이 아니라 **한 번만 실행되고 캐시됨**을 주석으로 남기세요.<sup>[[1]](#references)</sup>

## 안전 및 검증 참고 사항

- Python `pickle` 로딩은 코드를 실행할 수 있습니다. 신뢰할 수 있는 View8 실행에서 로컬로 생성한 `.pkl` 파일만 로드하고, 샘플이 제공한 pickle을 데이터로 취급하지 마세요.<sup>[[2]](#references)</sup>
- 함수 본문이 없다고 해서 소스에 해당 함수가 없었다는 증거는 아닙니다. V8은 lazy function이 처음 호출되어 컴파일될 때까지 해당 함수를 metadata로 직렬화할 수 있습니다. 정적 triage 중에는 이러한 함수를 미해결 상태로 표시하세요.<sup>[[6]](#references)</sup>
- 패턴 기반 패스는 범용 JavaScript decompiler가 아닙니다. 미해결 표현식을 보존하고, 모호한 dispatcher 변형은 억지로 다시 쓰지 말고 직접 검사하세요.<sup>[[1]](#references)[[2]](#references)</sup>
- LLM을 이용해 추정한 함수 이름은 탐색을 돕는 단서일 뿐 증거가 아닙니다. 이를 사용할 경우 의존성을 leaf부터 처리하되, 모든 레이블을 본문, 인자, 문자열, 데이터 흐름, API 및 부작용과 대조해 검증하세요.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [봉인을 깨다: JSCeal의 컴파일된 V8 바이트코드 정적 난독화 해제](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [V8 SerializedCodeData 헤더](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Node.js vm.Script 코드 캐시](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
