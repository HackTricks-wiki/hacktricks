# Node.js/V8 캐시된 Bytecode의 정적 Deobfuscation

{{#include ../../banners/hacktricks-training.md}}

V8 cached data는 JavaScript 소스도, 일반적인 native executable도 아닌 **버전에 종속된 손실 표현**입니다. 따라서 유용한 static workflow는 외부 packing을 제거하고, 일치하는 V8 build로 cache를 disassemble한 다음, 이를 intermediate pseudocode model로 변환하고 sample을 실행하지 않은 상태에서 dependency-aware transformation을 적용하는 것입니다. [View8](https://github.com/suleram/View8)과 [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)는 `javascript-obfuscator`로 보호된 Node.js payload에 이 접근 방식을 구현합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Cache 획득 및 disassemble

먼저 모든 `.jsc` 파일이 동일한 wrapper를 가진다고 가정하지 말고 preload/launcher를 검사합니다. 예를 들어 `node.exe -r preflight.js app.jsc`와 같은 launcher는 main module보다 먼저 `preflight.js`를 실행합니다. 분석된 계열에서는 preload가 Brotli layer를 제거했습니다. Unpacking 후에는 bundled runtime에서 정확한 Node.js/V8 generation을 식별합니다. 한 V8 version에서 생성된 cache는 다른 version에서 거부되거나 잘못 decode될 수 있으므로, 정확한 V8 tag에 해당하는 `v8dasm`을 build하거나 확보하고 필요한 View8 및 string-printing patch를 적용해야 합니다.<sup>[[1]](#references)[[2]](#references)</sup>

Toolkit의 non-executing workflow는 다음과 같습니다:<sup>[[2]](#references)</sup>
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
`--normalize`는 실행마다 생성된 함수에 안정적인 식별자를 부여합니다. 텍스트 출력은 검사용이며, 직렬화된 객체 그래프를 사용하면 서로 독립적인 pass에서도 함수, 선언자, scope 및 메타데이터 간의 관계를 유지할 수 있습니다. 이는 **재구성되거나 실행 가능한 JavaScript가 아닙니다**.<sup>[[1]](#references)[[2]](#references)</sup>

### View8 pseudocode를 IR로 읽기

일반적인 이름은 `func_<name>_0x<address>`이고, 인수는 `a0...aN`, virtual register는 `r0...rN`이며, `ACCU`는 V8의 accumulator입니다. `start`는 root declarer이고, `Scope[...]`, globals 및 dictionaries는 nested function이 capture하거나 공유하는 값을 모델링합니다. 모든 expression을 JavaScript syntax로 파싱해서는 안 됩니다. 예를 들어 View8의 `!r6 === "0"`은 전체 비교의 부정(`r6 !== "0"`)을 나타내며, 이는 branch를 재구성할 때 중요합니다.<sup>[[1]](#references)[[3]](#references)</sup>

## Dependency-aware deobfuscation

다음 pass에 필요한 입력이 드러나도록 정해진 순서로 transformation을 적용하고, 출력이 안정화될 때까지 propagation을 반복합니다. 실용적인 순서는 다음과 같습니다.<sup>[[1]](#references)[[2]](#references)</sup>

1. declarer hierarchy를 순회하고 globals, registers, dictionaries 및 `Scope[...]` references에서 값을 propagation합니다.
2. string-decoder arguments를 복구하고 encrypted calls를 plaintext로 교체합니다.
3. 인접한 string chunks를 fold합니다. 그 결과로 생성되는 property names와 dispatcher-order strings가 이후 pass를 가능하게 합니다.
4. control flow를 unflatten하고, call proxies와 atomic-operation wrappers를 inline하며, dictionary에 저장된 function references를 resolve합니다.
5. 각 resolved string, key 또는 proxy가 또 다른 indirection 계층을 드러낼 수 있으므로 다시 propagation합니다.
6. 인식된 one-shot initialization thunks를 collapse하고, 해당 call sites가 resolve된 후에만 dead helpers를 제거합니다.

### Shift된 RC4 string arrays를 black box로 복구하기

일반적인 `javascript-obfuscator` 레이아웃은 하나의 array에 Base64-encoded RC4 chunks를 저장합니다. Decoder wrappers는 numeric offset과 짧은 key를 제공하며, 때로는 argument order가 뒤바뀌고 closure scopes에서 capture한 constants를 더하거나 뺍니다. Root decoder가 너무 심하게 obfuscation된 경우 전체 function을 재구성하는 대신 unknown array-index shift를 경험적으로 복구합니다.<sup>[[1]](#references)</sup>

`N`개의 chunks를 가진 array와 동일한 decoder에 대한 여러 calls가 있는 경우:<sup>[[1]](#references)</sup>
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
단일 printable decryption 결과만으로 shift를 받아들이지 마세요. 잘못된 ciphertext도 우연히 printable하게 보일 수 있습니다. 최소 세 개의 서로 다른 관찰 결과를 사용하고, 모든 관찰 결과에서 plausible한 텍스트를 생성하는 유일한 shift만 받아들이세요. 그런 다음 wrapper/declarer graph를 순회하면서 각 addition 또는 subtraction을 누적하고 numeric argument가 먼저 오는지 기록하세요. 이 metadata를 sample별로 cache하고, decoder 호출을 대체한 뒤, 인접한 plaintext chunk를 연결하고 triage를 위해 문자열을 별도로 export하세요.<sup>[[1]](#references)[[2]](#references)</sup>

### unflattening 중 semantics 보존

`3|2|1|0|4`와 같은 문자열로 구동되는 dispatcher loop의 경우, order string을 decode하고 각 state comparison을 해당 block에 매핑하세요. View8의 negated-condition 표기도 반영한 다음 dispatcher order에 따라 block을 출력하세요. 중첩된 `continue`는 일반적인 fall-through가 아니라 dispatcher로 되돌아가는 early jump를 나타낼 수 있습니다. loop를 제거할 때는 해당 `continue`를 삭제하고, 이를 감싸는 `if` 다음에 원래 이어지던 statement를 생성된 `else` branch로 이동하세요. dispatcher를 단순히 삭제하면 behavior가 변경됩니다.<sup>[[1]](#references)</sup>

### proxies, operations 및 lazy thunks를 inline하기

`return a0(a1, a2)`와 같은 forwarding helper를 normalize한 후 call site를 direct call로 대체하세요. subtraction, division, comparison, membership test 또는 invocation을 위한 wrapper도 같은 방식으로 처리하세요. helper reference 자체가 decrypted dictionary key 또는 closure value 뒤에 저장되어 있을 수 있으므로, inlining 전후에 string 및 structure propagation을 실행하세요.<sup>[[1]](#references)</sup>

또한 저장된 function을 한 번 호출하고 해당 reference를 clear하며, 그 결과를 cache한 뒤 이후 호출에서 해당 cache를 반환하는 closure도 인식하세요. initialization site에서 이러한 thunk를 collapse하면 underlying dispatcher 또는 capability function이 드러나지만, 원래 execution이 **one-shot and cached**였음을 표시해야 합니다. 모든 호출을 새로운 invocation으로 모델링해서는 안 됩니다.<sup>[[1]](#references)</sup>

## Safety 및 validation 참고 사항

- Python `pickle` loading은 code를 실행할 수 있습니다. 신뢰할 수 있는 View8 run에서 로컬로 생성된 `.pkl` 파일만 load하고, sample이 제공한 pickle을 data로 취급하지 마세요.<sup>[[2]](#references)</sup>
- Pattern-driven pass는 general JavaScript decompiler가 아닙니다. unresolved expression을 보존하고, 모호한 dispatcher variant는 rewrite를 강제하지 말고 수동으로 inspect하세요.<sup>[[1]](#references)[[2]](#references)</sup>
- LLM-assisted function name은 navigation hint일 뿐 evidence가 아닙니다. 이를 사용하는 경우 dependency를 leaf-first로 process하되, 모든 label을 body, argument, string, data flow, API 및 side effect와 대조하여 verify하세요.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Breaking the Seal: JSCeal의 컴파일된 V8 Bytecode에 대한 Static Deobfuscation](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}
