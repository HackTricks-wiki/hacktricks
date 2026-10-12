# Proof Assistant 및 Formal Verification Security

{{#include ../banners/hacktricks-training.md}}

Proof assistant는 동일한 항을 여러 경로로 실행할 수 있습니다. 예를 들어 kernel reduction, interpreter, 생성된 코드, runtime primitive 또는 external checker를 거칠 수 있습니다. 증명은 신뢰된 결과에 기여하도록 허용된 모든 구성 요소만큼만 강력합니다. Lean에서 native decision procedure는 더 빠른 평가를 위해 신뢰 컴퓨팅 기반(TCB)을 넓힙니다. 즉, compiler와 native 구현이 있는 정의가 증명의 무결성에 영향을 미칩니다.<sup>[[3]](#references)</sup>

## Logical/native differential evaluation

실행 가능한 구현이 논리적 모델과 다른 primitive를 우선적으로 살펴보세요. 예를 들어 compiler intrinsic, foreign-function interface, runtime override, `@[implemented_by]`로 표시된 정의가 이에 해당합니다. **동일한 closed term**을 논리 경로와 compiled 경로에서 각각 평가하고, 값·예외·종료 여부가 다르면 보안 이슈로 간주하세요.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

유용한 경계값 유형은 다음과 같습니다.<sup>[[1]](#references)[[4]](#references)</sup>

- `0`, 입력 길이, machine-word 한계 전후의 인덱스, `2^63` 이상과 같은 값;
- 길이가 0 또는 1바이트인 범위, `start = end`, `start > end`, 객체를 훨씬 벗어난 위치;
- 비어 있거나 비어 있지 않은 입력, 멀티바이트 문자열, 유효하지 않은 경계, compiled 시 잘릴 수 있는 산술 연산;
- native primitive에 논리적 모델에는 없는 소유권 또는 borrowing 동작이 있을 때의 heap-backed 값.

다음의 축약된 Lean 패턴은 `String.Pos.Raw.extract`에서 발견된 문제를 보여줍니다. 취약한 native code는 매우 큰 1바이트 범위에 대해 원래 문자열을 반환했지만, definitional reduction은 빈 문자열을 반환했습니다. 이 의미 불일치는 관련 memory-safety 결함과 별도로 수정되었습니다.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>

```lean
def value : String := "non-empty"
def startPos : String.Pos.Raw := ⟨2^63⟩
def endPos : String.Pos.Raw := ⟨2^63 + 1⟩

example : False := by
  have logical : String.Pos.Raw.extract value startPos endPos = "" := rfl
  have native : String.Pos.Raw.extract value startPos endPos = value := by
    native_decide
  exact (by decide) (logical.symm.trans native)
```

이 패턴은 문자열을 넘어 일반화됩니다. 논리적 평가로 `E = A`가 증명되고 신뢰할 수 있는 네이티브 평가로 `E = B`가 증명되면, 추이성을 통해 `A = B`를 얻습니다. `A`와 `B`가 관찰상 서로 다르면 `False`가 도출되고, 폭발 원리인 `False.elim`을 사용해 어떤 목표 명제든 증명할 수 있습니다. 커널에 잘못된 환원 규칙이 있을 필요는 없습니다. 컴파일러를 기반으로 한 결과가 공리를 통해 논리에 들어왔기 때문에 무결성 문제가 발생합니다.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

## Lean에서 확장된 TCB 감사

신뢰할 수 없는 증명에 대해 편집기의 체크 표시나 성공적인 빌드만을 유일한 검증 수단으로 삼지 마세요. `#print axioms`로 보안상 중요한 각 정리의 전체 의존성 폐쇄를 검사하세요. Lean의 검증 지침에 따르면 `_native` 이름은 네이티브 평가 의존성을, `sorryAx`는 불완전한 증명을, 그 밖의 비표준 이름은 사용자 정의 공리를 나타냅니다.<sup>[[3]](#references)</sup>

```lean
#print axioms targetTheorem
```

예를 들어, 다음과 유사한 생성된 의존성이 있다면 커널 축약만으로 도출된 증명이 아니라 컴파일된 실행이 가정된 결과에 기여했다는 뜻입니다:<sup>[[1]](#references)[[4]](#references)</sup>

```text
targetTheorem._native.native_decide.ax_1_1
```

소스 검토 중에는 기본 제공 decision procedure와 명시적 우회 수단을 찾아보되, 의존성이 간접적이거나 생성된 것일 수 있으므로 `#print axioms`로 결과를 확인하세요:<sup>[[3]](#references)</sup>

```bash
rg -n 'native_decide|decide\s+\+native|bv_decide|sorry|axiom' .
```

조사 결과를 분류할 때 각 계층을 구분하세요:<sup>[[3]](#references)</sup>

1. **명제 무결성:** 표기법, type-class 인스턴스, import, 정의가 의도한 주장을 표현하는지 확인합니다.
2. **증명 의존성:** 예상치 못한 공리를 거부하거나 명시적으로 검토합니다. 특히 생성된 native-evaluation 공리를 주의합니다.
3. **커널 재검증:** `lake build` 후 `lean4checker --fresh <Module>`을 실행해 `.olean` 파일의 선언을 재검증합니다.
4. **적대적 증명 검증:** 신뢰할 수 없는 코드를 sandbox에서 빌드하고, 외부 checker와 함께 `lake comparator`를 사용해 신뢰할 수 있는 challenge 명제와 대조합니다.

`lean4checker`는 유용한 심층 방어 수단이지만, `.olean` 파일의 구조적 정확성을 신뢰하며 신뢰할 수 없는 Lean meta-code를 실행하는 행위 자체가 검증 환경을 손상할 수 있습니다. 위험도가 높은 증명의 경우 comparator는 증명을 sandbox 외부로 내보내고, 신뢰할 수 있는 challenge와 명제를 대조하며, 독립적으로 구현된 checker를 통해 증명을 재검증할 수 있습니다. 구현의 다양성은 하나의 compiler, runtime 또는 kernel 결함이 어디서나 동일한 거짓 결과를 검증할 가능성을 줄입니다.<sup>[[3]](#references)</sup>

## References

- [1] [`String.Pos.Raw.extract` 모델/runtime 불일치와 use-after-free - Lean 이슈 #14684](https://github.com/leanprover/lean4/issues/14684)
- [2] [`String.Pos.Raw.extract` 모델/runtime 불일치 수정 - Lean PR #14717](https://github.com/leanprover/lean4/pull/14717)
- [3] [Lean 언어 레퍼런스: Lean 증명 검증하기](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [4] [여백 안에 들어가는 페르마의 마지막 정리 “증명”](https://blog.trailofbits.com/2026/09/09/a-proof-of-fermats-last-theorem-that-fits-the-margin/)
{{#include ../banners/hacktricks-training.md}}
