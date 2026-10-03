# Proof Assistant and Formal Verification Security

{{#include ../banners/hacktricks-training.md}}

Proof assistants can execute the same term through several paths: kernel reduction, an interpreter, generated code, runtime primitives, or an external checker. A proof is only as strong as every component allowed to contribute trusted results. In Lean, native decision procedures trade faster evaluation for a larger trusted computing base (TCB): the compiler and definitions with native implementations become relevant to proof integrity.<sup>[[3]](#references)</sup>

## Logical/native differential evaluation

Prioritize primitives whose executable implementation is different from their logical model (for example compiler intrinsics, foreign-function interfaces, runtime overrides, and definitions marked with `@[implemented_by]`). Differentially evaluate the **same closed term** through the logical and compiled paths, and treat any value, exception, or termination mismatch as a security finding.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Useful boundary-value classes include:<sup>[[1]](#references)[[4]](#references)</sup>

- indexes around `0`, the input length, the machine-word limit, and values such as `2^63` or larger;
- zero/one-byte ranges, `start = end`, `start > end`, and positions far beyond the object;
- empty and non-empty inputs, multibyte strings, invalid boundaries, and arithmetic that may truncate when compiled;
- heap-backed values when a native primitive has ownership or borrowing behavior absent from the logical model.

The following reduced Lean pattern illustrates the issue found in `String.Pos.Raw.extract`: vulnerable native code returned the original string for an enormous one-byte range, while definitional reduction returned the empty string. This semantic mismatch was fixed separately from the related memory-safety defect.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>

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

This pattern generalizes beyond strings: if logical evaluation proves `E = A` and trusted native evaluation proves `E = B`, transitivity produces `A = B`. When `A` and `B` are observably distinct, this yields `False`; `False.elim` (the explosion principle) can then prove any target proposition. The kernel need not have an incorrect reduction rule—the integrity failure occurs because a compiler-backed result entered the logic through an axiom.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

## Auditing the expanded TCB in Lean

Do not use editor checkmarks or a successful build as the only validation for an untrusted proof. Inspect the complete dependency closure of each security-critical theorem with `#print axioms`; Lean's validation guidance identifies `_native` names as native-evaluation dependencies, `sorryAx` as an incomplete proof, and other nonstandard names as custom axioms.<sup>[[3]](#references)</sup>

```lean
#print axioms targetTheorem
```

For example, a generated dependency resembling the following means compiled execution contributed an assumed result rather than a proof derived solely by kernel reduction:<sup>[[1]](#references)[[4]](#references)</sup>

```text
targetTheorem._native.native_decide.ax_1_1
```

During source review, search for native decision procedures and explicit escape hatches, but confirm the result with `#print axioms` because dependencies may be indirect or generated:<sup>[[3]](#references)</sup>

```bash
rg -n 'native_decide|decide\s+\+native|bv_decide|sorry|axiom' .
```

Distinguish the layers when triaging a finding:<sup>[[3]](#references)</sup>

1. **Statement integrity:** verify that notation, type-class instances, imports, and definitions express the intended claim.
2. **Proof dependencies:** reject or explicitly review unexpected axioms, especially generated native-evaluation axioms.
3. **Kernel replay:** after `lake build`, run `lean4checker --fresh <Module>` to replay declarations from the `.olean` files.
4. **Hostile-proof validation:** build untrusted code in a sandbox and use `lake comparator` with external checkers against a trusted challenge statement.

`lean4checker` provides useful defense in depth, but it trusts the structural correctness of `.olean` files and running untrusted Lean meta-code can itself compromise the checking environment. For high-risk proofs, comparator exports the proof outside the sandbox, checks the statement against the trusted challenge, and can replay it through independently implemented checkers; implementation diversity reduces the chance that one compiler, runtime, or kernel defect validates the same false result everywhere.<sup>[[3]](#references)</sup>

## References

- [1] [`String.Pos.Raw.extract` model/runtime mismatch and use-after-free - Lean issue #14684](https://github.com/leanprover/lean4/issues/14684)
- [2] [Fix `String.Pos.Raw.extract` model/runtime mismatch - Lean PR #14717](https://github.com/leanprover/lean4/pull/14717)
- [3] [Lean Language Reference: Validating a Lean Proof](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [4] [A “Proof” of Fermat’s Last Theorem That Fits the Margin](https://blog.trailofbits.com/2026/09/09/a-proof-of-fermats-last-theorem-that-fits-the-margin/)

{{#include ../banners/hacktricks-training.md}}
