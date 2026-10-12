# 证明助手与形式化验证安全

{{#include ../banners/hacktricks-training.md}}

证明助手可以通过多条路径执行同一个项：内核归约、解释器、生成的代码、runtime 原语或外部检查器。证明的强度取决于每个可能提供可信结果的组件。在 Lean 中，原生决策过程以更大的可信计算基（TCB）换取更快的求值速度：编译器以及带有原生实现的定义都会影响证明的完整性。<sup>[[3]](#references)</sup>

## 逻辑/原生差异求值

优先检查可执行实现与其逻辑模型不同的原语（例如编译器内建函数、外部函数接口、runtime 覆盖项以及标记了 `@[implemented_by]` 的定义）。通过逻辑路径和编译路径对**同一个封闭项**进行差异求值，并将任何值、异常或终止行为不一致视为安全问题。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

值得检查的边界值类别包括：<sup>[[1]](#references)[[4]](#references)</sup>

- 接近 `0`、输入长度、机器字长上限的索引，以及 `2^63` 或更大的值；
- 零字节或单字节范围、`start = end`、`start > end`，以及远超对象范围的位置；
- 空和非空输入、多字节字符串、无效边界，以及编译时可能发生截断的算术运算；
- 当原生原语具有逻辑模型中不存在的所有权或借用行为时，检查基于堆的值。

下面这个精简的 Lean 模式展示了 `String.Pos.Raw.extract` 中发现的问题：易受攻击的原生代码在遇到一个极大的单字节范围时返回原字符串，而定义性归约则返回空字符串。这个语义不一致问题与相关的内存安全缺陷分别修复。<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>

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

这种模式不只适用于字符串：如果逻辑求值证明 `E = A`，而受信任的原生求值证明 `E = B`，则可通过传递性得出 `A = B`。当 `A` 和 `B` 在可观察层面上不同时，就能推出 `False`；随后可用 `False.elim`（爆炸原理）证明任意目标命题。内核无需包含错误的归约规则——完整性失效是因为编译器支持的结果通过公理进入了逻辑。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

## 审计 Lean 中扩展后的 TCB

对于不可信证明，不要只凭编辑器勾选标记或成功构建来验证。使用 `#print axioms` 检查每个安全关键定理的完整依赖闭包；Lean 的验证指南指出，`_native` 名称表示依赖原生求值，`sorryAx` 表示证明不完整，其他非标准名称则表示自定义公理。<sup>[[3]](#references)</sup>

```lean
#print axioms targetTheorem
```

例如，类似以下内容的生成依赖项意味着，编译执行提供了一个假定结果，而不是仅通过内核归约得出的证明：<sup>[[1]](#references)[[4]](#references)</sup>

```text
targetTheorem._native.native_decide.ax_1_1
```

在审查源代码时，搜索原生判定过程和显式逃逸机制，但要通过 `#print axioms` 确认结果，因为依赖关系可能是间接的，或由系统生成：<sup>[[3]](#references)</sup>

```bash
rg -n 'native_decide|decide\s+\+native|bv_decide|sorry|axiom' .
```

区分对发现进行分流时涉及的各层：<sup>[[3]](#references)</sup>

1. **语句完整性：**验证符号、类型类实例、导入和定义是否表达了预期的声明。
2. **证明依赖项：**拒绝或明确审查意外公理，尤其是生成的原生求值公理。
3. **内核重放：**执行 `lake build` 后，运行 `lean4checker --fresh <Module>`，从 `.olean` 文件重放声明。
4. **恶意证明验证：**在沙箱中构建不可信代码，并使用 `lake comparator`，通过外部检查器验证其是否符合受信任的挑战声明。

`lean4checker` 提供了有用的纵深防御，但它信任 `.olean` 文件在结构上的正确性；运行不可信的 Lean 元代码本身也可能危害检查环境。对于高风险证明，comparator 会将证明导出到沙箱之外，对照受信任的挑战检查声明，并可通过独立实现的检查器重放证明；实现多样性降低了某个编译器、运行时或内核缺陷导致所有检查器都验证同一个错误结果的可能性。<sup>[[3]](#references)</sup>

## References

- [1] [`String.Pos.Raw.extract` 模型/运行时不匹配及 use-after-free - Lean issue #14684](https://github.com/leanprover/lean4/issues/14684)
- [2] [修复 `String.Pos.Raw.extract` 模型/运行时不匹配 - Lean PR #14717](https://github.com/leanprover/lean4/pull/14717)
- [3] [Lean 语言参考：验证 Lean 证明](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [4] [一份“证明”费马大定理的证明，恰好能写在页边空白处](https://blog.trailofbits.com/2026/09/09/a-proof-of-fermats-last-theorem-that-fits-the-margin/)
{{#include ../banners/hacktricks-training.md}}
