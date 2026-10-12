# Segurança em Assistentes de Prova e Verificação Formal

{{#include ../banners/hacktricks-training.md}}

Assistentes de prova podem executar o mesmo termo por vários caminhos: redução do kernel, um interpretador, código gerado, primitivas de runtime ou um verificador externo. Uma prova é tão forte quanto cada componente autorizado a contribuir com resultados confiáveis. No Lean, procedimentos de decisão nativos trocam uma avaliação mais rápida por uma base computacional confiável (TCB) maior: o compilador e as definições com implementações nativas passam a ser relevantes para a integridade das provas.<sup>[[3]](#references)</sup>

## Avaliação diferencial lógica/nativa

Priorize primitivas cuja implementação executável seja diferente do seu modelo lógico (por exemplo, intrínsecos do compilador, interfaces de funções estrangeiras, substituições de runtime e definições marcadas com `@[implemented_by]`). Avalie diferencialmente o **mesmo termo fechado** pelos caminhos lógico e compilado, e trate qualquer divergência de valor, exceção ou término como um achado de segurança.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Classes úteis de valores-limite incluem:<sup>[[1]](#references)[[4]](#references)</sup>

- índices próximos de `0`, do comprimento da entrada, do limite da palavra da máquina e valores como `2^63` ou maiores;
- intervalos de zero ou um byte, `start = end`, `start > end` e posições muito além do objeto;
- entradas vazias e não vazias, strings multibyte, limites inválidos e operações aritméticas que podem sofrer truncamento quando compiladas;
- valores alocados no heap quando uma primitiva nativa tem comportamento de propriedade ou empréstimo ausente do modelo lógico.

O padrão Lean reduzido a seguir ilustra o problema encontrado em `String.Pos.Raw.extract`: o código nativo vulnerável retornava a string original para um intervalo de um byte enorme, enquanto a redução definicional retornava a string vazia. Essa divergência semântica foi corrigida separadamente do defeito de segurança de memória relacionado.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>

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

Esse padrão se generaliza para além de strings: se a avaliação lógica prova `E = A` e a avaliação nativa confiável prova `E = B`, a transitividade produz `A = B`. Quando `A` e `B` são observavelmente distintos, isso resulta em `False`; `False.elim` (o princípio da explosão) pode então provar qualquer proposição-alvo. O kernel não precisa ter uma regra de redução incorreta — a falha de integridade ocorre porque um resultado apoiado por compilador entrou na lógica por meio de um axioma.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

## Auditoria do TCB expandido no Lean

Não use marcas de confirmação do editor ou uma compilação bem-sucedida como única validação de uma prova não confiável. Inspecione o fechamento completo de dependências de cada teorema crítico para a segurança com `#print axioms`; as orientações de validação do Lean identificam nomes `_native` como dependências de avaliação nativa, `sorryAx` como uma prova incompleta e outros nomes não padronizados como axiomas personalizados.<sup>[[3]](#references)</sup>

```lean
#print axioms targetTheorem
```

Por exemplo, uma dependência gerada semelhante à seguinte significa que a execução compilada contribuiu com um resultado assumido, em vez de uma prova derivada exclusivamente por redução do kernel:<sup>[[1]](#references)[[4]](#references)</sup>

```text
targetTheorem._native.native_decide.ax_1_1
```

Durante a revisão do código-fonte, procure procedimentos de decisão nativos e mecanismos explícitos de escape, mas confirme o resultado com `#print axioms`, pois as dependências podem ser indiretas ou geradas:<sup>[[3]](#references)</sup>

```bash
rg -n 'native_decide|decide\s+\+native|bv_decide|sorry|axiom' .
```

Diferencie as camadas ao fazer a triagem de uma descoberta:<sup>[[3]](#references)</sup>

1. **Integridade da declaração:** verifique se a notação, as instâncias de type-class, os imports e as definições expressam a afirmação pretendida.
2. **Dependências da prova:** rejeite ou revise explicitamente axiomas inesperados, especialmente axiomas gerados de avaliação nativa.
3. **Reexecução pelo kernel:** após `lake build`, execute `lean4checker --fresh <Module>` para reexecutar as declarações a partir dos arquivos `.olean`.
4. **Validação de provas não confiáveis:** compile código não confiável em um sandbox e use `lake comparator` com verificadores externos contra uma declaração de desafio confiável.

`lean4checker` oferece uma defesa em profundidade útil, mas confia na correção estrutural dos arquivos `.olean`, e a execução de meta-código Lean não confiável pode, por si só, comprometer o ambiente de verificação. Para provas de alto risco, comparator exporta a prova para fora do sandbox, verifica a declaração em relação ao desafio confiável e pode reexecutá-la por meio de verificadores implementados de forma independente; a diversidade de implementações reduz a chance de que um defeito em um compilador, runtime ou kernel valide o mesmo resultado falso em todos os verificadores.<sup>[[3]](#references)</sup>

## References

- [1] [`String.Pos.Raw.extract`: divergência entre modelo e runtime e use-after-free - Lean issue #14684](https://github.com/leanprover/lean4/issues/14684)
- [2] [Corrigir a divergência entre modelo e runtime de `String.Pos.Raw.extract` - Lean PR #14717](https://github.com/leanprover/lean4/pull/14717)
- [3] [Referência da linguagem Lean: validação de uma prova Lean](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [4] [Uma “prova” do Último Teorema de Fermat que cabe na margem](https://blog.trailofbits.com/2026/09/09/a-proof-of-fermats-last-theorem-that-fits-the-margin/)
{{#include ../banners/hacktricks-training.md}}
