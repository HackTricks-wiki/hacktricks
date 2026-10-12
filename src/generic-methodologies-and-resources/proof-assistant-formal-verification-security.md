# Seguridad de los asistentes de pruebas y la verificación formal

{{#include ../banners/hacktricks-training.md}}

Los asistentes de pruebas pueden ejecutar el mismo término por varias vías: reducción del kernel, un intérprete, código generado, primitivas de runtime o un verificador externo. Una prueba solo es tan sólida como cada componente al que se permite aportar resultados de confianza. En Lean, los procedimientos de decisión nativos intercambian una evaluación más rápida por una base de computación confiable (TCB) más amplia: el compilador y las definiciones con implementaciones nativas pasan a ser relevantes para la integridad de las pruebas.<sup>[[3]](#references)</sup>

## Evaluación diferencial lógica/nativa

Prioriza las primitivas cuya implementación ejecutable difiera de su modelo lógico (por ejemplo, intrínsecos del compilador, interfaces de funciones externas, sustituciones en runtime y definiciones marcadas con `@[implemented_by]`). Evalúa diferencialmente el **mismo término cerrado** mediante las rutas lógica y compilada, y considera cualquier discrepancia de valor, excepción o terminación como un hallazgo de seguridad.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Entre las clases útiles de valores límite se incluyen:<sup>[[1]](#references)[[4]](#references)</sup>

- índices alrededor de `0`, la longitud de la entrada, el límite de la palabra de máquina y valores como `2^63` o superiores;
- rangos de cero o un byte, `start = end`, `start > end` y posiciones muy posteriores al objeto;
- entradas vacías y no vacías, cadenas multibyte, límites no válidos y operaciones aritméticas que puedan truncarse al compilar;
- valores respaldados por el heap cuando una primitiva nativa tenga un comportamiento de propiedad o préstamo ausente en el modelo lógico.

El siguiente patrón reducido de Lean ilustra el problema encontrado en `String.Pos.Raw.extract`: el código nativo vulnerable devolvía la cadena original para un rango de un byte enorme, mientras que la reducción definicional devolvía la cadena vacía. Esta discrepancia semántica se corrigió por separado del defecto relacionado con la seguridad de memoria.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>

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

Este patrón se generaliza más allá de las cadenas: si la evaluación lógica demuestra `E = A` y la evaluación nativa de confianza demuestra `E = B`, la transitividad produce `A = B`. Cuando `A` y `B` son observacionalmente distintos, esto da `False`; entonces `False.elim` (el principio de explosión) puede demostrar cualquier proposición objetivo. El kernel no necesita tener una regla de reducción incorrecta: el fallo de integridad se produce porque un resultado respaldado por el compilador entró en la lógica a través de un axioma.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

## Auditoría del TCB ampliado en Lean

No uses las marcas de verificación del editor ni una compilación exitosa como única validación de una prueba que no sea de confianza. Inspecciona el cierre completo de dependencias de cada teorema crítico para la seguridad con `#print axioms`; las directrices de validación de Lean identifican los nombres `_native` como dependencias de evaluación nativa, `sorryAx` como una prueba incompleta y otros nombres no estándar como axiomas personalizados.<sup>[[3]](#references)</sup>

```lean
#print axioms targetTheorem
```

Por ejemplo, una dependencia generada similar a la siguiente significa que la ejecución compilada aportó un resultado supuesto en lugar de una prueba derivada únicamente mediante reducción del kernel:<sup>[[1]](#references)[[4]](#references)</sup>

```text
targetTheorem._native.native_decide.ax_1_1
```

Durante la revisión del código fuente, busca procedimientos de decisión nativos y mecanismos explícitos para eludir las verificaciones, pero confirma el resultado con `#print axioms`, porque las dependencias pueden ser indirectas o generarse automáticamente:<sup>[[3]](#references)</sup>

```bash
rg -n 'native_decide|decide\s+\+native|bv_decide|sorry|axiom' .
```

Distingue las capas al clasificar un hallazgo:<sup>[[3]](#references)</sup>

1. **Integridad de las declaraciones:** verifica que la notación, las instancias de clases de tipos, las importaciones y las definiciones expresen la afirmación prevista.
2. **Dependencias de la prueba:** rechaza o revisa explícitamente los axiomas inesperados, especialmente los axiomas de evaluación nativa generados.
3. **Reejecución del kernel:** después de `lake build`, ejecuta `lean4checker --fresh <Module>` para volver a ejecutar las declaraciones de los archivos `.olean`.
4. **Validación de pruebas hostiles:** compila el código no confiable en un sandbox y usa `lake comparator` con checkers externos frente a una declaración de desafío confiable.

`lean4checker` ofrece una defensa en profundidad útil, pero confía en la corrección estructural de los archivos `.olean`, y ejecutar código meta de Lean no confiable puede comprometer por sí mismo el entorno de verificación. Para pruebas de alto riesgo, comparator exporta la prueba fuera del sandbox, verifica la declaración frente al desafío confiable y puede volver a ejecutarla mediante checkers implementados de forma independiente; la diversidad de implementaciones reduce la probabilidad de que un defecto en un compilador, runtime o kernel valide el mismo resultado falso en todas partes.<sup>[[3]](#references)</sup>

## References

- [1] [Desajuste entre el modelo y el runtime de `String.Pos.Raw.extract` y use-after-free - issue #14684 de Lean](https://github.com/leanprover/lean4/issues/14684)
- [2] [Corregir el desajuste entre el modelo y el runtime de `String.Pos.Raw.extract` - PR #14717 de Lean](https://github.com/leanprover/lean4/pull/14717)
- [3] [Referencia del lenguaje Lean: validar una prueba de Lean](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [4] [Una «prueba» del último teorema de Fermat que cabe en el margen](https://blog.trailofbits.com/2026/09/09/a-proof-of-fermats-last-theorem-that-fits-the-margin/)
{{#include ../banners/hacktricks-training.md}}
