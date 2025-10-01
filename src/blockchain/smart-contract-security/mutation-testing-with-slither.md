# Mutation Testing para Solidity con Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" al introducir sistemáticamente pequeños cambios (mutants) en tu código Solidity y volver a ejecutar tu suite de pruebas. Si una prueba falla, el mutant es eliminado. Si las pruebas siguen pasando, el mutant sobrevive, revelando un punto ciego en tu suite de pruebas que la cobertura de líneas/ramas no puede detectar.

Idea clave: La cobertura muestra que el código se ejecutó; mutation testing muestra si el comportamiento está realmente verificado.

## Por qué la cobertura puede engañar

Considera esta sencilla comprobación de umbral:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Las pruebas unitarias que solo comprueban un valor por debajo y otro por encima del umbral pueden alcanzar el 100% de cobertura de líneas/ramas mientras no afirman la igualdad límite (==). Un refactor a `deposit >= 2 ether` seguiría pasando esas pruebas, rompiendo silenciosamente la lógica del protocolo.

Las pruebas de mutación exponen esta brecha al mutar la condición y verificar que tus tests fallen.

## Operadores de mutación comunes en Solidity

El motor de mutación de Slither aplica muchos pequeños cambios que alteran la semántica, como:
- Reemplazo de operadores: `+` ↔ `-`, `*` ↔ `/`, etc.
- Reemplazo de asignación: `+=` → `=`, `-=` → `=`
- Reemplazo de constantes: valor distinto de cero → `0`, `true` ↔ `false`
- Negación/reemplazo de condiciones dentro de `if`/bucles
- Comentar líneas completas (CR: Comment Replacement)
- Reemplazar una línea por `revert()`
- Intercambio de tipos de datos: p. ej., `int128` → `int64`

Objetivo: eliminar el 100% de los mutantes generados, o justificar los supervivientes con un razonamiento claro.

## Ejecutar pruebas de mutación con slither-mutate

Requisitos: Slither v0.10.2+.

- Listar opciones y mutadores:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- ejemplo de Foundry (capturar resultados y mantener un registro completo):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Si no usas Foundry, reemplaza `--test-cmd` por la forma en que ejecutas las pruebas (p. ej., `npx hardhat test`, `npm test`).

Los artefactos e informes se almacenan en `./mutation_campaign` por defecto. Los mutantes no detectados (sobrevivientes) se copian allí para su inspección.

### Entendiendo la salida

Las líneas del informe se ven así:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- La etiqueta entre corchetes es el mutator alias (p. ej., `CR` = Comment Replacement).
- `UNCAUGHT` significa que las pruebas pasaron bajo el comportamiento mutado → falta una aserción.

## Reducir el tiempo de ejecución: priorizar mutantes con impacto

Las campañas de mutación pueden durar horas o días. Consejos para reducir el coste:
- Alcance: comienza solo con contratos/directorios críticos, luego expande.
- Prioriza mutadores: si un mutante de alta prioridad en una línea sobrevive (p. ej., línea entera comentada), puedes omitir variantes de menor prioridad para esa línea.
- Paraleliza las pruebas si tu runner lo permite; almacena en caché dependencias/compilaciones.
- Fail-fast: detente pronto cuando un cambio demuestre claramente una brecha en las aserciones.

## Flujo de triage para mutantes supervivientes

1) Inspecciona la línea mutada y el comportamiento.
- Reproduce localmente aplicando la línea mutada y ejecutando una prueba focalizada.

2) Fortalece las pruebas para afirmar el estado, no solo los valores de retorno.
- Añade comprobaciones de igualdad y límites (p. ej., test threshold `==`).
- Asegura post-condiciones: balances, suministro total, efectos de autorización y eventos emitidos.

3) Sustituye mocks demasiado permisivos por comportamiento realista.
- Asegúrate de que los mocks hagan cumplir transferencias, rutas de fallo y emisiones de eventos que ocurren on-chain.

4) Añade invariantes para fuzz tests.
- Ej.: conservación del valor, balances no negativos, invariantes de autorización, suministro monótono cuando sea aplicable.

5) Vuelve a ejecutar slither-mutate hasta que los supervivientes sean eliminados o estén justificados explícitamente.

## Caso de estudio: revelando aserciones de estado faltantes (Arkis protocol)

Una campaña de mutación durante una auditoría del Arkis DeFi protocol mostró supervivientes como:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Comentar la asignación no rompió los tests, lo que demuestra que faltan aserciones del estado posterior. Causa raíz: el código confiaba en un `_cmd.value` controlado por el usuario en lugar de validar las transferencias reales de tokens. Un atacante podría desincronizar las transferencias esperadas frente a las reales para vaciar fondos. Resultado: riesgo de alta severidad para la solvencia del protocolo.

Guía: Trata los mutantes sobrevivientes que afectan transferencias de valor, contabilidad o control de acceso como de alto riesgo hasta que sean eliminados.

## Lista de comprobación práctica

- Ejecuta una campaña dirigida:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Clasifica los mutantes sobrevivientes y escribe tests/invariantes que fallen con el comportamiento mutado.
- Comprueba saldos, suministro, autorizaciones y eventos.
- Añade tests límite (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Sustituye mocks poco realistas; simula modos de fallo.
- Itera hasta que todos los mutantes sean eliminados o justificados con comentarios y razonamiento.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
