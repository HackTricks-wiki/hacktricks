# Mutation Testing for Solidity with Slither (slither-mutate)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "prueba tus pruebas" introduciendo sistemáticamente pequeños cambios (mutantes) en tu código Solidity y volviendo a ejecutar tu suite de pruebas. Si una prueba falla, el mutante es eliminado. Si las pruebas siguen pasando, el mutante sobrevive, revelando un punto ciego en tu suite de pruebas que la cobertura de líneas/ramas no puede detectar.

Idea clave: La cobertura muestra que el código fue ejecutado; mutation testing muestra si el comportamiento realmente está verificado.

## Por qué la cobertura puede engañar

Considera esta simple comprobación de umbral:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Las pruebas unitarias que solo comprueban un valor por debajo y otro por encima del umbral pueden alcanzar el 100% de cobertura de líneas/ramas mientras no verifican la condición de igualdad (==). Un refactor a `deposit >= 2 ether` seguiría pasando esas pruebas, rompiendo silenciosamente la lógica del protocolo.

Mutation testing expone esta brecha mutando la condición y verificando que tus pruebas fallen.

## Operadores mutation comunes de Solidity

La mutation engine de Slither aplica muchos pequeños cambios que alteran la semántica, tales como:
- Reemplazo de operadores: `+` ↔ `-`, `*` ↔ `/`, etc.
- Reemplazo de asignaciones: `+=` → `=`, `-=` → `=`
- Reemplazo de constantes: distinto de cero → `0`, `true` ↔ `false`
- Negación/reemplazo de condiciones dentro de `if`/bucles
- Comentar líneas completas (CR: Comment Replacement)
- Reemplazar una línea por `revert()`
- Intercambio de tipos de dato: p. ej., `int128` → `int64`

Objetivo: eliminar al 100% de los mutantes generados, o justificar los sobrevivientes con razonamiento claro.

## Ejecutando mutation testing con slither-mutate

Requisitos: Slither v0.10.2+.

- Listar opciones y mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Foundry example (capturar los resultados y mantener un registro completo):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Si no usas Foundry, reemplaza `--test-cmd` por la forma en que ejecutas las pruebas (p. ej., `npx hardhat test`, `npm test`).

Los artefactos y los informes se almacenan en `./mutation_campaign` por defecto. Los mutantes no capturados (sobrevivientes) se copian allí para su inspección.

### Entendiendo la salida

Las líneas del informe se ven así:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- La etiqueta entre corchetes es el alias del mutator (por ejemplo, `CR` = Comment Replacement).
- `UNCAUGHT` significa que las pruebas pasaron bajo el comportamiento mutado → aserción faltante.

## Reducir tiempo de ejecución: priorizar mutantes con impacto

Las campañas de mutación pueden durar horas o días. Consejos para reducir coste:
- Scope: empieza con contratos/directorios críticos únicamente, luego expande.
- Priorizar mutators: si un mutante de alta prioridad en una línea sobrevive (p. ej., la línea completa comentada), puedes omitir variantes de menor prioridad para esa línea.
- Paraleliza tests si tu runner lo permite; cachea dependencias/builds.
- Fail-fast: detente temprano cuando un cambio demuestre claramente una brecha de aserción.

## Flujo de triage para mutantes supervivientes

1) Inspecciona la línea mutada y el comportamiento.
- Reproduce localmente aplicando la línea mutada y ejecutando una prueba focalizada.

2) Fortalece las pruebas para asertar estado, no solo valores de retorno.
- Añade comprobaciones de igualdad-límite (p. ej., test threshold `==`).
- Aserta post-condiciones: balances, total supply, efectos de autorización y eventos emitidos.

3) Sustituye mocks demasiado permisivos por comportamiento realista.
- Asegura que los mocks hagan cumplir transfers, caminos de fallo y emisiones de eventos que ocurren on-chain.

4) Añade invariantes para fuzz tests.
- P. ej., conservación del valor, balances no negativos, invariantes de autorización, suministro monótono cuando corresponda.

5) Re-run slither-mutate hasta que los supervivientes sean eliminados o justificados explícitamente.

## Estudio de caso: revelar aserciones de estado faltantes (protocolo Arkis)

Una campaña de mutación durante una auditoría del protocolo Arkis DeFi sacó a la luz supervivientes como:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Comentar la asignación no rompió las pruebas, lo que demuestra la falta de aserciones sobre el estado posterior. Causa raíz: el código confió en un `_cmd.value` controlado por el usuario en lugar de validar transferencias reales de tokens. Un atacante podría desincronizar las transferencias esperadas frente a las reales para vaciar fondos. Resultado: riesgo de alta severidad para la solvencia del protocolo.

Orientación: Trate a los mutantes supervivientes que afectan transferencias de valor, contabilidad o control de acceso como de alto riesgo hasta que sean eliminados.

## Lista de verificación práctica

- Ejecute una campaña dirigida:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Clasifique los mutantes supervivientes y escriba pruebas/invariantes que fallen bajo el comportamiento mutado.
- Aserte saldos, suministro, autorizaciones y eventos.
- Agregue pruebas límite (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Reemplace mocks poco realistas; simule modos de fallo.
- Itere hasta que todos los mutantes sean eliminados o justificados con comentarios y fundamento.

## Referencias

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../banners/hacktricks-training.md}}
