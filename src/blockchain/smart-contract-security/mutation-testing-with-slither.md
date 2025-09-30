# Pruebas de mutación para Solidity con Slither (slither-mutate)

{{#include ../../../banners/hacktricks-training.md}}

La prueba de mutación "prueba tus pruebas" introduciendo sistemáticamente pequeños cambios (mutantes) en tu código Solidity y volviendo a ejecutar tu suite de pruebas. Si una prueba falla, el mutante queda eliminado. Si las pruebas siguen pasando, el mutante sobrevive, revelando un punto ciego en tu suite de pruebas que la cobertura de línea/rama no puede detectar.

Idea clave: la cobertura muestra que el código se ejecutó; la prueba de mutación muestra si el comportamiento realmente está verificado.

## Por qué la cobertura puede ser engañosa

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
Las pruebas unitarias que solo verifican un valor por debajo y un valor por encima del umbral pueden alcanzar el 100% de cobertura de líneas y ramas mientras no comprueban la igualdad límite (==). Un refactor a `deposit >= 2 ether` seguiría pasando esas pruebas, rompiendo silenciosamente la lógica del protocolo.

Mutation testing expone esta brecha al mutar la condición y verificar que tus pruebas fallen.

## Operadores comunes de mutación en Solidity

Slither’s mutation engine aplica muchas pequeñas ediciones que cambian la semántica, como:
- Reemplazo de operadores: `+` ↔ `-`, `*` ↔ `/`, etc.
- Reemplazo de asignación: `+=` → `=`, `-=` → `=`
- Reemplazo de constantes: no cero → `0`, `true` ↔ `false`
- Negación/reemplazo de condiciones dentro de `if`/loops
- Comentar líneas completas (CR: Comment Replacement)
- Reemplazar una línea por `revert()`
- Intercambio de tipos de datos: p. ej., `int128` → `int64`

Objetivo: eliminar el 100% de los mutantes generados, o justificar a los supervivientes con razonamiento claro.

## Running mutation testing with slither-mutate

Requisitos: Slither v0.10.2+.

- Listar opciones y mutadores:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Ejemplo de Foundry (capturar los resultados y mantener un registro completo):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Si no usas Foundry, reemplaza `--test-cmd` por la forma en que ejecutas las pruebas (p. ej., `npx hardhat test`, `npm test`).

Los artefactos y los informes se almacenan en `./mutation_campaign` por defecto. Los mutantes no detectados (que sobreviven) se copian allí para su inspección.

### Entendiendo la salida

Las líneas del informe se ven así:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- La etiqueta entre corchetes es el alias del mutador (p. ej., `CR` = Comment Replacement).
- `UNCAUGHT` significa que las pruebas pasaron bajo el comportamiento mutado → falta de aserción.

## Reducir el tiempo de ejecución: priorizar mutantes de mayor impacto

Las campañas de mutación pueden durar horas o días. Consejos para reducir el costo:
- Alcance: Empieza solo con los contratos/directorios críticos, luego expande.
- Priorizar mutators: Si un mutante de alta prioridad en una línea sobrevive (p. ej., línea entera comentada), puedes omitir variantes de menor prioridad para esa línea.
- Paraleliza las pruebas si tu runner lo permite; cachea dependencias/builds.
- Fail-fast: detén temprano cuando un cambio demuestre claramente una brecha de aserción.

## Flujo de triage para mutantes sobrevivientes

1) Inspecciona la línea mutada y su comportamiento.
- Reproduce localmente aplicando la línea mutada y ejecutando una prueba focalizada.

2) Fortalece las pruebas para afirmar el estado, no solo los valores retornados.
- Añade comprobaciones de igualdad/límite (p. ej., test threshold `==`).
- Aserta post-condiciones: balances, total supply, efectos de autorización y eventos emitidos.

3) Sustituye mocks demasiado permisivos por comportamiento realista.
- Asegúrate de que los mocks hagan cumplir transfers, failure paths, y emisiones de eventos que ocurren on-chain.

4) Añade invariantes para fuzz tests.
- Ej.: conservación del valor, balances no negativos, invariantes de autorización, monotonic supply cuando aplique.

5) Vuelve a ejecutar slither-mutate hasta que los sobrevivientes sean eliminados o estén justificados explícitamente.

## Estudio de caso: revelar aserciones de estado faltantes (protocolo Arkis)

Una campaña de mutación durante una auditoría del protocolo Arkis DeFi reveló sobrevivientes como:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Comentar la asignación no rompió los tests, lo que demuestra la falta de aserciones de post-estado. Causa raíz: el código confiaba en un `_cmd.value` controlado por el usuario en lugar de validar las transferencias reales de tokens. Un atacante podría desincronizar las transferencias esperadas frente a las reales para drenar fondos. Resultado: riesgo de alta severidad para la solvencia del protocolo.

Guía: Considere de alto riesgo a los mutantes supervivientes que afecten transferencias de valor, contabilidad o control de acceso hasta que sean eliminados.

## Practical checklist

- Ejecutar una campaña dirigida:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Triar los supervivientes y escribir tests/invariantes que fallarían bajo el comportamiento mutado.
- Compruebe saldos, supply, autorizaciones y eventos.
- Agregar pruebas límite (`==`, overflows/underflows, zero-address, zero-amount, empty arrays).
- Reemplace mocks poco realistas; simule modos de fallo.
- Iterar hasta que todos los mutantes sean eliminados o justificados con comentarios y su razonamiento.

## References

- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)

{{#include ../../../banners/hacktricks-training.md}}
