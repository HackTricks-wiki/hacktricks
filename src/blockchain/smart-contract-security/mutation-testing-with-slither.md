# Mutation Testing for Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing "tests your tests" mediante la introducción sistemática de pequeños cambios (mutants) en el código del contract y volviendo a ejecutar la test suite. Si un test falla, el mutant es killed. Si los tests siguen pasando, el mutant survives, revealing a blind spot that line/branch coverage cannot detect.

Key idea: Coverage muestra que el código fue ejecutado; mutation testing muestra si el comportamiento está realmente asserted.

## Why coverage can deceive

Consider this simple threshold check:
```solidity
function verifyMinimumDeposit(uint256 deposit) public returns (bool) {
if (deposit >= 1 ether) {
return true;
} else {
return false;
}
}
```
Las pruebas unitarias que solo verifican un valor por debajo y un valor por encima del umbral pueden alcanzar un 100% de coverage de líneas/ramas mientras no afirman el boundary de igualdad (==). Un refactor a `deposit >= 2 ether` seguiría pasando esas pruebas, rompiendo silenciosamente la lógica del protocolo.

Mutation testing expone esta brecha mutando la condición y verificando que las pruebas fallen.

Para smart contracts, los mutants que sobreviven suelen corresponder a checks faltantes alrededor de:
- Authorization y límites de roles
- Invariantes de accounting/value-transfer
- Revert conditions y failure paths
- Boundary conditions (`==`, valores cero, arrays vacíos, valores max/min)

## Mutation operators con la señal de seguridad más alta

Clases de mutación útiles para auditar contratos:
- **Alta severidad**: reemplazar statements con `revert()` para exponer caminos no ejecutados
- **Severidad media**: comentar líneas / eliminar lógica para revelar side effects no verificados
- **Baja severidad**: cambios sutiles de operadores o constantes como `>=` -> `>` o `+` -> `-`
- Otros cambios comunes: reemplazo de asignación, boolean flips, negación de condiciones y cambios de tipo

Objetivo práctico: eliminar todos los mutants significativos y justificar explícitamente los que sobreviven y son irrelevantes o semánticamente equivalentes.

## Por qué la mutación aware de sintaxis es mejor que regex

Los motores de mutación antiguos dependían de regex o rewrites orientados a líneas. Eso funciona, pero tiene limitaciones importantes:
- Las statements multilínea son difíciles de mutar de forma segura
- La estructura del lenguaje no se entiende, así que comments/tokens pueden ser objetivo de forma deficiente
- Generar todas las variantes posibles en una línea débil desperdicia gran cantidad de runtime

Las herramientas basadas en AST o Tree-sitter mejoran esto al apuntar a nodos estructurados en lugar de líneas crudas:
- **slither-mutate** usa el Solidity AST de Slither
- **mewt** usa Tree-sitter como núcleo agnóstico al lenguaje
- **MuTON** se basa en `mewt` y añade soporte de primera clase para lenguajes de TON como FunC, Tolk y Tact

Esto hace que los constructs multilínea y las mutaciones a nivel de expresión sean mucho más fiables que los enfoques solo con regex.

## Ejecutar mutation testing con slither-mutate

Requisitos: Slither v0.10.2+.

- Listar opciones y mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Ejemplo de Foundry (capturar resultados y mantener un log completo):
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Si no usas Foundry, reemplaza `--test-cmd` con cómo ejecutas los tests (por ejemplo, `npx hardhat test`, `npm test`).

Los artifacts se almacenan en `./mutation_campaign` por defecto. Los mutants no detectados (sobrevivientes) se copian allí para su inspección.

### Entendiendo la salida

Las líneas del informe se ven así:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- La etiqueta entre corchetes es el alias del mutator (por ejemplo, `CR` = Comment Replacement).
- `UNCAUGHT` significa que los tests pasaron bajo el comportamiento mutado → falta una assertion.

## Reducir runtime: prioriza mutants impactantes

Las campañas de mutation pueden llevar horas o días. Consejos para reducir el costo:
- Scope: empieza solo con contratos/directorios críticos y luego amplía.
- Prioriza mutators: si un mutant de alta prioridad en una línea sobrevive (por ejemplo `revert()` o comment-out), omite variantes de menor prioridad para esa línea.
- Usa campañas en dos fases: ejecuta primero tests enfocados/rápidos y luego vuelve a probar solo los uncaught mutants con el suite completo.
- Mapea los mutation targets a comandos de test específicos cuando sea posible (por ejemplo, auth code -> auth tests).
- Restringe las campañas a mutants de severidad high/medium cuando el tiempo sea limitado.
- Paraleliza los tests si tu runner lo permite; cachea dependencies/builds.
- Fail-fast: deténte pronto cuando un cambio demuestre claramente una assertion gap.

La matemática del runtime es brutal: `1000 mutants x 5-minute tests ~= 83 hours`, así que el diseño de la campaña importa tanto como el mutator en sí.

## Campañas persistentes y triage a escala

Una debilidad de los workflows antiguos es volcar los resultados solo a `stdout`. Para campañas largas, esto dificulta pausar/reanudar, filtrar y revisar.

`mewt`/`MuTON` mejoran esto almacenando mutants y resultados en campañas respaldadas por SQLite. Beneficios:
- Pausar y reanudar ejecuciones largas sin perder progreso
- Filtrar solo uncaught mutants en un archivo específico o clase de mutación
- Exportar/translate resultados a SARIF para herramientas de review
- Dar a AI-assisted triage conjuntos de resultados más pequeños y filtrados en lugar de logs crudos del terminal

Los resultados persistentes son especialmente útiles cuando mutation testing pasa a formar parte de un audit pipeline en lugar de una revisión manual puntual.

## Workflow de triage para mutants que sobreviven

1) Inspecciona la línea mutada y el comportamiento.
- Reproduce localmente aplicando la línea mutada y ejecutando un test enfocado.

2) Refuerza los tests para afirmar estado, no solo valores de retorno.
- Añade checks de boundary de igualdad (por ejemplo, test del threshold `==`).
- Afirmar post-conditions: balances, total supply, efectos de authorization y eventos emitidos.

3) Sustituye mocks demasiado permisivos por comportamiento realista.
- Asegura que los mocks hagan cumplir transfers, failure paths y emisiones de eventos que ocurren on-chain.

4) Añade invariants para fuzz tests.
- Por ejemplo, conservación de valor, balances no negativos, invariants de authorization, supply monótono donde aplique.

5) Separa true positives de semantic no-ops.
- Ejemplo: `x > 0` -> `x != 0` es insignificante cuando `x` es unsigned.

6) Vuelve a ejecutar la campaña hasta que los survivors mueran o estén justificados explícitamente.

## Caso de estudio: revelar missing state assertions (Arkis protocol)

Una campaña de mutation durante una audit del protocolo DeFi Arkis mostró survivors como:
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Comentar la asignación no rompió los tests, lo que demuestra la falta de aserciones post-state. Causa raíz: el código confiaba en un `_cmd.value` controlado por el usuario en lugar de validar las transferencias reales de tokens. Un atacante podría desincronizar las transferencias esperadas frente a las reales para drenar fondos. Resultado: riesgo de alta severidad para la solvencia del protocolo.

Guía: Trata los mutants sobrevivientes que afecten transferencias de valor, accounting, o control de acceso como de alto riesgo hasta que sean eliminados.

## No generes tests a ciegas para matar cada mutant

La generación de tests guiada por mutation puede salir mal si la implementación actual es incorrecta. Ejemplo: mutar `priority >= 2` a `priority > 2` cambia el comportamiento, pero la corrección adecuada no siempre es "escribe un test para `priority == 2`". Ese comportamiento podría ser el bug.

Flujo de trabajo más seguro:
- Usa los mutants sobrevivientes para identificar requisitos ambiguos
- Valida el comportamiento esperado a partir de specs, documentación del protocolo o revisores
- Solo entonces codifica el comportamiento como un test/invariant

De lo contrario, corres el riesgo de convertir accidentes de implementación en la suite de tests y ganar una falsa sensación de confianza.

## Lista práctica de verificación

- Ejecuta una campaña dirigida:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Prefiere mutators con conciencia de sintaxis (AST/Tree-sitter) sobre mutation basada solo en regex cuando esté disponible.
- Clasifica los survivors y escribe tests/invariants que fallen bajo el comportamiento mutado.
- Aserta balances, supply, autorizaciones y eventos.
- Añade tests de límites (`==`, overflows/underflows, zero-address, zero-amount, arrays vacíos).
- Sustituye mocks poco realistas; simula modos de fallo.
- Conserva los resultados cuando la herramienta lo soporte, y filtra mutants no capturados antes de la clasificación.
- Usa campañas de dos fases o por objetivo para mantener el runtime manejable.
- Itera hasta que todos los mutants sean eliminados o justificados con comentarios y rationale.

## Referencias

- [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [Use mutation testing to find the bugs your tests don't catch (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [Arkis DeFi Prime Brokerage Security Review (Appendix C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [Slither (GitHub)](https://github.com/crytic/slither)
- [Slither Mutator documentation](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [mewt](https://github.com/trailofbits/mewt)
- [MuTON](https://github.com/trailofbits/muton)

{{#include ../../banners/hacktricks-training.md}}
