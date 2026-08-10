# Pruebas de mutación para Smart Contracts (slither-mutate, mewt, MuTON)

Las pruebas de mutación "ponen a prueba tus tests" al introducir sistemáticamente pequeños cambios (mutantes) en el código del contrato y volver a ejecutar la suite de tests. Si un test falla, el mutante muere. Si los tests siguen pasando, el mutante sobrevive, lo que revela un punto ciego que la cobertura de líneas o ramas no puede detectar.

Idea clave: la cobertura muestra que se ejecutó el código; las pruebas de mutación muestran si el comportamiento está realmente comprobado.<sup>[[2]](#references)</sup>

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
Las pruebas unitarias que solo comprueban un valor por debajo y otro por encima del umbral pueden alcanzar una cobertura de líneas/ramas del 100 % sin verificar el límite de igualdad (`==`). Una refactorización a `deposit >= 2 ether` seguiría superando dichas pruebas, rompiendo silenciosamente la lógica del protocolo.<sup>[[2]](#references)</sup>

Mutation testing expone esta brecha al mutar la condición y verificar que las pruebas fallen.

En smart contracts, los mutants supervivientes suelen corresponder a comprobaciones faltantes relacionadas con:
- Autorización y límites de roles
- Invariantes de contabilidad/transferencia de valor
- Condiciones de revert y rutas de fallo
- Condiciones límite (`==`, valores cero, arrays vacíos, valores máximos/mínimos)

## Mutation operators con mayor señal de seguridad

Clases de mutación útiles para auditar contratos:<sup>[[1]](#references)[[2]](#references)</sup>
- **Alta severidad**: reemplazar instrucciones por `revert()` para exponer rutas no ejecutadas
- **Severidad media**: comentar líneas/eliminar lógica para revelar efectos secundarios no verificados
- **Baja severidad**: cambios sutiles de operadores o constantes, como `>=` -> `>` o `+` -> `-`
- Otras ediciones comunes: reemplazo de asignaciones, inversión de booleanos, negación de condiciones y cambios de tipo

Objetivo práctico: eliminar todos los mutants relevantes y justificar explícitamente los supervivientes que sean irrelevantes o semánticamente equivalentes.

## Por qué la mutación consciente de la sintaxis es mejor que regex

Los motores de mutación antiguos dependían de regex o de reescrituras orientadas a líneas. Esto funciona, pero presenta limitaciones importantes:<sup>[[1]](#references)</sup>
- Las instrucciones multilínea son difíciles de mutar de forma segura
- No se comprende la estructura del lenguaje, por lo que los comentarios/tokens pueden seleccionarse incorrectamente
- Generar todas las variantes posibles sobre una línea poco adecuada desperdicia grandes cantidades de tiempo de ejecución

Las herramientas basadas en AST o Tree-sitter mejoran esto al dirigirse a nodos estructurados en lugar de líneas sin procesar:<sup>[[1]](#references)</sup>
- **slither-mutate** usa el AST de Solidity de Slither.<sup>[[4]](#references)</sup>
- **mewt** usa Tree-sitter como núcleo independiente del lenguaje.<sup>[[6]](#references)</sup>
- **MuTON** se basa en `mewt` y añade compatibilidad de primera clase con lenguajes de TON como FunC, Tolk y Tact.<sup>[[7]](#references)</sup>

Esto hace que las construcciones multilínea y las mutaciones a nivel de expresión sean mucho más fiables que los enfoques basados únicamente en regex.

## Ejecución de mutation testing con slither-mutate

Requisitos: Slither v0.10.2+.

- Listar opciones y mutators:
```bash
slither-mutate --help
slither-mutate --list-mutators
```
- Ejemplo de Foundry (captura los resultados y conserva un registro completo):<sup>[[2]](#references)</sup>
```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```
- Si no usas Foundry, reemplaza `--test-cmd` por la forma en que ejecutas las pruebas (por ejemplo, `npx hardhat test`, `npm test`).

Los artifacts se almacenan en `./mutation_campaign` de forma predeterminada. Los mutantes no detectados (supervivientes) se copian allí para su inspección.<sup>[[5]](#references)</sup>

### Comprender el resultado

Las líneas del informe tienen este formato:
```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```
- La etiqueta entre corchetes es el alias del mutator (p. ej., `CR` = Comment Replacement).
- `UNCAUGHT` significa que las pruebas pasaron con el comportamiento mutado → falta una aserción.

## Reducción del tiempo de ejecución: priorizar mutants de impacto

Las campañas de mutation testing pueden tardar horas o días. Consejos para reducir el coste:<sup>[[1]](#references)[[2]](#references)</sup>
- Alcance: empieza solo con los contratos/directorios críticos y amplía después.
- Prioriza los mutators: si sobrevive un mutant de alta prioridad en una línea (por ejemplo, `revert()` o comment-out), omite las variantes de menor prioridad para esa línea.
- Usa campañas en dos fases: ejecuta primero pruebas específicas y rápidas; después, vuelve a probar solo los mutants uncaught con la suite completa.
- Asocia los objetivos de mutation con comandos de prueba específicos cuando sea posible (por ejemplo, código de auth -> pruebas de auth).
- Limita las campañas a mutants de severidad alta/media cuando el tiempo sea limitado.
- Ejecuta las pruebas en paralelo si tu runner lo permite; almacena en caché las dependencias/builds.
- Fail-fast: detén la ejecución pronto cuando un cambio demuestre claramente una brecha en las aserciones.

Las matemáticas del tiempo de ejecución son brutales: `1000 mutants x 5-minute tests ~= 83 hours`, por lo que el diseño de la campaña importa tanto como el propio mutator.<sup>[[1]](#references)</sup>

## Campañas persistentes y triage a escala

Una debilidad de los workflows antiguos es volcar los resultados únicamente a `stdout`. En campañas largas, esto dificulta pausar/reanudar, filtrar y revisar los resultados.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` mejoran este aspecto al almacenar los mutants y sus resultados en campañas respaldadas por SQLite. Beneficios:<sup>[[1]](#references)</sup>
- Pausar y reanudar ejecuciones largas sin perder el progreso
- Filtrar únicamente los mutants uncaught de un archivo o una clase de mutation específicos
- Exportar/traducir los resultados a SARIF para herramientas de revisión
- Proporcionar al triage asistido por AI conjuntos de resultados más pequeños y filtrados en lugar de logs sin procesar del terminal

Los resultados persistentes son especialmente útiles cuando mutation testing pasa a formar parte de un pipeline de auditoría en lugar de una revisión manual puntual.

## Workflow de triage para mutants supervivientes

1) Inspecciona la línea y el comportamiento mutados.
- Reprodúcelo localmente aplicando la línea mutada y ejecutando una prueba específica.

2) Refuerza las pruebas para comprobar el estado, no solo los valores devueltos.
- Añade comprobaciones de los límites de igualdad (p. ej., prueba el umbral `==`).
- Comprueba las post-condiciones: balances, total supply, efectos de autorización y eventos emitidos.

3) Sustituye los mocks excesivamente permisivos por un comportamiento realista.
- Asegúrate de que los mocks hagan cumplir las transferencias, las rutas de error y las emisiones de eventos que ocurren on-chain.

4) Añade invariantes para las pruebas fuzz.
- P. ej., conservación del valor, balances no negativos, invariantes de autorización y supply monotónico cuando corresponda.

5) Separa los true positives de los semantic no-ops.
- Ejemplo: `x > 0` -> `x != 0` no tiene sentido cuando `x` es unsigned.

6) Vuelve a ejecutar la campaña hasta que los supervivientes sean eliminados o se justifiquen explícitamente.

## Caso práctico: revelar aserciones de estado ausentes (protocolo Arkis)

Una campaña de mutation testing durante una auditoría del protocolo DeFi Arkis detectó supervivientes como:<sup>[[2]](#references)[[3]](#references)</sup>
```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```
Comentar la asignación no rompió las pruebas, lo que demostró la ausencia de aserciones sobre el estado posterior. Causa raíz: el código confiaba en un `_cmd.value` controlado por el usuario en lugar de validar las transferencias reales de tokens. Un atacante podría desincronizar las transferencias esperadas y reales para drenar fondos. Resultado: riesgo de alta severidad para la solvencia del protocolo.<sup>[[2]](#references)[[3]](#references)</sup>

Guía: trata los mutantes supervivientes que afecten a las transferencias de valor, la contabilidad o el control de acceso como de alto riesgo hasta que sean eliminados.

## No generes pruebas a ciegas para eliminar cada mutante

La generación de pruebas basada en mutaciones puede ser contraproducente si la implementación actual es incorrecta. Ejemplo: mutar `priority >= 2` a `priority > 2` cambia el comportamiento, pero la solución correcta no siempre es "escribir una prueba para `priority == 2`". Ese comportamiento podría ser precisamente el bug.<sup>[[1]](#references)</sup>

Flujo de trabajo más seguro:
- Usa los mutantes supervivientes para identificar requisitos ambiguos
- Valida el comportamiento esperado a partir de las especificaciones, la documentación del protocolo o los revisores
- Solo después codifica el comportamiento como una prueba/invariante

De lo contrario, te arriesgas a fijar accidentes de implementación en la suite de pruebas y obtener una falsa sensación de confianza.

## Lista de comprobación práctica

- Ejecuta una campaña específica:
- `slither-mutate ./src/contracts --test-cmd="forge test"`
- Prefiere mutadores conscientes de la sintaxis (AST/Tree-sitter) frente a mutaciones basadas únicamente en regex cuando estén disponibles.
- Clasifica los mutantes supervivientes y escribe pruebas/invariantes que fallen con el comportamiento mutado.
- Verifica saldos, supply, autorizaciones y eventos.
- Añade pruebas de límites (`==`, overflows/underflows, zero-address, zero-amount, arrays vacíos).
- Sustituye los mocks poco realistas; simula modos de fallo.
- Persiste los resultados cuando las herramientas lo permitan y filtra los mutantes no detectados antes de clasificarlos.
- Usa campañas en dos fases o por objetivo para mantener el tiempo de ejecución bajo control.
- Itera hasta que todos los mutantes sean eliminados o estén justificados con comentarios y argumentos.

## References

- [1] [Mutation testing for the agentic era](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Usa mutation testing para encontrar los bugs que tus pruebas no detectan (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Revisión de seguridad de Arkis DeFi Prime Brokerage (Apéndice C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Documentación de Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
