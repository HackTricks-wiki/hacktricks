# Mutation Testing para Smart Contracts (slither-mutate, mewt, MuTON)

{{#include ../../banners/hacktricks-training.md}}

Mutation testing «prueba tus pruebas» al introducir sistemáticamente pequeños cambios (mutantes) en el código del contrato y volver a ejecutar el conjunto de pruebas. Si una prueba falla, el mutante muere. Si las pruebas siguen pasando, el mutante sobrevive, lo que revela un punto ciego que la cobertura de líneas o ramas no puede detectar.

Idea clave: la cobertura muestra que se ejecutó el código; mutation testing muestra si el comportamiento está realmente verificado mediante aserciones.<sup>[[2]](#references)</sup>

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

Las pruebas unitarias que solo comprueban un valor por debajo y otro por encima del umbral pueden alcanzar una cobertura del 100 % de líneas y ramas sin comprobar el límite de igualdad (==). Una refactorización a `deposit >= 2 ether` seguiría pasando esas pruebas y rompería silenciosamente la lógica del protocolo.<sup>[[2]](#references)</sup>

Mutation testing expone esta brecha al mutar la condición y verificar que las pruebas fallen.

En smart contracts, los mutantes que sobreviven suelen revelar comprobaciones ausentes relacionadas con:
- Autorización y límites de roles
- Invariantes de contabilidad y transferencia de valor
- Condiciones de revert y rutas de error
- Condiciones límite (`==`, valores cero, arrays vacíos, valores máximos/mínimos)

## Operadores de mutación con mayor señal de seguridad

Clases de mutación útiles para auditar contratos:<sup>[[1]](#references)[[2]](#references)</sup>
- **Alta severidad**: reemplazar instrucciones por `revert()` para revelar rutas no ejecutadas
- **Severidad media**: comentar líneas o eliminar lógica para revelar efectos secundarios no verificados
- **Baja severidad**: cambios sutiles de operadores o constantes, como `>=` -> `>` o `+` -> `-`
- Otras modificaciones habituales: reemplazo de asignaciones, cambios de booleanos, negación de condiciones y cambios de tipo

Objetivo práctico: eliminar todos los mutantes significativos y justificar explícitamente los que sobrevivan por ser irrelevantes o semánticamente equivalentes.

## Por qué la mutación consciente de la sintaxis es mejor que regex

Los motores de mutación antiguos se basaban en regex o reescrituras orientadas a líneas. Esto funciona, pero tiene limitaciones importantes:<sup>[[1]](#references)</sup>
- Es difícil mutar instrucciones multilínea de forma segura
- No se comprende la estructura del lenguaje, por lo que se pueden seleccionar mal comentarios o tokens
- Generar todas las variantes posibles en una línea con poca cobertura desperdicia mucho tiempo de ejecución

Las herramientas basadas en AST o Tree-sitter mejoran esto al seleccionar nodos estructurados en lugar de líneas sin procesar:<sup>[[1]](#references)</sup>
- **slither-mutate** usa el AST de Solidity de Slither.<sup>[[4]](#references)</sup>
- **mewt** usa Tree-sitter como núcleo independiente del lenguaje.<sup>[[6]](#references)</sup>
- **MuTON** se basa en `mewt` y añade compatibilidad nativa con lenguajes de TON como FunC, Tolk y Tact.<sup>[[7]](#references)</sup>

Esto hace que las construcciones multilínea y las mutaciones a nivel de expresión sean mucho más fiables que los enfoques basados únicamente en regex.

## Ejecutar mutation testing con slither-mutate

Requisitos: Slither v0.10.2+.

- Listar opciones y mutadores:

```bash
slither-mutate --help
slither-mutate --list-mutators
```

- Ejemplo de Foundry (capturar los resultados y conservar un registro completo):<sup>[[2]](#references)</sup>

```bash
slither-mutate ./src/contracts --test-cmd="forge test" &> >(tee mutation.results)
```

- Si no usas Foundry, reemplaza `--test-cmd` por el comando que uses para ejecutar las pruebas (p. ej., `npx hardhat test`, `npm test`).

Los artefactos se almacenan en `./mutation_campaign` de forma predeterminada. Los mutantes no detectados (supervivientes) se copian allí para inspeccionarlos.<sup>[[5]](#references)</sup>

### Cómo entender el resultado

Las líneas del informe tienen este aspecto:

```text
INFO:Slither-Mutate:Mutating contract ContractName
INFO:Slither-Mutate:[CR] Line 123: 'original line' ==> '//original line' --> UNCAUGHT
```

- La etiqueta entre corchetes es el alias del mutador (p. ej., `CR` = Comment Replacement).
- `UNCAUGHT` significa que las pruebas pasaron con el comportamiento mutado → falta una aserción.

## Reducir el tiempo de ejecución: priorizar los mutantes de mayor impacto

Las campañas de mutación pueden durar horas o días. Consejos para reducir el costo:<sup>[[1]](#references)[[2]](#references)</sup>
- Alcance: empieza solo con los contratos/directorios críticos y luego amplía el alcance.
- Prioriza los mutadores: si un mutante de alta prioridad en una línea sobrevive (por ejemplo, `revert()` o comentar el código), omite las variantes de menor prioridad para esa línea.
- Usa campañas en dos fases: ejecuta primero pruebas enfocadas y rápidas; después, vuelve a probar solo los mutantes no detectados con la suite completa.
- Cuando sea posible, asigna los objetivos de mutación a comandos de prueba específicos (por ejemplo, código de autenticación -> pruebas de autenticación).
- Si el tiempo apremia, limita las campañas a mutantes de gravedad alta o media.
- Ejecuta pruebas en paralelo si tu runner lo permite; almacena en caché las dependencias/compilaciones.
- Fail-fast: detén la ejecución pronto cuando un cambio demuestre claramente una brecha en las aserciones.

El cálculo del tiempo de ejecución es brutal: `1000 mutants x 5-minute tests ~= 83 hours`, así que el diseño de la campaña importa tanto como el propio mutador.<sup>[[1]](#references)</sup>

## Campañas persistentes y clasificación a escala

Una debilidad de los flujos de trabajo antiguos es que vuelcan los resultados solo en `stdout`. En campañas largas, esto dificulta pausar/reanudar, filtrar y revisar.<sup>[[1]](#references)</sup>

`mewt`/`MuTON` mejoran esto al almacenar mutantes y resultados en campañas respaldadas por SQLite. Ventajas:<sup>[[1]](#references)</sup>
- Pausar y reanudar ejecuciones largas sin perder el progreso
- Filtrar solo los mutantes no detectados en un archivo o una clase de mutación específicos
- Exportar/convertir los resultados a SARIF para herramientas de revisión
- Proporcionar a la clasificación asistida por IA conjuntos de resultados más pequeños y filtrados, en lugar de registros de terminal sin procesar

Los resultados persistentes son especialmente útiles cuando las pruebas de mutación pasan a formar parte de un pipeline de auditoría, en vez de ser una revisión manual puntual.

## Flujo de trabajo para clasificar mutantes supervivientes

1) Inspecciona la línea mutada y su comportamiento.
   - Reprodúcelo localmente aplicando la línea mutada y ejecutando una prueba enfocada.

2) Refuerza las pruebas para que verifiquen el estado, no solo los valores devueltos.
   - Añade comprobaciones en los límites de igualdad (p. ej., prueba el umbral `==`).
   - Verifica las postcondiciones: saldos, suministro total, efectos de autorización y eventos emitidos.

3) Sustituye los mocks demasiado permisivos por un comportamiento realista.
   - Asegúrate de que los mocks apliquen las transferencias, las rutas de fallo y las emisiones de eventos que ocurren on-chain.

4) Añade invariantes a las pruebas fuzz.
   - Por ejemplo: conservación del valor, saldos no negativos, invariantes de autorización y suministro monótono cuando corresponda.

5) Separa los verdaderos positivos de los no-ops semánticos.
   - Ejemplo: `x > 0` -> `x != 0` no tiene efecto cuando `x` es unsigned.

6) Vuelve a ejecutar la campaña hasta eliminar los supervivientes o justificar explícitamente su supervivencia.

## Caso de estudio: detección de aserciones de estado faltantes (protocolo Arkis)

Una campaña de mutación durante una auditoría del protocolo DeFi Arkis reveló supervivientes como:<sup>[[2]](#references)[[3]](#references)</sup>

```text
INFO:Slither-Mutate:[CR] Line 33: 'cmdsToExecute.last().value = _cmd.value' ==> '//cmdsToExecute.last().value = _cmd.value' --> UNCAUGHT
```

Comentar la asignación no rompió las pruebas, lo que demuestra que faltan aserciones del estado posterior. Causa raíz: el código confiaba en `_cmd.value`, controlado por el usuario, en lugar de validar las transferencias reales de tokens. Un atacante podía desincronizar las transferencias esperadas de las reales para drenar fondos. Resultado: riesgo de alta severidad para la solvencia del protocolo.<sup>[[2]](#references)[[3]](#references)</sup>

Recomendación: trata los mutantes supervivientes que afectan a las transferencias de valor, la contabilidad o el control de acceso como de alto riesgo hasta que sean eliminados.

## No generes pruebas a ciegas para eliminar todos los mutantes

La generación de pruebas basada en mutation puede ser contraproducente si la implementación actual es incorrecta. Ejemplo: mutar `priority >= 2` a `priority > 2` cambia el comportamiento, pero la solución correcta no siempre es «escribir una prueba para `priority == 2`». Ese comportamiento podría ser en sí mismo el error.<sup>[[1]](#references)</sup>

Flujo de trabajo más seguro:
- Usa los mutantes supervivientes para identificar requisitos ambiguos
- Valida el comportamiento esperado con las especificaciones, la documentación del protocolo o los revisores
- Solo entonces codifica el comportamiento como una prueba o invariante

De lo contrario, corres el riesgo de codificar accidentes de implementación en el conjunto de pruebas y obtener una falsa sensación de seguridad.

## Lista de verificación práctica

- Ejecuta una campaña específica:
  - `slither-mutate ./src/contracts --test-cmd="forge test"`
- Cuando sea posible, prefiere mutadores conscientes de la sintaxis (AST/Tree-sitter) a los que solo usan regex.
- Analiza los mutantes supervivientes y escribe pruebas o invariantes que fallen con el comportamiento mutado.
- Comprueba los saldos, la oferta, las autorizaciones y los eventos.
- Añade pruebas de casos límite (`==`, desbordamientos/subdesbordamientos, dirección cero, cantidad cero, arrays vacíos).
- Sustituye los mocks poco realistas; simula modos de fallo.
- Guarda los resultados si las herramientas lo permiten y filtra los mutantes no capturados antes de analizarlos.
- Usa campañas en dos fases o por objetivo para mantener el tiempo de ejecución bajo control.
- Repite el proceso hasta que todos los mutantes sean eliminados o se justifiquen con comentarios y argumentos.

## References

- [1] [Pruebas de mutación para la era agentic](https://blog.trailofbits.com/2026/04/01/mutation-testing-for-the-agentic-era/)
- [2] [Usa mutation testing para encontrar los errores que tus pruebas no detectan (Trail of Bits)](https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/)
- [3] [Revisión de seguridad de Arkis DeFi Prime Brokerage (Apéndice C)](https://github.com/trailofbits/publications/blob/master/reviews/2024-12-arkis-defi-prime-brokerage-securityreview.pdf)
- [4] [Slither (GitHub)](https://github.com/crytic/slither)
- [5] [Documentación de Slither Mutator](https://github.com/crytic/slither/blob/master/docs/src/tools/Mutator.md)
- [6] [mewt](https://github.com/trailofbits/mewt)
- [7] [MuTON](https://github.com/trailofbits/muton)
{{#include ../../banners/hacktricks-training.md}}
