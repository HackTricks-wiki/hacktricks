# Blockchain y criptomonedas

{{#include ../../banners/hacktricks-training.md}}

Este capítulo cubre conceptos de blockchain y seguridad on-chain. Si hay un peer de Bitcoin expuesto, empieza por la [enumeración del servicio Bitcoin P2P](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md); para un frontend de navegador, una conexión de wallet o un backend off-chain, consulta [pentesting de DApp](../../pentesting-web/dapps-DecentralizedApplications.md). Para conocer las operaciones de privacidad de las criptomonedas y sus limitaciones, consulta el [capítulo sobre privacidad de las criptomonedas](../../privacy/cryptocurrency-privacy.md).

## Conceptos básicos

- Los **contratos inteligentes** son programas que se ejecutan en una blockchain cuando se cumplen ciertas condiciones y automatizan la ejecución de acuerdos sin intermediarios.
- Las **aplicaciones descentralizadas (dApps)** se basan en contratos inteligentes e incluyen un frontend fácil de usar y un backend transparente y auditable.
- Los **tokens y las monedas** se diferencian en que las monedas sirven como dinero digital, mientras que los tokens representan valor o propiedad en contextos específicos.
  - Los **tokens de utilidad** dan acceso a servicios, y los **tokens de seguridad** representan la propiedad de activos.
- **DeFi** significa finanzas descentralizadas y ofrece servicios financieros sin autoridades centrales.
- **DEX** y **DAO** hacen referencia, respectivamente, a las plataformas de intercambio descentralizadas y a las organizaciones autónomas descentralizadas.

Para conocer la terminología de órdenes spot, futuros, apalancamiento y opciones que se usa en los mercados de criptomonedas, consulta [Términos de inversión](investment-terms.md).

## Mecanismos de consenso

Los mecanismos de consenso garantizan que las transacciones se validen de forma segura y consensuada en la blockchain:

- **Proof of Work (PoW)** se basa en la capacidad de cálculo para verificar transacciones.
- **Proof of Stake (PoS)** exige que los validadores posean una cantidad determinada de tokens y reduce el consumo de energía en comparación con PoW.<sup>[[1]](#references)</sup>

## Fundamentos de Bitcoin

### Transacciones

Las transacciones de Bitcoin implican transferir fondos entre direcciones. Se validan mediante firmas digitales, lo que garantiza que solo el propietario de la clave privada pueda iniciar transferencias.<sup>[[2]](#references)</sup>

#### Componentes clave:

- Las **transacciones multifirma** requieren varias firmas para autorizar una transacción.<sup>[[3]](#references)</sup>
- Las transacciones constan de **entradas** (origen de los fondos), **salidas** (destino), **comisiones** (pagadas a los mineros) y **scripts** (reglas de la transacción).

### Lightning Network

Busca mejorar la escalabilidad de Bitcoin al permitir múltiples transacciones dentro de un canal y publicar en la blockchain únicamente el estado final.

## Problemas de privacidad de Bitcoin

Los ataques a la privacidad, como la **propiedad común de entradas** y la **detección de direcciones de cambio de UTXO**, aprovechan los patrones de las transacciones. Estrategias como los **Mixers** y **CoinJoin** mejoran el anonimato al ocultar los vínculos entre las transacciones de distintos usuarios.

## Adquirir bitcoins de forma anónima

Entre los métodos se incluyen las transacciones en efectivo, la minería y el uso de mixers. **CoinJoin** combina varias transacciones para dificultar su rastreo, mientras que **PayJoin** disfraza las transacciones CoinJoin como transacciones normales para aumentar la privacidad.

# Resumen de los ataques a la privacidad de Bitcoin

En el mundo de Bitcoin, la privacidad de las transacciones y el anonimato de los usuarios suelen ser motivo de preocupación. A continuación, se presenta una descripción simplificada de varios métodos comunes con los que los atacantes pueden comprometer la privacidad de Bitcoin.<sup>[[6]](#references)</sup>

## **Suposición de propiedad común de las entradas**

Por lo general, es poco frecuente combinar entradas de distintos usuarios en una sola transacción debido a la complejidad que esto implica. Por lo tanto, **se suele asumir que dos direcciones de entrada de una misma transacción pertenecen al mismo propietario**.

## **Detección de direcciones de cambio de UTXO**

Una UTXO, o **salida de transacción no gastada**, debe gastarse por completo en una transacción. Si solo se envía una parte a otra dirección, el resto se envía a una nueva dirección de cambio. Los observadores pueden asumir que esta nueva dirección pertenece al remitente, lo que compromete su privacidad.

### Ejemplo

Para mitigar este riesgo, se pueden usar servicios de mezcla o varias direcciones para ocultar la propiedad.

## **Exposición en redes sociales y foros**

A veces, los usuarios comparten sus direcciones de Bitcoin en línea, lo que facilita **vincular la dirección con su propietario**.

## **Análisis del grafo de transacciones**

Las transacciones se pueden visualizar como grafos, lo que revela posibles conexiones entre usuarios según el flujo de fondos.

## **Heurística de entrada innecesaria (heurística de cambio óptimo)**

Esta heurística se basa en analizar transacciones con varias entradas y salidas para adivinar cuál de las salidas corresponde al cambio que se devuelve al remitente.

### Ejemplo

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Si agregar más entradas hace que el cambio sea mayor que cualquiera de las entradas individuales, puede confundir la heurística.

## **Reutilización Forzada de Direcciones**

Los atacantes pueden enviar pequeñas cantidades a direcciones usadas anteriormente, con la esperanza de que el destinatario las combine con otras entradas en transacciones futuras, vinculando así las direcciones.

### Comportamiento Correcto de la Wallet

Las wallets deberían evitar usar monedas recibidas en direcciones vacías que ya se hayan usado para prevenir este leak de privacidad.

## **Otras Técnicas de Análisis de Blockchain**

- **Importes de Pago Exactos:** Es probable que las transacciones sin cambio sean entre dos direcciones propiedad del mismo usuario.
- **Números Redondos:** Un número redondo en una transacción sugiere que se trata de un pago y que la salida no redonda probablemente sea el cambio.
- **Fingerprinting de Wallets:** Las distintas wallets tienen patrones únicos de creación de transacciones, lo que permite a los analistas identificar el software utilizado y, potencialmente, la dirección de cambio.
- **Correlaciones de Importe y Tiempo:** Divulgar los horarios o importes de las transacciones puede hacer que sean rastreables.

## **Análisis de Tráfico**

Al monitorear el tráfico de red, los atacantes pueden vincular potencialmente transacciones o bloques con direcciones IP, comprometiendo la privacidad de los usuarios. Esto es especialmente cierto si una entidad opera muchos nodos de Bitcoin, lo que aumenta su capacidad para monitorear las transacciones.

## Más

Para obtener una lista completa de ataques y defensas de privacidad, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transacciones Anónimas de Bitcoin

## Formas de Obtener Bitcoins de Forma Anónima

- **Transacciones en Efectivo**: Adquirir bitcoin mediante efectivo.
- **Alternativas al Efectivo**: Comprar tarjetas de regalo e intercambiarlas por bitcoin en línea.
- **Mining**: El método más privado para obtener bitcoins es mediante mining, especialmente si se realiza en solitario, ya que los pools de mining pueden conocer la dirección IP del minero. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Robo**: En teoría, robar bitcoin podría ser otra forma de adquirirlo de manera anónima, aunque es ilegal y no se recomienda.

## Servicios de Mixing

Al usar un servicio de mixing, un usuario puede **enviar bitcoins** y recibir **otros bitcoins a cambio**, lo que dificulta rastrear al propietario original. Sin embargo, esto requiere confiar en que el servicio no conserve registros y realmente devuelva los bitcoins. Entre las opciones alternativas de mixing están los casinos de Bitcoin.

## CoinJoin

**CoinJoin** combina varias transacciones de distintos usuarios en una sola, lo que complica el proceso de asociar las entradas con las salidas. A pesar de su eficacia, las transacciones con tamaños únicos de entradas y salidas todavía pueden rastrearse.

Entre las transacciones de ejemplo que podrían haber usado CoinJoin están `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para más información, visita [CoinJoin](https://coinjoin.io/en). Para ver un mixer de smart contracts de Ethereum que separa los depósitos de los retiros posteriores, consulta [Tornado Cash](https://tornado.cash).

## PayJoin

Una variante de CoinJoin, **PayJoin** (o P2EP), disfraza la transacción entre dos partes (por ejemplo, un cliente y un comerciante) como una transacción normal, sin las salidas iguales características de CoinJoin. Esto hace que sea extremadamente difícil de detectar y podría invalidar la heurística de propiedad común de entradas utilizada por las entidades de vigilancia de transacciones.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transacciones como la anterior podrían ser PayJoin, lo que mejora la privacidad y, al mismo tiempo, las hace indistinguibles de las transacciones estándar de bitcoin.

**El uso de PayJoin podría alterar significativamente los métodos tradicionales de vigilancia**, lo que lo convierte en un avance prometedor en la búsqueda de privacidad transaccional.

# Mejores prácticas para la privacidad en las criptomonedas

## **Técnicas de sincronización de wallets**

Para mantener la privacidad y la seguridad, es crucial sincronizar las wallets con la blockchain. Destacan dos métodos:

- **Full node**: Al descargar toda la blockchain, un full node garantiza la máxima privacidad. Todas las transacciones realizadas se almacenan localmente, lo que hace imposible que los adversarios identifiquen qué transacciones o direcciones le interesan al usuario.
- **Filtrado de bloques del lado del cliente**: Este método consiste en crear filtros para cada bloque de la blockchain, lo que permite a las wallets identificar las transacciones relevantes sin revelar intereses específicos a los observadores de la red. Las wallets ligeras descargan estos filtros y solo obtienen los bloques completos cuando encuentran una coincidencia con las direcciones del usuario.

## **Uso de Tor para el anonimato**

Dado que Bitcoin opera en una red peer-to-peer, se recomienda usar Tor para ocultar la dirección IP y mejorar la privacidad al interactuar con la red.

## **Cómo evitar la reutilización de direcciones**

Para proteger la privacidad, es fundamental usar una dirección nueva en cada transacción. Reutilizar direcciones puede comprometer la privacidad al vincular transacciones con una misma entidad. Las wallets modernas desalientan la reutilización de direcciones mediante su diseño.

## **Estrategias para la privacidad de las transacciones**

- **Varias transacciones**: Dividir un pago en varias transacciones puede ocultar el importe de la transacción y frustrar los ataques contra la privacidad.
- **Evitar el cambio**: Optar por transacciones que no requieran outputs de cambio mejora la privacidad al dificultar los métodos de detección de cambio.
- **Varios outputs de cambio**: Si no es posible evitar el cambio, generar varios outputs de cambio también puede mejorar la privacidad.

# **Monero: un referente del anonimato**

Monero está diseñado para priorizar la privacidad de las transacciones.

# **Ethereum: gas y transacciones**

## **Comprender el gas**

El gas mide el esfuerzo computacional necesario para ejecutar operaciones en Ethereum y se expresa en **gwei**. Por ejemplo, una transacción que cuesta 2,310,000 gwei (o 0.00231 ETH) tiene un límite de gas y una tarifa base, además de una tarifa de prioridad para incentivar su inclusión por parte de los validadores. Los usuarios pueden establecer una tarifa máxima para asegurarse de no pagar de más; el excedente se reembolsa.<sup>[[5]](#references)</sup>

## **Ejecutar transacciones**

Las transacciones en Ethereum incluyen un emisor y un destinatario, que pueden ser direcciones de usuarios o de smart contracts. Requieren una tarifa y deben incluirse en un bloque. La información esencial de una transacción incluye el destinatario, la firma del emisor, el valor, los datos opcionales, el límite de gas y las tarifas. Cabe destacar que la dirección del emisor se deduce de la firma, por lo que no es necesario incluirla en los datos de la transacción.<sup>[[4]](#references)</sup>

Estas prácticas y mecanismos son fundamentales para quienes buscan usar criptomonedas priorizando la privacidad y la seguridad.

## Red teaming de Web3 centrado en el valor

- Inventariar los componentes que pueden manejar valor (signers, oracles, bridges, automatización) para comprender quién puede mover fondos y cómo.
- Asociar cada componente con las tácticas MITRE AADAPT pertinentes para revelar vías de escalada de privilegios.
- Ensayar cadenas de ataque de flash-loan/oracle/credenciales/entre cadenas para validar el impacto y documentar las condiciones previas explotables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromiso del flujo de firma de Web3

- La manipulación de la cadena de suministro de las interfaces de wallet puede modificar los payloads de EIP-712 justo antes de la firma y obtener firmas válidas para tomar el control de proxies basados en delegatecall (por ejemplo, sobrescribir el slot-0 de Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstracción de cuentas (ERC-4337)

- Entre los modos de fallo comunes de las smart accounts se incluyen la omisión del control de acceso de `EntryPoint`, campos de gas sin firmar, validación con estado, repetición de ERC-1271 y drenaje de tarifas mediante revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Seguridad de smart contracts

- Pruebas de mutación para encontrar puntos ciegos en las suites de pruebas:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridad de las pruebas ZK / los guests de zkVM

Cuando un prover usa una **zkVM** o un circuito de prueba específico de una aplicación para demostrar una afirmación, el verifier solo aprende que el **guest program se ejecutó tal como está escrito**. Si el guest contiene **deserialización insegura**, **comportamiento indefinido** o **restricciones semánticas ausentes**, un prover malicioso puede generar una prueba que se verifique aunque las **métricas públicas o el invariante declarado sean falsos**.<sup>[[7]](#references)</sup>

### Deserialización insegura dentro de los guests de pruebas

- Tratar los bytes privados del witness/circuit como **entrada no confiable controlada por un atacante**, aunque estén ocultos por la prueba.
- Evitar deserializarlos con helpers sin comprobaciones, como `rkyv::access_unchecked`, a menos que los bytes ya se hayan validado por otros medios.
- Validar los discriminantes de enum, los punteros relativos, las longitudes y los índices cargados desde datos serializados no confiables antes de que afecten el flujo de control o el acceso a memoria.

Patrón práctico de auditoría:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Si un campo como `op.kind` es un enum y un atacante puede inyectar un **discriminante fuera de rango**, cada `match` posterior sobre ese valor se vuelve sospechoso.

### Bypass de contadores mediante jump table / UB

Si Rust compila un `match` grande como una **jump table**, un discriminante de enum no válido puede provocar un **flujo de control indefinido**. Un patrón peligroso es:<sup>[[7]](#references)[[9]](#references)</sup>

1. Un `match` actualiza **contadores/restricciones críticos para la seguridad**.
2. Un segundo `match` ejecuta la **semántica real de la instrucción**.
3. Un discriminante fuera de rango indexa más allá de la primera jump table y llega a código asociado con la segunda.

Resultado: la operación se ejecuta, pero se omite la ruta de contabilización. En una zkVM esto puede falsificar pruebas que indiquen métricas imposibles, como menos gates, menos operaciones costosas u otros recursos limitados falsificados.

Lista de verificación:

- Busca enums controlados por un atacante y deserializados desde el witness/entrada privada.
- Inspecciona las instrucciones `match` repetidas sobre el mismo campo de opcode/kind.
- Considera que la combinación de `unsafe` + deserialización sin comprobaciones + dispatch de opcode grande es de alto riesgo.
- Realiza ingeniería inversa del binario emitido cuando sea necesario; la disposición de la jump table puede ser más importante que el código fuente.

### Restricciones semánticas ausentes en intérpretes reversibles/especializados

No valides solo la seguridad de memoria; valida también las **reglas semánticas** que la prueba debe hacer cumplir.

Para conjuntos de instrucciones reversibles o similares a los cuánticos, asegúrate de que los operandos que deban ser distintos estén realmente sujetos a esa restricción. Una operación similar a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

se vuelve inseguro si el invitado no rechaza:

```text
op.q_control1 == op.q_control2 == op.q_target
```

En ese caso, la transición se reduce a:

```text
q = q ^ (q & q) = 0
```

Esto crea una **primitiva de reinicio determinista**, que rompe las suposiciones de reversibilidad y permite realizar cálculos no previstos a menor costo. En los sistemas de prueba que certifican el uso de recursos, esto puede permitir que los atacantes superen las comprobaciones funcionales mientras eluden el modelo de costos que el verificador cree estar aplicando.

### Consejos del prover insuficientemente restringidos y aritmética modular

Los valores cargados desde una **pila de advice/witness están controlados por el prover**, incluso cuando se describen como cocientes, restos, inversos o pistas precalculados. Una prueba solo establece que el witness satisface las restricciones implementadas; no establece que se haya realizado el cálculo previsto si esas restricciones omiten una comprobación de tipo, rango o forma canónica.<sup>[[13]](#references)</sup>

Para un helper de reducción o división euclidiana, audita la relación entera completa, no solo la resta o multiplicación final. Cada limb de `q` y `r` debe estar restringido al ancho declarado, la reconstrucción `x = q * m + r` debe cumplirse en la representación entera prevista y debe hacerse cumplir el límite canónico `0 <= r < m`. Valida un valor **antes** de pasarlo a una instrucción `u32`/`u64` más estrecha; una operación de ancho reducido no demuestra retroactivamente que el elemento de campo original o el valor de varios limbs tuviera el tipo esperado.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

El fallo de `mod_12289` en Miden ilustra el patrón de exploit: el cociente se comprobaba como un valor de 64 bits de dos limbs, pero el resto suministrado mediante advice llegaba a `u32overflowing_sub` sin una validación equivalente. Un prover malicioso podía coordinar valores inválidos de cociente y resto para que las restricciones de la resta implementada siguieran cumpliéndose, aunque el procedimiento devolviera un resto no matemático. Como este resultado alimentaba la verificación de Falcon, el fallo de soundness podía escalarse hasta obtener firmas de autorización falsificadas, en lugar de limitarse a producir un resultado aritmético incorrecto.<sup>[[13]](#references)</sup>

### Auditar VMs criptográficas de pila implícita

Los lenguajes de pila ocultan los operandos, así que primero hay que elevar las instrucciones a un IR donde cada valor consumido y producido de la pila sea una expresión con procedencia. Luego, una pipeline de análisis conservadora puede:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Construir el grafo de llamadas e inferir los efectos de pila de entrada y salida de los procedimientos.
2. Ejecutar simbólicamente las instrucciones compatibles y elevar el flujo de control a expresiones SSA/estructuradas.
3. Propagar hechos abstractos como `Unknown`, `ProvenU32`, `Bool`, la procedencia de los valores y la inicialización local hasta alcanzar un punto fijo.
4. Marcar los valores derivados de advice que llegan a operaciones aritméticas tipadas o a sinks que requieren valores distintos de cero sin pasar por un sanitizer en **cada** ruta de entrada.
5. Comparar las firmas declaradas e inferidas y verificar que cada salida preserve los valores de la pila propiedad del caller.

Trata las firmas desconocidas o las construcciones no compatibles como una **laguna del análisis**, no como un resultado limpio. Las llamadas dinámicas, los bucles que no preservan la pila y las ramas con distintos efectos de pila pueden hacer imposible un seguimiento sólido de las posiciones de la pila; un decompilador más seguro rechaza o marca estos casos en vez de generar pseudocódigo plausible pero incorrecto.<sup>[[10]](#references)[[13]](#references)</sup>

En los puntos de unión del flujo de control, conserva una propiedad solo si se cumple en todos los predecesores (por ejemplo, `ProvenU32 join Unknown = Unknown`). Distingue también la convergencia de punto fijo de alcanzar un límite de iteraciones: solo una sobreaproximación convergida y sólida puede justificar que la ausencia de un diagnóstico sea evidencia de que todas las ejecuciones representadas satisfacen la propiedad.<sup>[[11]](#references)</sup>

### Usa obligaciones de prueba para revelar precondiciones ocultas

Para conjuntos pequeños de instrucciones, traduce los procedimientos a un modelo ejecutable de VM formal y demuestra tanto el resultado como la transformación completa de la pila. El teorema debe cubrir la terminación, las entradas tipadas, el prefijo de salida esperado y la preservación de la pila intacta del caller. Audita el enunciado del teorema con el mismo cuidado que la prueba: el kernel puede validar una prueba de una afirmación debilitada accidentalmente.<sup>[[12]](#references)[[13]](#references)</sup>

Las hipótesis inesperadas son hallazgos útiles. En la revisión de Miden, una prueba de rotación a la derecha de 64 bits requería `shift mod 32 != 0`, lo que reveló un caso límite defectuoso para entradas grandes cuando el shift era múltiplo de 32; otra prueba encontró que `wrapping_mul` de 256 bits descartaba valores de la pila propiedad del caller. Añade el caso límite descubierto a las pruebas y luego corrige la implementación o refuerza deliberadamente la precondición pública, en vez de aceptar en silencio la suposición adicional.<sup>[[12]](#references)[[13]](#references)</sup>

### Qué probar en sistemas ZK

- Haz fuzzing de todos los parsers del guest con codificaciones malformadas de witness/entradas privadas.
- Asegura la validación del rango del enum antes del despacho de opcode.
- Añade comprobaciones semánticas para el aliasing de operandos y otras formas de instrucción inválidas.
- Rastrea cada origen de advice/witness hasta cada sink aritmético tipado y exige validación en todas las rutas.<sup>[[11]](#references)[[13]](#references)</sup>
- Prueba los helpers aritméticos con limbs no canónicos, restos fuera de rango y cantidades de shift límite.<sup>[[12]](#references)[[13]](#references)</sup>
- Comprueba la altura de la pila y la preservación de los valores situados por debajo de los argumentos declarados del procedimiento en cada retorno.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Compara los contadores reportados/públicos con una implementación de referencia independiente.
- Recuerda que una prueba válida puede demostrar una **afirmación incorrecta** si el programa guest tiene errores.

## Autorización dependiente del estado

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Explotación de DeFi/AMM

Si estás investigando la explotación práctica de DEXes y AMMs (hooks de Uniswap v4, abuso de redondeo/precisión, swaps que cruzan umbrales amplificados mediante flash loans), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados multi-asset que almacenan en caché saldos virtuales y pueden envenenarse cuando `supply == 0`, estudia:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Prueba de participación - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Claves públicas y privadas explicadas - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [¿Qué son las transacciones multifirma? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transacciones | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas y tarifas | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacidad - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Vencimos la prueba de conocimiento cero de Google sobre criptoanálisis cuántico](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Protección de las criptomonedas de curva elíptica frente a vulnerabilidades cuánticas: estimaciones de recursos y mitigaciones (versión corregida)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repositorio de prueba de concepto de Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Arquitectura del decompilador MASM](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Motor de análisis estático de MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Modelo MASM-to-Lean y pruebas de corrección](https://github.com/trailofbits/masm-lean)
- [13] [Auditoría en la era de la IA (lo bastante buena)](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
