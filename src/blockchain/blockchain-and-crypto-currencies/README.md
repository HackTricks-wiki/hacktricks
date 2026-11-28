# Blockchain y criptomonedas

{{#include ../../banners/hacktricks-training.md}}

Este capítulo abarca los conceptos de blockchain y la seguridad on-chain. Para un peer de Bitcoin expuesto, empieza con la [enumeración del servicio P2P de Bitcoin](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md); para un frontend de navegador, una conexión a una wallet o un backend off-chain, usa [pentesting de DApp](../../pentesting-web/dapps-DecentralizedApplications.md). Para conocer las operaciones de privacidad de las criptomonedas y sus límites, consulta el [capítulo sobre privacidad de las criptomonedas](../../privacy/cryptocurrency-privacy.md).

## Conceptos básicos

- Los **contratos inteligentes** se definen como programas que se ejecutan en una blockchain cuando se cumplen ciertas condiciones y automatizan la ejecución de acuerdos sin intermediarios.
- Las **aplicaciones descentralizadas (dApps)** se basan en contratos inteligentes y cuentan con un frontend fácil de usar y un backend transparente y auditable.
- **Tokens y monedas** se diferencian en que las monedas sirven como dinero digital, mientras que los tokens representan valor o propiedad en contextos específicos.
  - Los **tokens de utilidad** dan acceso a servicios, y los **security tokens** representan la propiedad de activos.
- **DeFi** significa finanzas descentralizadas y ofrece servicios financieros sin autoridades centrales.
- **DEX** y **DAO** se refieren, respectivamente, a plataformas de intercambio descentralizado y organizaciones autónomas descentralizadas.

Para conocer la terminología de órdenes spot, futuros, apalancamiento y opciones que se usa en los mercados de criptomonedas, consulta [Términos de inversión](investment-terms.md). Para conocer el abuso de la tasa de financiación en protocolos perpetuos, consulta [Explotación de la tasa de financiación en perpetuos](perpetual-funding-rate-exploitation.md).

## Mecanismos de consenso

Los mecanismos de consenso garantizan que las transacciones se validen de forma segura y consensuada en la blockchain:

- **Proof of Work (PoW)** se basa en la potencia computacional para verificar transacciones.
- **Proof of Stake (PoS)** exige que los validadores posean una cantidad determinada de tokens, lo que reduce el consumo de energía en comparación con PoW.<sup>[[1]](#references)</sup>

## Fundamentos de Bitcoin

### Transacciones

Las transacciones de Bitcoin implican transferir fondos entre direcciones. Se validan mediante firmas digitales, que garantizan que solo el propietario de la clave privada pueda iniciar transferencias.<sup>[[2]](#references)</sup>

#### Componentes clave:

- Las **transacciones multisig** requieren varias firmas para autorizar una transacción.<sup>[[3]](#references)</sup>
- Las transacciones constan de **entradas** (origen de los fondos), **salidas** (destino), **comisiones** (pagadas a los mineros) y **scripts** (reglas de la transacción).

### Lightning Network

Busca mejorar la escalabilidad de Bitcoin al permitir varias transacciones dentro de un canal y transmitir a la blockchain únicamente el estado final.

## Problemas de privacidad de Bitcoin

Los ataques a la privacidad, como la **propiedad común de entradas** y la **detección de direcciones de cambio UTXO**, aprovechan patrones de transacción. Estrategias como los **Mixers** y **CoinJoin** mejoran el anonimato al ocultar los vínculos entre las transacciones de los usuarios.

## Adquisición anónima de bitcoins

Los métodos incluyen intercambios en efectivo, minería y uso de Mixers. **CoinJoin** combina varias transacciones para dificultar su rastreo, mientras que **PayJoin** disfraza las transacciones CoinJoin como transacciones normales para aumentar la privacidad.

# Resumen de los ataques a la privacidad de Bitcoin

En el mundo de Bitcoin, la privacidad de las transacciones y el anonimato de los usuarios suelen ser motivo de preocupación. A continuación, se ofrece un resumen simplificado de varios métodos comunes que los atacantes pueden usar para comprometer la privacidad de Bitcoin.<sup>[[6]](#references)</sup>

## **Suposición de propiedad común de entradas**

Por lo general, es poco frecuente combinar entradas de distintos usuarios en una sola transacción debido a la complejidad que implica. Por eso, **a menudo se supone que dos direcciones de entrada de una misma transacción pertenecen al mismo propietario**.

## **Detección de direcciones de cambio UTXO**

Un UTXO, o **salida de transacción no gastada**, debe gastarse por completo en una transacción. Si solo se envía una parte a otra dirección, el resto se envía a una nueva dirección de cambio. Los observadores pueden suponer que esta nueva dirección pertenece al remitente, lo que compromete su privacidad.

### Ejemplo

Para mitigar este riesgo, se pueden usar servicios de mezcla o varias direcciones para ocultar la propiedad.

## **Exposición en redes sociales y foros**

A veces, los usuarios comparten sus direcciones de Bitcoin en línea, lo que **facilita vincular la dirección con su propietario**.

## **Análisis de grafos de transacciones**

Las transacciones pueden representarse como grafos, lo que revela posibles conexiones entre usuarios según el flujo de fondos.

## **Heurística de entrada innecesaria (heurística de cambio óptimo)**

Esta heurística se basa en analizar transacciones con varias entradas y salidas para adivinar cuál de las salidas corresponde al cambio que se devuelve al remitente.

### Ejemplo

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Si añadir más inputs hace que el output del cambio sea mayor que cualquier input individual, puede confundir la heurística.

## **Reutilización forzada de direcciones**

Los atacantes pueden enviar pequeñas cantidades a direcciones usadas anteriormente, con la esperanza de que el destinatario las combine con otros inputs en transacciones futuras y, de este modo, vincule las direcciones entre sí.

### Comportamiento correcto de la wallet

Las wallets deberían evitar usar coins recibidos en direcciones vacías que ya se hayan usado, para prevenir este leak de privacidad.

## **Otras técnicas de análisis de blockchain**

- **Importes de pago exactos:** Es probable que las transacciones sin cambio sean entre dos direcciones propiedad del mismo usuario.
- **Números redondos:** Un número redondo en una transacción sugiere que se trata de un pago y que el output no redondo probablemente sea el cambio.
- **Fingerprinting de wallets:** Las distintas wallets tienen patrones únicos al crear transacciones, lo que permite a los analistas identificar el software utilizado y, potencialmente, la dirección de cambio.
- **Correlaciones entre importe y tiempo:** Revelar los horarios o importes de las transacciones puede hacer que estas sean rastreables.

## **Análisis de tráfico**

Al monitorizar el tráfico de red, los atacantes pueden vincular transacciones o bloques a direcciones IP, comprometiendo la privacidad de los usuarios. Esto es especialmente cierto si una entidad opera muchos nodos de Bitcoin, lo que aumenta su capacidad para monitorizar transacciones.

## Más

Para obtener una lista completa de ataques y defensas de privacidad, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transacciones anónimas de Bitcoin

## Formas de obtener bitcoins de forma anónima

- **Transacciones en efectivo**: Obtener bitcoin mediante efectivo.
- **Alternativas al efectivo**: Comprar tarjetas de regalo e intercambiarlas en línea por bitcoin.
- **Minería**: La forma más privada de obtener bitcoins es mediante la minería, especialmente si se hace en solitario, ya que los mining pools pueden conocer la dirección IP del minero. [Información sobre mining pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Robo**: En teoría, robar bitcoin podría ser otra forma de obtenerlo de manera anónima, aunque es ilegal y no se recomienda.

## Servicios de mixing

Al usar un servicio de mixing, un usuario puede **enviar bitcoins** y recibir **otros bitcoins a cambio**, lo que dificulta rastrear al propietario original. Sin embargo, esto requiere confiar en que el servicio no guarde logs y devuelva realmente los bitcoins. Entre las alternativas de mixing están los casinos de Bitcoin.

## CoinJoin

**CoinJoin** combina varias transacciones de distintos usuarios en una sola, lo que complica el proceso de asociar inputs con outputs. A pesar de su eficacia, las transacciones con tamaños únicos de inputs y outputs aún pueden ser rastreables.

Entre las transacciones de ejemplo que podrían haber usado CoinJoin están `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para obtener más información, visita [CoinJoin](https://coinjoin.io/en). Para un mixer de smart contracts de Ethereum que separa los depósitos de los retiros posteriores, consulta [Tornado Cash](https://tornado.cash).

## PayJoin

Una variante de CoinJoin, **PayJoin** (o P2EP), disfraza la transacción entre dos partes (por ejemplo, un cliente y un comerciante) como una transacción normal, sin los outputs iguales característicos de CoinJoin. Esto hace que sea extremadamente difícil de detectar y podría invalidar la heurística de propiedad común de inputs que usan las entidades de vigilancia de transacciones.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Las transacciones como la anterior podrían ser PayJoin, lo que mejora la privacidad y, a la vez, las hace indistinguibles de las transacciones estándar de bitcoin.

**El uso de PayJoin podría perturbar significativamente los métodos de vigilancia tradicionales**, lo que lo convierte en un avance prometedor en la búsqueda de privacidad transaccional.

# Mejores prácticas para la privacidad en las criptomonedas

## **Técnicas de sincronización de wallets**

Para mantener la privacidad y la seguridad, es fundamental sincronizar las wallets con la blockchain. Destacan dos métodos:

- **Nodo completo**: Al descargar toda la blockchain, un nodo completo garantiza la máxima privacidad. Todas las transacciones realizadas se almacenan localmente, lo que impide que los adversarios identifiquen qué transacciones o direcciones le interesan al usuario.
- **Filtrado de bloques del lado del cliente**: Este método consiste en crear filtros para cada bloque de la blockchain, lo que permite a las wallets identificar transacciones relevantes sin revelar intereses específicos a quienes observan la red. Las wallets ligeras descargan estos filtros y solo obtienen los bloques completos cuando encuentran una coincidencia con las direcciones del usuario.

## **Uso de Tor para el anonimato**

Dado que Bitcoin funciona en una red peer-to-peer, se recomienda usar Tor para ocultar la dirección IP y mejorar la privacidad al interactuar con la red.

## **Cómo evitar la reutilización de direcciones**

Para proteger la privacidad, es fundamental usar una dirección nueva para cada transacción. Reutilizar direcciones puede comprometer la privacidad al vincular transacciones con una misma entidad. Las wallets modernas desaconsejan la reutilización de direcciones mediante su diseño.

## **Estrategias para la privacidad de las transacciones**

- **Varias transacciones**: Dividir un pago en varias transacciones puede ocultar el importe de la transacción y frustrar los ataques a la privacidad.
- **Evitar el cambio**: Optar por transacciones que no requieran salidas de cambio mejora la privacidad al dificultar los métodos de detección de cambio.
- **Varias salidas de cambio**: Si no es posible evitar el cambio, generar varias salidas de cambio puede mejorar igualmente la privacidad.

# **Monero: un referente del anonimato**

Monero está diseñado para priorizar la privacidad de las transacciones.

# **Ethereum: gas y transacciones**

## **Entender el gas**

El gas mide el esfuerzo computacional necesario para ejecutar operaciones en Ethereum y se cotiza en **gwei**. Por ejemplo, una transacción que cuesta 2,310,000 gwei (o 0.00231 ETH) incluye un límite de gas y una tarifa base, además de una tarifa de prioridad para incentivar que un validador la incluya. Los usuarios pueden establecer una tarifa máxima para asegurarse de no pagar de más; el excedente se reembolsa.<sup>[[5]](#references)</sup>

## **Ejecutar transacciones**

Las transacciones en Ethereum incluyen un remitente y un destinatario, que pueden ser direcciones de usuario o de smart contracts. Requieren una tarifa y deben incluirse en un bloque. La información esencial de una transacción incluye el destinatario, la firma del remitente, el valor, los datos opcionales, el límite de gas y las tarifas. Cabe destacar que la dirección del remitente se deduce de la firma, por lo que no es necesario incluirla en los datos de la transacción.<sup>[[4]](#references)</sup>

Estas prácticas y mecanismos son fundamentales para quienes buscan interactuar con las criptomonedas dando prioridad a la privacidad y la seguridad.

## Red Teaming de Web3 centrado en el valor

- Inventariar los componentes que manejan valor (firmantes, oráculos, bridges, automatización) para entender quién puede mover fondos y cómo.
- Asignar cada componente a las tácticas pertinentes de MITRE AADAPT para revelar vías de escalada de privilegios.
- Ensayar cadenas de ataque con flash loans, oráculos, credenciales y ataques cross-chain para validar el impacto y documentar las precondiciones explotables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromiso del flujo de firma de Web3

- La manipulación de la cadena de suministro de las interfaces de wallet puede alterar los payloads EIP-712 justo antes de la firma y obtener firmas válidas para tomas de control de proxies basadas en delegatecall (por ejemplo, sobrescribir el slot 0 de masterCopy de Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstracción de cuentas (ERC-4337)

- Entre los modos de fallo habituales de las smart accounts se incluyen la omisión del control de acceso de `EntryPoint`, campos de gas sin firmar, validación con estado, repetición de ERC-1271 y drenaje de tarifas mediante revert después de la validación.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Seguridad de smart contracts

- Usar mutation testing para encontrar puntos ciegos en las suites de pruebas:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridad de las pruebas ZK y los guests de zkVM

Cuando un prover utiliza una **zkVM** o un circuito de pruebas específico de una aplicación para certificar una afirmación, el verificador solo sabe que el **programa guest se ejecutó tal como estaba escrito**. Si el guest contiene **deserialización insegura**, **comportamiento indefinido** o **restricciones semánticas ausentes**, un prover malicioso puede generar una prueba que se verifique aunque las **métricas públicas o el invariante declarado sean falsos**.<sup>[[7]](#references)</sup>

### Deserialización insegura dentro de los guests de pruebas

- Tratar los bytes del witness/circuito privado como **entrada no confiable controlada por un atacante**, incluso si la prueba los mantiene ocultos.
- Evitar deserializarlos con funciones auxiliares sin comprobaciones, como `rkyv::access_unchecked`, a menos que los bytes ya se hayan validado por otro medio.
- Validar los discriminantes de enums, los punteros relativos, las longitudes y los índices cargados desde datos serializados no confiables antes de que influyan en el flujo de control o el acceso a memoria.

Patrón práctico de auditoría:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Si un campo como `op.kind` es un enum y un atacante puede inyectar un **discriminante fuera de rango**, cada `match` posterior sobre ese valor se vuelve sospechoso.

### Bypass de contadores mediante jump table / UB

Si Rust convierte un `match` grande en una **jump table**, un discriminante de enum no válido puede provocar **flujo de control indefinido**. Un patrón peligroso es:<sup>[[7]](#references)[[9]](#references)</sup>

1. Un `match` actualiza **contadores/restricciones críticos para la seguridad**.
2. Un segundo `match` ejecuta la **semántica real de la instrucción**.
3. Un discriminante fuera de rango indexa más allá de la primera jump table y llega a código asociado a la segunda.

Resultado: la operación se ejecuta, pero se omite la ruta de contabilización. En una zkVM, esto puede forjar pruebas que reportan métricas imposibles, como menos gates, menos operaciones costosas u otros recursos acotados falsificados.

Lista de verificación:

- Busca enums controlados por el atacante y deserializados desde la entrada witness/privada.
- Inspecciona las sentencias `match` repetidas sobre el mismo campo opcode/kind.
- Considera `unsafe` + deserialización sin comprobaciones + despacho de opcode grande una combinación de alto riesgo.
- Haz reverse engineering del binario emitido cuando sea necesario; la disposición de la jump table puede importar más que el código fuente.

### Restricciones semánticas ausentes en intérpretes reversibles/especializados

No valides únicamente la seguridad de memoria; valida también las **reglas semánticas** que la prueba debe hacer cumplir.

Para conjuntos de instrucciones reversibles o similares a los cuánticos, asegúrate de que los operandos que deben ser distintos estén realmente restringidos para que lo sean. Una operación similar a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>

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

Esto crea una **primitiva de reinicio determinista**, rompe los supuestos de reversibilidad y permite realizar cálculos no previstos a menor costo. En sistemas de prueba que certifican el uso de recursos, esto puede permitir que los atacantes satisfagan las comprobaciones funcionales mientras eluden el modelo de costos que el verificador cree estar aplicando.

### Datos de entrada del prover insuficientemente restringidos y aritmética modular

Los valores cargados desde una **pila de advice/witness están bajo el control del prover**, incluso cuando se describen como cocientes, restos, inversos o pistas precalculados. Una prueba solo establece que el witness satisface las restricciones implementadas; no establece que se haya realizado el cálculo previsto si esas restricciones omiten una comprobación de tipo, rango o forma canónica.<sup>[[13]](#references)</sup>

Para un helper de reducción o división euclídea, audita la relación entera completa, no solo la resta o multiplicación final. Cada limb de `q` y `r` debe estar restringido al ancho declarado, la reconstrucción `x = q * m + r` debe cumplirse en la representación entera prevista y debe imponerse el límite canónico `0 <= r < m`. Valida un valor **antes** de pasarlo a una instrucción `u32`/`u64` más estrecha; una operación de ancho reducido no demuestra retroactivamente que el elemento de campo original o el valor de varios limbs tuviera el tipo esperado.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

El fallo de `mod_12289` en Miden ilustra el patrón de exploit: el cociente se comprobaba como un valor de 64 bits de dos limbs, pero el resto proporcionado mediante advice llegaba a `u32overflowing_sub` sin una validación equivalente. Un prover malicioso podía coordinar valores inválidos de cociente y resto para que se cumplieran las restricciones de la resta implementada y, aun así, el procedimiento devolviera un resto no matemático. Como este resultado alimentaba la verificación de Falcon, el fallo de soundness podía escalarse hasta falsificar firmas de autorización, en lugar de limitarse a producir un resultado aritmético incorrecto.<sup>[[13]](#references)</sup>

### Auditoría de VMs criptográficas con pila implícita

Los lenguajes de pila ocultan los operandos, así que primero hay que elevar las instrucciones a una IR donde cada valor consumido y producido en la pila sea una expresión con procedencia. Después, un pipeline de análisis conservador puede:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Construir el grafo de llamadas e inferir los efectos de entrada y salida de la pila de cada procedimiento.
2. Ejecutar simbólicamente las instrucciones compatibles y elevar el flujo de control a expresiones SSA/estructuradas.
3. Propagar hechos abstractos como `Unknown`, `ProvenU32`, `Bool`, la procedencia de los valores y la inicialización local hasta alcanzar un punto fijo.
4. Marcar los valores derivados de advice que lleguen a operaciones aritméticas tipadas o a sinks que requieran valores distintos de cero sin un sanitizer en **todos** los caminos de entrada.
5. Comparar las firmas declaradas e inferidas, y verificar que cada salida preserve los valores de la pila que pertenecen al caller.

Trata una firma desconocida o una construcción no compatible como una **laguna de análisis**, no como un resultado limpio. Las llamadas dinámicas, los bucles que no preservan la pila y las ramas con distintos efectos sobre la pila pueden impedir un seguimiento sólido de los slots de la pila; un decompilador más seguro rechaza o marca estos casos en lugar de emitir pseudocódigo plausible, pero incorrecto.<sup>[[10]](#references)[[13]](#references)</sup>

En las uniones del flujo de control, conserva una propiedad solo si se cumple en todos los predecesores (por ejemplo, `ProvenU32 join Unknown = Unknown`). Distingue también entre alcanzar la convergencia del punto fijo y llegar al límite de iteraciones: solo una sobreaproximación sólida y convergente permite tratar la ausencia de un diagnóstico como evidencia de que todas las ejecuciones representadas cumplen la propiedad.<sup>[[11]](#references)</sup>

### Usa obligaciones de prueba para revelar precondiciones ocultas

Para conjuntos pequeños de instrucciones, traduce los procedimientos a un modelo ejecutable formal de VM y demuestra tanto el resultado como la transformación completa de la pila. El teorema debe cubrir la terminación, las entradas tipadas, el prefijo de salida esperado y la preservación de la pila del caller que no se modifica. Audita el enunciado del teorema con el mismo cuidado que la prueba: el kernel puede validar la prueba de una afirmación debilitada por accidente.<sup>[[12]](#references)[[13]](#references)</sup>

Las hipótesis inesperadas son hallazgos útiles. En la revisión de Miden, una prueba de la rotación a la derecha de 64 bits requería `shift mod 32 != 0`, lo que reveló un caso límite que fallaba para entradas grandes cuando el desplazamiento era múltiplo de 32; otra prueba encontró que `wrapping_mul` de 256 bits descartaba valores de la pila que pertenecían al caller. Añade el caso límite descubierto a las pruebas y luego corrige la implementación o refuerza deliberadamente la precondición pública, en lugar de aceptar la suposición adicional en silencio.<sup>[[12]](#references)[[13]](#references)</sup>

### Qué probar en sistemas ZK

- Haz fuzzing de todos los parsers guest con codificaciones malformadas de witness/entradas privadas.
- Afirma la validación del rango de los enums antes del despacho de opcodes.
- Añade comprobaciones semánticas para aliasing de operandos y otras formas de instrucciones inválidas.
- Rastrea cada origen de advice/witness hasta cada sink aritmético tipado y exige validación en todos los caminos.<sup>[[11]](#references)[[13]](#references)</sup>
- Prueba los helpers aritméticos con limbs no canónicos, restos fuera de rango y valores límite de desplazamiento.<sup>[[12]](#references)[[13]](#references)</sup>
- Afirma la altura de la pila y la preservación de los valores situados por debajo de los argumentos declarados del procedimiento en cada retorno.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Compara los contadores reportados/públicos con una implementación de referencia independiente.
- Recuerda que una prueba válida aún puede demostrar la **afirmación equivocada** si el programa guest tiene errores.

## Autorización dependiente del estado

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

Si estás investigando la explotación práctica de DEX y AMM (hooks de Uniswap v4, abuso de redondeo/precisión, swaps amplificados con flash loans que cruzan umbrales), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados multi-activo que almacenan en caché saldos virtuales y pueden ser envenenados cuando `supply == 0`, consulta:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Prueba de participación - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Clave pública y clave privada: explicación - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [¿Qué son las transacciones multifirma? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transacciones | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas y tarifas | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacidad - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Vencimos la prueba de conocimiento cero de Google para el criptoanálisis cuántico](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Protección de las criptomonedas de curva elíptica frente a vulnerabilidades cuánticas: estimaciones de recursos y mitigaciones (versión parcheada)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repositorio de prueba de concepto de Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Arquitectura del decompilador de MASM](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Motor de análisis estático de MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Modelo de MASM a Lean y pruebas de corrección](https://github.com/trailofbits/masm-lean)
- [13] [Auditoría en la era de la IA (lo bastante buena)](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
