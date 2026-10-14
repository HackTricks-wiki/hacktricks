# Blockchain y criptomonedas

{{#include ../../banners/hacktricks-training.md}}

## Conceptos básicos

- **Los contratos inteligentes** se definen como programas que se ejecutan en una blockchain cuando se cumplen ciertas condiciones y automatizan la ejecución de acuerdos sin intermediarios.
- **Las aplicaciones descentralizadas (dApps)** se basan en contratos inteligentes y cuentan con una interfaz de usuario fácil de usar y un back-end transparente y auditable.
- **Los tokens y las monedas** se diferencian en que las monedas sirven como dinero digital, mientras que los tokens representan valor o propiedad en contextos específicos.
  - **Los tokens de utilidad** dan acceso a servicios, y **los tokens de seguridad** representan la propiedad de activos.
- **DeFi** significa Finanzas Descentralizadas y ofrece servicios financieros sin autoridades centrales.
- **DEX** y **DAO** se refieren, respectivamente, a plataformas de intercambio descentralizadas y organizaciones autónomas descentralizadas.

Para consultar la terminología de órdenes spot, futuros, apalancamiento y opciones utilizada en los mercados de criptomonedas, consulta [Términos de inversión](investment-terms.md).

## Mecanismos de consenso

Los mecanismos de consenso garantizan que las transacciones en la blockchain se validen de forma segura y consensuada:

- **Proof of Work (PoW)** se basa en la potencia computacional para verificar las transacciones.
- **Proof of Stake (PoS)** exige que los validadores posean una cantidad determinada de tokens, lo que reduce el consumo de energía en comparación con PoW.<sup>[[1]](#references)</sup>

## Conceptos esenciales de Bitcoin

### Transacciones

Las transacciones de Bitcoin transfieren fondos entre direcciones. Se validan mediante firmas digitales, lo que garantiza que solo el propietario de la clave privada pueda iniciar transferencias.<sup>[[2]](#references)</sup>

#### Componentes clave:

- **Las transacciones multifirma** requieren varias firmas para autorizar una transacción.<sup>[[3]](#references)</sup>
- Las transacciones constan de **entradas** (origen de los fondos), **salidas** (destino), **comisiones** (pagadas a los mineros) y **scripts** (reglas de la transacción).

### Lightning Network

Busca mejorar la escalabilidad de Bitcoin al permitir múltiples transacciones dentro de un canal y publicar en la blockchain solo el estado final.

## Problemas de privacidad de Bitcoin

Los ataques a la privacidad, como la **propiedad común de entradas** y la **detección de direcciones de cambio UTXO**, aprovechan los patrones de las transacciones. Estrategias como los **mixers** y **CoinJoin** mejoran el anonimato al ocultar los vínculos entre las transacciones de los usuarios.

## Adquirir bitcoins de forma anónima

Entre los métodos se incluyen los intercambios en efectivo, la minería y el uso de mixers. **CoinJoin** combina varias transacciones para dificultar su rastreo, mientras que **PayJoin** disimula las transacciones CoinJoin para que parezcan transacciones normales y aumentar la privacidad.

# Resumen de los ataques a la privacidad de Bitcoin

En el mundo de Bitcoin, la privacidad de las transacciones y el anonimato de los usuarios suelen ser motivo de preocupación. A continuación se ofrece un resumen sencillo de varios métodos comunes con los que los atacantes pueden comprometer la privacidad de Bitcoin.<sup>[[6]](#references)</sup>

## **Suposición de propiedad común de las entradas**

Por lo general, es poco frecuente combinar en una sola transacción entradas de distintos usuarios debido a la complejidad que esto implica. Por ello, **se suele suponer que dos direcciones de entrada de una misma transacción pertenecen al mismo propietario**.

## **Detección de direcciones de cambio UTXO**

Una UTXO, o **salida de transacción no gastada**, debe gastarse por completo en una transacción. Si solo se envía una parte a otra dirección, el resto va a una nueva dirección de cambio. Los observadores pueden suponer que esta nueva dirección pertenece al remitente, lo que compromete su privacidad.

### Ejemplo

Para mitigar este riesgo, se pueden utilizar servicios de mezcla o varias direcciones para ocultar la propiedad.

## **Exposición en redes sociales y foros**

A veces, los usuarios comparten sus direcciones de Bitcoin en Internet, lo que facilita **vincular la dirección con su propietario**.

## **Análisis del grafo de transacciones**

Las transacciones se pueden representar como grafos, lo que revela posibles conexiones entre usuarios a partir del flujo de fondos.

## **Heurística de entradas innecesarias (heurística de cambio óptimo)**

Esta heurística se basa en analizar transacciones con varias entradas y salidas para deducir cuál de las salidas corresponde al cambio que se devuelve al remitente.

### Ejemplo

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Si añadir más entradas hace que la salida de cambio sea mayor que cualquier entrada individual, puede confundir la heurística.

## **Reutilización forzada de direcciones**

Los atacantes pueden enviar pequeñas cantidades a direcciones usadas anteriormente, con la esperanza de que el destinatario las combine con otras entradas en transacciones futuras y, de ese modo, vincule las direcciones entre sí.

### Comportamiento correcto de la wallet

Las wallets deberían evitar usar monedas recibidas en direcciones vacías que ya se hayan usado, para prevenir esta filtración de privacidad.

## **Otras técnicas de análisis de blockchain**

- **Importes de pago exactos:** Es probable que las transacciones sin cambio se realicen entre dos direcciones propiedad del mismo usuario.
- **Números redondos:** Un número redondo en una transacción sugiere que se trata de un pago; es probable que la salida con un importe no redondo sea el cambio.
- **Fingerprinting de wallets:** Las distintas wallets tienen patrones únicos de creación de transacciones, lo que permite a los analistas identificar el software utilizado y, potencialmente, la dirección de cambio.
- **Correlaciones entre importes y horarios:** Revelar los horarios o importes de las transacciones puede hacer que estas sean rastreables.

## **Análisis del tráfico**

Al monitorizar el tráfico de red, los atacantes pueden vincular transacciones o bloques con direcciones IP, comprometiendo la privacidad de los usuarios. Esto es especialmente cierto si una entidad opera muchos nodos de Bitcoin, lo que mejora su capacidad para monitorizar las transacciones.

## Más información

Para ver una lista completa de ataques y defensas de privacidad, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transacciones anónimas de Bitcoin

## Formas de obtener bitcoins de forma anónima

- **Transacciones en efectivo**: Obtener bitcoin mediante efectivo.
- **Alternativas al efectivo**: Comprar tarjetas de regalo e intercambiarlas por bitcoin en línea.
- **Minería**: El método más privado para obtener bitcoins es mediante la minería, especialmente si se realiza en solitario, ya que los pools de minería podrían conocer la dirección IP del minero. [Información sobre pools de minería](https://en.bitcoin.it/wiki/Pooled_mining)
- **Robo**: En teoría, robar bitcoin podría ser otra forma de obtenerlo de manera anónima, aunque es ilegal y no se recomienda.

## Servicios de mezcla

Al usar un servicio de mezcla, un usuario puede **enviar bitcoins** y recibir **otros bitcoins a cambio**, lo que dificulta rastrear al propietario original. Sin embargo, esto requiere confiar en que el servicio no conserve registros y realmente devuelva los bitcoins. Otras opciones de mezcla incluyen los casinos de Bitcoin.

## CoinJoin

**CoinJoin** combina varias transacciones de distintos usuarios en una sola, lo que complica el proceso para cualquiera que intente asociar las entradas con las salidas. A pesar de su eficacia, las transacciones con cantidades únicas de entradas y salidas todavía pueden ser rastreables.

Algunos ejemplos de transacciones que podrían haber usado CoinJoin son `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para obtener más información, visita [CoinJoin](https://coinjoin.io/en). Para ver un mixer de smart contracts de Ethereum que separa los depósitos de los retiros posteriores, consulta [Tornado Cash](https://tornado.cash).

## PayJoin

Una variante de CoinJoin, **PayJoin** (o P2EP), disfraza la transacción entre dos partes (por ejemplo, un cliente y un comerciante) como una transacción normal, sin las salidas iguales distintivas de CoinJoin. Esto hace que sea extremadamente difícil de detectar y podría invalidar la heurística de propiedad común de las entradas que utilizan las entidades que vigilan las transacciones.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transacciones como la anterior podrían ser PayJoin, lo que mejora la privacidad y, al mismo tiempo, las hace indistinguibles de las transacciones estándar de bitcoin.

**El uso de PayJoin podría alterar significativamente los métodos tradicionales de vigilancia**, por lo que representa un avance prometedor en la búsqueda de privacidad transaccional.

# Mejores prácticas para la privacidad en criptomonedas

## **Técnicas de sincronización de wallets**

Para mantener la privacidad y la seguridad, es fundamental sincronizar las wallets con la blockchain. Destacan dos métodos:

- **Nodo completo**: Al descargar toda la blockchain, un nodo completo garantiza la máxima privacidad. Todas las transacciones realizadas se almacenan localmente, lo que impide que los adversarios identifiquen qué transacciones o direcciones le interesan al usuario.
- **Filtrado de bloques en el cliente**: Este método consiste en crear filtros para cada bloque de la blockchain, lo que permite a las wallets identificar transacciones relevantes sin revelar intereses específicos a quienes observan la red. Las wallets ligeras descargan estos filtros y solo obtienen los bloques completos cuando encuentran una coincidencia con las direcciones del usuario.

## **Uso de Tor para el anonimato**

Dado que Bitcoin funciona en una red peer-to-peer, se recomienda usar Tor para ocultar la dirección IP y mejorar la privacidad al interactuar con la red.

## **Evitar la reutilización de direcciones**

Para proteger la privacidad, es fundamental usar una dirección nueva para cada transacción. Reutilizar direcciones puede comprometer la privacidad al vincular transacciones con una misma entidad. Las wallets modernas desalientan la reutilización de direcciones mediante su diseño.

## **Estrategias para la privacidad de las transacciones**

- **Varias transacciones**: Dividir un pago en varias transacciones puede ocultar el importe de la transacción y frustrar ataques a la privacidad.
- **Evitar el cambio**: Optar por transacciones que no requieran salidas de cambio mejora la privacidad al dificultar los métodos de detección de cambio.
- **Varias salidas de cambio**: Si no es posible evitar el cambio, generar varias salidas de cambio puede mejorar la privacidad.

# **Monero: un referente del anonimato**

Monero está diseñado para priorizar la privacidad de las transacciones.

# **Ethereum: gas y transacciones**

## **Comprender el gas**

El gas mide el esfuerzo computacional necesario para ejecutar operaciones en Ethereum y se cotiza en **gwei**. Por ejemplo, una transacción que cuesta 2,310,000 gwei (o 0.00231 ETH) tiene un límite de gas y una tarifa base, además de una tarifa de prioridad para incentivar su inclusión por parte de un validador. Los usuarios pueden establecer una tarifa máxima para evitar pagar de más; el excedente se reembolsa.<sup>[[5]](#references)</sup>

## **Ejecutar transacciones**

Las transacciones en Ethereum involucran un remitente y un destinatario, que pueden ser direcciones de usuario o de smart contracts. Requieren una tarifa y deben incluirse en un bloque. La información esencial de una transacción incluye el destinatario, la firma del remitente, el valor, los datos opcionales, el límite de gas y las tarifas. Cabe destacar que la dirección del remitente se deduce de la firma, por lo que no es necesario incluirla en los datos de la transacción.<sup>[[4]](#references)</sup>

Estas prácticas y mecanismos son fundamentales para quienes buscan usar criptomonedas priorizando la privacidad y la seguridad.

## Red Teaming de Web3 centrado en el valor

- Inventariar los componentes que contienen valor (firmantes, oráculos, bridges, automatización) para comprender quién puede mover fondos y cómo.
- Asociar cada componente con las tácticas pertinentes de MITRE AADAPT para revelar rutas de escalada de privilegios.
- Ensayar cadenas de ataque con flash loans, oráculos, credenciales y cross-chain para validar el impacto y documentar las precondiciones explotables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromiso del flujo de trabajo de firma de Web3

- La manipulación de la cadena de suministro de las interfaces de wallet puede modificar payloads de EIP-712 justo antes de la firma y obtener firmas válidas para ataques de toma de control de proxies basados en delegatecall (por ejemplo, sobrescribir `masterCopy` de Safe en el slot 0).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstracción de cuentas (ERC-4337)

- Entre los modos de fallo comunes de las smart accounts se incluyen la omisión del control de acceso de `EntryPoint`, campos de gas sin firmar, validación con estado, repetición de ERC-1271 y agotamiento de fondos mediante revert después de la validación.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Seguridad de smart contracts

- Pruebas de mutación para encontrar puntos ciegos en las suites de pruebas:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridad de pruebas ZK / guests de zkVM

Cuando un prover usa una **zkVM** o un circuito de prueba específico de una aplicación para demostrar una afirmación, el verifier solo aprende que el **programa guest se ejecutó tal como está escrito**. Si el guest contiene **deserialización insegura**, **comportamiento indefinido** o **restricciones semánticas ausentes**, un prover malicioso puede generar una prueba que se verifique aunque las **métricas públicas o la invariante afirmada sean falsas**.<sup>[[7]](#references)</sup>

### Deserialización insegura dentro de los guests de pruebas

- Trata los bytes del witness privado/circuito como **entrada no confiable del atacante**, aunque estén ocultos por la prueba.
- Evita deserializarlos con helpers sin comprobaciones, como `rkyv::access_unchecked`, a menos que los bytes ya se hayan validado por otros medios.
- Los discriminantes de enum, punteros relativos, longitudes e índices cargados desde datos serializados no confiables deben validarse antes de influir en el flujo de control o en el acceso a memoria.

Patrón práctico de auditoría:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Si un campo como `op.kind` es un enum y un atacante puede inyectar un **discriminante fuera de rango**, cada `match` posterior sobre ese valor resulta sospechoso.

### Bypass de contadores mediante jump table / UB

Si Rust convierte un `match` grande en una **jump table**, un discriminante de enum no válido puede provocar un **flujo de control indefinido**. Un patrón peligroso es:<sup>[[7]](#references)[[9]](#references)</sup>

1. Un `match` actualiza **contadores/restricciones críticos para la seguridad**.
2. Un segundo `match` ejecuta la **semántica real de la instrucción**.
3. Un discriminante fuera de rango indexa más allá de la primera jump table y llega al código asociado con la segunda.

Resultado: la operación se ejecuta, pero se omite la ruta de contabilización. En una zkVM, esto puede falsificar pruebas que reportan métricas imposibles, como menos gates, menos operaciones costosas u otros recursos limitados falsificados.

Lista de comprobación:

- Busca enums controlados por el atacante y deserializados desde la entrada witness/privada.
- Inspecciona las instrucciones `match` repetidas sobre el mismo campo de opcode/kind.
- Considera que la combinación de `unsafe` + deserialización sin comprobaciones + despacho de opcode grande es de alto riesgo.
- Haz reverse engineering del binario generado cuando sea necesario; la disposición de la jump table puede importar más que el código fuente.

### Restricciones semánticas ausentes en intérpretes reversibles/especializados

No valides solo la seguridad de memoria; valida también las **reglas semánticas** que la prueba debe imponer.

En conjuntos de instrucciones reversibles o similares a los cuánticos, asegúrate de que se imponga que los operandos que deben ser distintos realmente lo sean. Una operación similar a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

se vuelve inseguro si el invitado no rechaza:

```text
op.q_control1 == op.q_control2 == op.q_target
```

En ese caso, la transición colapsa en:

```text
q = q ^ (q & q) = 0
```

Esto crea una **primitiva de reinicio determinista**, rompe las suposiciones de reversibilidad y permite realizar cálculos no previstos a menor costo. En sistemas de prueba que certifican el uso de recursos, esto puede permitir que los atacantes satisfagan las comprobaciones funcionales y, a la vez, eludan el modelo de costos que el verificador cree estar aplicando.

### Datos de advice del prover con restricciones insuficientes y aritmética modular

Los valores cargados desde una **pila de advice/witness están controlados por el prover**, incluso cuando se describen como cocientes, restos, inversos o pistas precalculados. Una prueba solo establece que el witness satisface las restricciones implementadas; no establece que se haya realizado el cálculo previsto si esas restricciones omiten una comprobación de tipo, rango o forma canónica.<sup>[[13]](#references)</sup>

En una reducción o una función auxiliar de división euclidiana, audita la relación entera completa, no solo la resta o multiplicación final. Cada limb de `q` y `r` debe estar restringido al ancho declarado, la reconstrucción `x = q * m + r` debe cumplirse en la representación entera prevista y debe aplicarse el límite canónico `0 <= r < m`. Valida un valor **antes** de pasarlo a una instrucción más estrecha `u32`/`u64`; una operación estrecha no demuestra retroactivamente que el elemento de campo original o el valor de varios limbs tuviera el tipo esperado.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

El fallo de `mod_12289` en Miden ilustra el patrón de explotación: el cociente se comprobaba como un valor de 64 bits en dos limbs, pero el resto proporcionado mediante advice llegaba a `u32overflowing_sub` sin una validación equivalente. Un prover malicioso podía coordinar valores inválidos de cociente y resto para que se siguieran cumpliendo las restricciones de la resta implementada, mientras que el procedimiento devolvía un resto no matemático. Como este resultado alimentaba la verificación de Falcon, el fallo de soundness podía escalarse hasta falsificar firmas de autorización, en vez de limitarse a producir un resultado aritmético incorrecto.<sup>[[13]](#references)</sup>

### Auditoría de VMs criptográficas con pila implícita

Los lenguajes de pila ocultan los operandos, así que primero hay que elevar las instrucciones a una IR donde cada valor consumido y producido en la pila sea una expresión con procedencia. Luego, una canalización de análisis conservadora puede:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Construir el grafo de llamadas e inferir los efectos de entrada y salida de la pila de cada procedimiento.
2. Ejecutar simbólicamente las instrucciones admitidas y elevar el flujo de control a expresiones SSA/estructuradas.
3. Propagar hechos abstractos como `Unknown`, `ProvenU32`, `Bool`, la procedencia de los valores y la inicialización local hasta alcanzar un punto fijo.
4. Señalar los valores derivados de advice que lleguen a operaciones aritméticas tipadas o a sinks que exigen un valor distinto de cero sin un sanitizador en **todas** las rutas de entrada.
5. Comparar las firmas declaradas con las inferidas y verificar que cada salida preserve los valores de la pila propiedad del caller.

Trata una firma desconocida o una construcción no admitida como una **laguna de análisis**, no como un resultado limpio. Las llamadas dinámicas, los bucles que no preservan la pila y las ramas con distintos efectos sobre la pila pueden impedir un seguimiento fiable de sus posiciones; un decompilador más seguro rechaza o marca estos casos en vez de generar pseudocódigo plausible pero incorrecto.<sup>[[10]](#references)[[13]](#references)</sup>

En las uniones del flujo de control, conserva una propiedad solo si se cumple en todos los predecesores (por ejemplo, `ProvenU32 join Unknown = Unknown`). Distingue también la convergencia al punto fijo de alcanzar un límite de iteraciones: solo una sobreaproximación convergente y sólida permite considerar la ausencia de un diagnóstico como evidencia de que todas las ejecuciones representadas cumplen la propiedad.<sup>[[11]](#references)</sup>

### Usa obligaciones de prueba para revelar precondiciones ocultas

En conjuntos pequeños de instrucciones, traduce los procedimientos a un modelo ejecutable de VM formal y demuestra tanto el resultado como la transformación completa de la pila. El teorema debe cubrir la terminación, las entradas tipadas, el prefijo de salida esperado y la preservación de la pila del caller que no se modifica. Audita el enunciado del teorema con tanto cuidado como la prueba: el kernel puede validar la prueba de una afirmación debilitada accidentalmente.<sup>[[12]](#references)[[13]](#references)</sup>

Las hipótesis inesperadas son hallazgos útiles. En la revisión de Miden, una prueba de rotación a la derecha de 64 bits requería `shift mod 32 != 0`, lo que reveló un caso límite fallido para entradas grandes cuando el desplazamiento era múltiplo de 32; otra prueba descubrió que `wrapping_mul` de 256 bits descartaba valores de la pila propiedad del caller. Añade el caso límite descubierto a las pruebas y luego corrige la implementación o fortalece deliberadamente la precondición pública, en lugar de aceptar silenciosamente la suposición adicional.<sup>[[12]](#references)[[13]](#references)</sup>

### Qué probar en sistemas ZK

- Haz fuzzing de todos los parsers del guest con codificaciones malformadas de witness/entrada privada.
- Comprueba la validación del rango de los enums antes del despacho de opcodes.
- Añade comprobaciones semánticas para aliasing de operandos y otras formas de instrucciones no válidas.
- Rastrea cada origen de advice/witness hasta cada sink aritmético tipado y exige validación en todas las rutas.<sup>[[11]](#references)[[13]](#references)</sup>
- Prueba los helpers aritméticos con limbs no canónicos, restos fuera de rango y valores límite de desplazamiento.<sup>[[12]](#references)[[13]](#references)</sup>
- Comprueba la altura de la pila y la preservación de los valores que estén por debajo de los argumentos declarados del procedimiento en cada retorno.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Compara los contadores reportados/públicos con una implementación de referencia independiente.
- Recuerda que una prueba válida aún puede demostrar la **afirmación equivocada** si el programa guest tiene errores.

## Autorización dependiente del estado

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Explotación de DeFi/AMM

Si investigas la explotación práctica de DEXes y AMM (hooks de Uniswap v4, abuso de redondeo/precisión, swaps amplificados mediante flash loans que cruzan umbrales), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados con múltiples activos que almacenan en caché saldos virtuales y pueden envenenarse cuando `supply == 0`, consulta:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Prueba de participación - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Claves públicas y privadas explicadas - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [¿Qué son las transacciones con múltiples firmas? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transacciones | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas y tarifas | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacidad - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Vencimos la prueba de conocimiento cero de Google sobre criptoanálisis cuántico](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Protección de las criptomonedas de curva elíptica frente a vulnerabilidades cuánticas: estimaciones de recursos y mitigaciones (versión parcheada)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repositorio de prueba de concepto de Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Arquitectura del decompilador de MASM](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Motor de análisis estático de MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Modelo de MASM a Lean y pruebas de corrección](https://github.com/trailofbits/masm-lean)
- [13] [Auditoría en la era de la IA (lo bastante buena)](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}
