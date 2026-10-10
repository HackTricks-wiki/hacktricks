# Blockchain y criptomonedas

{{#include ../../banners/hacktricks-training.md}}

## Conceptos básicos

- **Los contratos inteligentes** se definen como programas que se ejecutan en una blockchain cuando se cumplen ciertas condiciones y automatizan la ejecución de acuerdos sin intermediarios.
- **Las aplicaciones descentralizadas (dApps)** se basan en contratos inteligentes y cuentan con una interfaz de usuario intuitiva y un back-end transparente y auditable.
- **Los tokens y las monedas** se diferencian en que las monedas sirven como dinero digital, mientras que los tokens representan valor o propiedad en contextos específicos.
  - Los **tokens de utilidad** dan acceso a servicios, y los **tokens de seguridad** representan la propiedad de activos.
- **DeFi** significa finanzas descentralizadas y ofrece servicios financieros sin autoridades centrales.
- **DEX** y **DAO** se refieren, respectivamente, a las plataformas de exchange descentralizado y las organizaciones autónomas descentralizadas.

## Mecanismos de consenso

Los mecanismos de consenso garantizan que las transacciones se validen de forma segura y consensuada en la blockchain:

- **Proof of Work (PoW)** se basa en la potencia de cálculo para verificar transacciones.
- **Proof of Stake (PoS)** exige que los validadores posean una cierta cantidad de tokens, lo que reduce el consumo de energía en comparación con PoW.<sup>[[1]](#references)</sup>

## Conceptos básicos de Bitcoin

### Transacciones

Las transacciones de Bitcoin implican transferir fondos entre direcciones. Se validan mediante firmas digitales, que garantizan que solo el propietario de la clave privada pueda iniciar transferencias.<sup>[[2]](#references)</sup>

#### Componentes clave:

- Las **transacciones multifirma** requieren varias firmas para autorizar una transacción.<sup>[[3]](#references)</sup>
- Las transacciones constan de **entradas** (origen de los fondos), **salidas** (destino), **comisiones** (pagadas a los mineros) y **scripts** (reglas de la transacción).

### Lightning Network

Su objetivo es mejorar la escalabilidad de Bitcoin permitiendo varias transacciones dentro de un canal y publicando en la blockchain solo el estado final.

## Problemas de privacidad de Bitcoin

Los ataques a la privacidad, como la **propiedad común de entradas** y la **detección de direcciones de cambio UTXO**, aprovechan los patrones de las transacciones. Estrategias como los **mixers** y **CoinJoin** mejoran el anonimato al ocultar los vínculos entre las transacciones de los usuarios.

## Adquisición anónima de bitcoins

Los métodos incluyen transacciones en efectivo, minería y el uso de mixers. **CoinJoin** combina varias transacciones para dificultar su rastreo, mientras que **PayJoin** disfraza las transacciones CoinJoin como transacciones normales para aumentar la privacidad.

# Resumen de los ataques a la privacidad de Bitcoin

En el mundo de Bitcoin, la privacidad de las transacciones y el anonimato de los usuarios suelen ser motivo de preocupación. A continuación, se ofrece un resumen simplificado de varios métodos habituales con los que los atacantes pueden comprometer la privacidad de Bitcoin.<sup>[[6]](#references)</sup>

## **Suposición de propiedad común de entradas**

Por lo general, es poco frecuente combinar en una sola transacción entradas de distintos usuarios debido a la complejidad que esto implica. Por ello, **a menudo se supone que dos direcciones de entrada de una misma transacción pertenecen al mismo propietario**.

## **Detección de direcciones de cambio UTXO**

Un UTXO, o **salida de transacción no gastada**, debe gastarse por completo en una transacción. Si solo se envía una parte a otra dirección, el resto se envía a una nueva dirección de cambio. Los observadores pueden suponer que esta nueva dirección pertenece al remitente, lo que compromete su privacidad.

### Ejemplo

Para reducir este riesgo, se pueden usar servicios de mezcla o varias direcciones para ocultar la propiedad.

## **Exposición en redes sociales y foros**

A veces, los usuarios comparten sus direcciones de Bitcoin en línea, lo que facilita **vincular la dirección con su propietario**.

## **Análisis del grafo de transacciones**

Las transacciones pueden representarse como grafos, lo que revela posibles conexiones entre usuarios a partir del flujo de fondos.

## **Heurística de entrada innecesaria (heurística de cambio óptimo)**

Esta heurística se basa en analizar transacciones con varias entradas y salidas para adivinar cuál de las salidas corresponde al cambio que se devuelve al remitente.

### Ejemplo

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Si añadir más entradas hace que la salida de cambio sea mayor que cualquier entrada individual, puede confundir la heurística.

## **Reutilización forzada de direcciones**

Los atacantes pueden enviar pequeñas cantidades a direcciones usadas anteriormente, con la esperanza de que el destinatario las combine con otras entradas en transacciones futuras, vinculando así las direcciones.

### Comportamiento correcto de la wallet

Las wallets deberían evitar usar monedas recibidas en direcciones vacías que ya se hayan usado para prevenir este leak de privacidad.

## **Otras técnicas de análisis de blockchain**

- **Importes exactos de pago:** Es probable que las transacciones sin cambio sean entre dos direcciones propiedad del mismo usuario.
- **Números redondos:** Un número redondo en una transacción sugiere que se trata de un pago, y es probable que la salida con un importe no redondo sea el cambio.
- **Fingerprinting de wallets:** Las distintas wallets tienen patrones únicos de creación de transacciones, lo que permite a los analistas identificar el software utilizado y posiblemente la dirección de cambio.
- **Correlaciones de importes y tiempos:** Divulgar los tiempos o los importes de las transacciones puede hacer que estas sean rastreables.

## **Análisis de tráfico**

Al monitorizar el tráfico de red, los atacantes pueden vincular transacciones o bloques con direcciones IP, comprometiendo la privacidad de los usuarios. Esto es especialmente cierto si una entidad opera muchos nodos de Bitcoin, lo que aumenta su capacidad para monitorizar transacciones.

## Más información

Para ver una lista completa de ataques y defensas de privacidad, visita [Privacidad de Bitcoin en Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transacciones anónimas de Bitcoin

## Formas de obtener bitcoins de forma anónima

- **Transacciones en efectivo**: Obtener bitcoin mediante efectivo.
- **Alternativas al efectivo**: Comprar tarjetas de regalo e intercambiarlas en línea por bitcoin.
- **Minería**: El método más privado para obtener bitcoins es la minería, especialmente si se realiza en solitario, ya que los pools de minería podrían conocer la dirección IP del minero. [Información sobre los pools de minería](https://en.bitcoin.it/wiki/Pooled_mining)
- **Robo**: En teoría, robar bitcoin podría ser otra forma de obtenerlo de manera anónima, aunque es ilegal y no se recomienda.

## Servicios de mixing

Al usar un servicio de mixing, un usuario puede **enviar bitcoins** y recibir **otros bitcoins a cambio**, lo que dificulta rastrear al propietario original. Sin embargo, esto requiere confiar en que el servicio no guarde registros y realmente devuelva los bitcoins. Otras opciones de mixing incluyen los casinos de Bitcoin.

## CoinJoin

**CoinJoin** combina varias transacciones de distintos usuarios en una sola, lo que complica el proceso para cualquiera que intente emparejar las entradas con las salidas. A pesar de su eficacia, las transacciones con importes únicos en las entradas y salidas todavía pueden ser rastreables.

Algunos ejemplos de transacciones que podrían haber usado CoinJoin son `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para obtener más información, visita [CoinJoin](https://coinjoin.io/en). Para ver un mixer de smart contracts de Ethereum que separa los depósitos de los retiros posteriores, consulta [Tornado Cash](https://tornado.cash).

## PayJoin

Una variante de CoinJoin, **PayJoin** (o P2EP), disfraza como una transacción normal la transacción entre dos partes (por ejemplo, un cliente y un comerciante), sin las salidas iguales características de CoinJoin. Esto hace que sea extremadamente difícil de detectar y podría invalidar la heurística de propiedad común de entradas que utilizan las entidades de vigilancia de transacciones.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transacciones como la anterior podrían ser PayJoin, lo que mejora la privacidad sin dejar de ser indistinguibles de las transacciones estándar de bitcoin.

**El uso de PayJoin podría alterar significativamente los métodos de vigilancia tradicionales**, por lo que representa un avance prometedor en la búsqueda de privacidad transaccional.

# Mejores prácticas de privacidad en las criptomonedas

## **Técnicas de sincronización de wallets**

Para mantener la privacidad y la seguridad, es crucial sincronizar las wallets con la blockchain. Destacan dos métodos:

- **Full node**: Al descargar toda la blockchain, un full node garantiza la máxima privacidad. Todas las transacciones realizadas se almacenan localmente, lo que hace imposible que los adversarios identifiquen qué transacciones o direcciones le interesan al usuario.
- **Filtrado de bloques en el cliente**: Este método consiste en crear filtros para cada bloque de la blockchain, lo que permite a las wallets identificar las transacciones pertinentes sin revelar intereses específicos a los observadores de la red. Las wallets ligeras descargan estos filtros y solo obtienen los bloques completos cuando encuentran una coincidencia con las direcciones del usuario.

## **Uso de Tor para el anonimato**

Dado que Bitcoin opera en una red peer-to-peer, se recomienda usar Tor para enmascarar tu dirección IP y mejorar la privacidad al interactuar con la red.

## **Evitar la reutilización de direcciones**

Para proteger la privacidad, es fundamental usar una dirección nueva para cada transacción. Reutilizar direcciones puede comprometer la privacidad al vincular transacciones con la misma entidad. Las wallets modernas desalientan la reutilización de direcciones mediante su diseño.

## **Estrategias para la privacidad de las transacciones**

- **Varias transacciones**: Dividir un pago en varias transacciones puede ocultar el importe de la transacción y frustrar los ataques contra la privacidad.
- **Evitar el cambio**: Elegir transacciones que no requieran salidas de cambio mejora la privacidad al dificultar los métodos de detección del cambio.
- **Varias salidas de cambio**: Si no es posible evitar el cambio, generar varias salidas de cambio puede mejorar igualmente la privacidad.

# **Monero: un referente del anonimato**

Monero está diseñado para priorizar la privacidad de las transacciones.

# **Ethereum: gas y transacciones**

## **Entender el gas**

El gas mide el esfuerzo computacional necesario para ejecutar operaciones en Ethereum y se expresa en **gwei**. Por ejemplo, una transacción que cuesta 2,310,000 gwei (o 0.00231 ETH) tiene un límite de gas y una tarifa base, además de una tarifa de prioridad para incentivar a los validadores a incluirla. Los usuarios pueden establecer una tarifa máxima para asegurarse de no pagar de más; el excedente se reembolsa.<sup>[[5]](#references)</sup>

## **Ejecutar transacciones**

Las transacciones en Ethereum implican un emisor y un destinatario, que pueden ser direcciones de usuarios o de smart contracts. Requieren una tarifa y deben incluirse en un bloque. La información esencial de una transacción incluye el destinatario, la firma del emisor, el valor, los datos opcionales, el límite de gas y las tarifas. Cabe destacar que la dirección del emisor se deduce de la firma, por lo que no es necesario incluirla en los datos de la transacción.<sup>[[4]](#references)</sup>

Estas prácticas y mecanismos son fundamentales para quienes desean operar con criptomonedas dando prioridad a la privacidad y la seguridad.

## Red Teaming de Web3 centrado en el valor

- Inventariar los componentes que controlan valor (firmantes, oráculos, bridges, automatización) para entender quién puede mover fondos y cómo.
- Asociar cada componente con las tácticas pertinentes de MITRE AADAPT para exponer vías de escalada de privilegios.
- Ensayar cadenas de ataque con flash loans, oráculos, credenciales y cross-chain para validar el impacto y documentar las precondiciones explotables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromiso del flujo de firma de Web3

- La manipulación de la cadena de suministro de las interfaces de wallet puede modificar los payloads EIP-712 justo antes de la firma y obtener firmas válidas para tomar el control de proxies basados en delegatecall (por ejemplo, sobrescribir el slot-0 de Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstracción de cuentas (ERC-4337)

- Entre los modos de fallo habituales de las smart accounts se incluyen la omisión del control de acceso de `EntryPoint`, campos de gas sin firmar, validación con estado, replay de ERC-1271 y drenaje de tarifas mediante revert después de la validación.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Seguridad de smart contracts

- Mutation testing para encontrar puntos ciegos en las suites de pruebas:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridad de las pruebas ZK / guests de zkVM

Cuando un prover usa una **zkVM** o un circuito de pruebas específico de una aplicación para atestiguar una afirmación, el verificador solo aprende que el **programa guest se ejecutó tal como está escrito**. Si el guest contiene **deserialización insegura**, **comportamiento indefinido** o **restricciones semánticas ausentes**, un prover malicioso puede generar una prueba que se verifique aunque las **métricas públicas o el invariante afirmado sean falsos**.<sup>[[7]](#references)</sup>

### Deserialización insegura dentro de los guests de las pruebas

- Trata los bytes privados del witness/circuito como **entrada no confiable controlada por un atacante**, aunque estén ocultos por la prueba.
- Evita deserializarlos con funciones auxiliares sin comprobaciones, como `rkyv::access_unchecked`, a menos que los bytes ya se hayan validado por medios externos.
- Los discriminantes de enum, los punteros relativos, las longitudes y los índices cargados desde datos serializados no confiables deben validarse antes de que afecten al flujo de control o al acceso a memoria.

Patrón práctico de auditoría:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Si un campo como `op.kind` es un enum y un atacante puede inyectar un **discriminante fuera de rango**, toda instrucción `match` posterior sobre ese valor resulta sospechosa.

### Bypass mediante jump table / UB

Si Rust convierte un `match` grande en una **jump table**, un discriminante de enum no válido puede provocar un **flujo de control indefinido**. Un patrón peligroso es:<sup>[[7]](#references)[[9]](#references)</sup>

1. Un `match` actualiza **contadores/restricciones críticos para la seguridad**.
2. Un segundo `match` ejecuta la **semántica real de la instrucción**.
3. Un discriminante fuera de rango indexa más allá de la primera jump table y llega a código asociado con la segunda.

Resultado: la operación se ejecuta, pero se omite la ruta de contabilización. En una zkVM, esto puede falsificar pruebas que informan métricas imposibles, como una cantidad menor de gates, menos operaciones costosas u otros recursos acotados falsificados.

Lista de verificación:

- Busca enums controlados por el atacante y deserializados desde witness/entrada privada.
- Inspecciona las instrucciones `match` repetidas sobre el mismo campo de opcode/kind.
- Considera que `unsafe` + deserialización sin comprobaciones + dispatch de opcode grande es una combinación de alto riesgo.
- Haz ingeniería inversa del binario generado cuando sea necesario; la disposición de la jump table puede ser más importante que el código fuente.

### Restricciones semánticas ausentes en intérpretes reversibles/especializados

No valides solo la seguridad de la memoria; valida también las **reglas semánticas** que se supone que debe aplicar la prueba.

Para conjuntos de instrucciones reversibles o similares a los cuánticos, asegúrate de que los operandos que deben ser distintos tengan una restricción que los obligue a ser distintos. Una operación similar a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>

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

Esto crea una **primitiva de restablecimiento determinista**, que rompe las suposiciones de reversibilidad y permite realizar cálculos no previstos a menor costo. En los sistemas de prueba que certifican el uso de recursos, esto puede permitir que los atacantes superen las comprobaciones funcionales y, a la vez, eludan el modelo de costos que el verificador cree estar aplicando.

### Qué probar en sistemas ZK

- Fuzzear todos los parsers guest con codificaciones malformadas de witness/entrada privada.
- Validar el rango de enum antes de despachar opcodes.
- Añadir comprobaciones semánticas para el aliasing de operandos y otras formas de instrucción no válidas.
- Comparar los contadores reportados/públicos con una implementación de referencia independiente.
- Recuerda que una prueba válida aún puede demostrar la **afirmación equivocada** si el programa guest tiene errores.

## Autorización dependiente del estado

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Explotación de DeFi/AMM

Si investigas la explotación práctica de DEX y AMM (hooks de Uniswap v4, abuso de redondeo/precisión, swaps que cruzan umbrales amplificados con flash loans), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados de múltiples activos que almacenan en caché balances virtuales y pueden envenenarse cuando `supply == 0`, consulta:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Prueba de participación - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Clave pública y clave privada explicadas - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [¿Qué son las transacciones multifirma? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transacciones | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas y comisiones | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacidad - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Superamos la prueba de conocimiento cero de Google sobre criptoanálisis cuántico](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Protección de las criptomonedas de curva elíptica frente a vulnerabilidades cuánticas: estimaciones de recursos y mitigaciones (versión parcheada)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repositorio de prueba de concepto de Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
