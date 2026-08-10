# Blockchain y Cripto-Monedas

## Conceptos básicos

- Los **Smart Contracts** se definen como programas que se ejecutan en una blockchain cuando se cumplen ciertas condiciones, automatizando la ejecución de acuerdos sin intermediarios.
- Las **Decentralized Applications (dApps)** se construyen sobre smart contracts e incluyen un front-end fácil de usar y un back-end transparente y auditable.
- **Tokens & Coins** se diferencian en que las coins sirven como dinero digital, mientras que los tokens representan valor o propiedad en contextos específicos.
- Los **Utility Tokens** proporcionan acceso a servicios, mientras que los **Security Tokens** representan la propiedad de activos.
- **DeFi** significa Decentralized Finance y ofrece servicios financieros sin autoridades centrales.
- **DEX** y **DAOs** hacen referencia a Decentralized Exchange Platforms y Decentralized Autonomous Organizations, respectivamente.

## Mecanismos de consenso

Los mecanismos de consenso garantizan validaciones de transacciones seguras y acordadas en la blockchain:

- **Proof of Work (PoW)** se basa en la potencia computacional para verificar transacciones.
- **Proof of Stake (PoS)** exige que los validadores mantengan una determinada cantidad de tokens, reduciendo el consumo energético en comparación con PoW.<sup>[[1]](#references)</sup>

## Conceptos esenciales de Bitcoin

### Transacciones

Las transacciones de Bitcoin implican transferir fondos entre direcciones. Las transacciones se validan mediante firmas digitales, lo que garantiza que solo el propietario de la clave privada pueda iniciar transferencias.<sup>[[2]](#references)</sup>

#### Componentes clave:

- Las **Multisignature Transactions** requieren varias firmas para autorizar una transacción.<sup>[[3]](#references)</sup>
- Las transacciones constan de **inputs** (fuente de fondos), **outputs** (destino), **fees** (pagadas a los mineros) y **scripts** (reglas de la transacción).

### Lightning Network

Tiene como objetivo mejorar la escalabilidad de Bitcoin al permitir múltiples transacciones dentro de un canal y transmitir únicamente el estado final a la blockchain.

## Problemas de privacidad de Bitcoin

Los ataques contra la privacidad, como **Common Input Ownership** y **UTXO Change Address Detection**, explotan los patrones de las transacciones. Estrategias como **Mixers** y **CoinJoin** mejoran el anonimato al ocultar los vínculos entre las transacciones de los usuarios.

## Adquisición anónima de Bitcoins

Los métodos incluyen intercambios en efectivo, minería y el uso de mixers. **CoinJoin** mezcla múltiples transacciones para complicar su trazabilidad, mientras que **PayJoin** disfraza los CoinJoins como transacciones normales para aumentar la privacidad.

# Resumen de los ataques contra la privacidad de Bitcoin

En el mundo de Bitcoin, la privacidad de las transacciones y el anonimato de los usuarios suelen ser motivo de preocupación. A continuación se presenta una descripción simplificada de varios métodos comunes mediante los cuales los atacantes pueden comprometer la privacidad de Bitcoin.<sup>[[6]](#references)</sup>

## **Suposición de propiedad común de los inputs**

Por lo general, es poco habitual combinar inputs de distintos usuarios en una sola transacción debido a la complejidad que esto implica. Por lo tanto, a menudo se supone que **las dos direcciones de input de una misma transacción pertenecen al mismo propietario**.

## **Detección de la dirección de cambio de UTXO**

Un UTXO, o **Unspent Transaction Output**, debe gastarse por completo en una transacción. Si solo se envía una parte a otra dirección, el resto se envía a una nueva dirección de cambio. Los observadores pueden suponer que esta nueva dirección pertenece al remitente, comprometiendo su privacidad.

### Ejemplo

Para mitigar esto, los servicios de mixing o el uso de múltiples direcciones pueden ayudar a ocultar la propiedad.

## **Exposición en redes sociales y foros**

A veces, los usuarios comparten sus direcciones de Bitcoin en Internet, lo que facilita **vincular la dirección con su propietario**.

## **Análisis del grafo de transacciones**

Las transacciones pueden visualizarse como grafos, revelando posibles conexiones entre usuarios según el flujo de fondos.

## **Heurística de input innecesario (heurística de cambio óptimo)**

Esta heurística se basa en analizar transacciones con múltiples inputs y outputs para deducir qué output corresponde al cambio que regresa al remitente.

### Ejemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si añadir más inputs hace que el change output sea mayor que cualquier input individual, puede confundir la heurística.

## **Forced Address Reuse**

Los atacantes pueden enviar pequeñas cantidades a direcciones utilizadas anteriormente, esperando que el destinatario las combine con otros inputs en transacciones futuras, vinculando así las direcciones entre sí.

### Comportamiento correcto de la wallet

Las wallets deben evitar utilizar coins recibidas en direcciones ya utilizadas y vacías para prevenir este privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Las transacciones sin cambio probablemente se realizan entre dos direcciones pertenecientes al mismo usuario.
- **Round Numbers:** Un número redondo en una transacción sugiere que es un pago, mientras que el output no redondo probablemente sea el cambio.
- **Wallet Fingerprinting:** Las distintas wallets tienen patrones únicos de creación de transacciones, lo que permite a los analistas identificar el software utilizado y posiblemente la dirección de cambio.
- **Amount & Timing Correlations:** Revelar los tiempos o las cantidades de las transacciones puede hacer que estas sean rastreables.

## **Traffic Analysis**

Al monitorizar el tráfico de red, los atacantes pueden vincular potencialmente transacciones o bloques con direcciones IP, comprometiendo la privacidad de los usuarios. Esto es especialmente cierto si una entidad opera muchos nodos de Bitcoin, lo que mejora su capacidad para monitorizar las transacciones.

## More

Para consultar una lista completa de ataques y defensas de privacidad, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Adquirir bitcoin mediante efectivo.
- **Cash Alternatives**: Comprar tarjetas regalo e intercambiarlas online por bitcoin.
- **Mining**: El método más privado para obtener bitcoins es mediante mining, especialmente cuando se realiza en solitario, ya que los mining pools pueden conocer la dirección IP del minero. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: En teoría, robar bitcoin podría ser otro método para adquirirlo de forma anónima, aunque es ilegal y no se recomienda.

## Mixing Services

Al utilizar un mixing service, un usuario puede **send bitcoins** y recibir **different bitcoins in return**, lo que dificulta rastrear al propietario original. Sin embargo, esto requiere confiar en que el servicio no conserve logs y devuelva realmente los bitcoins. Entre las opciones alternativas de mixing se incluyen los casinos de Bitcoin.

## CoinJoin

**CoinJoin** combina múltiples transacciones de distintos usuarios en una sola, complicando el proceso para cualquiera que intente relacionar los inputs con los outputs. A pesar de su eficacia, las transacciones con tamaños únicos de inputs y outputs todavía pueden rastrearse potencialmente.

Entre las transacciones de ejemplo que podrían haber utilizado CoinJoin se incluyen `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para obtener más información, visita [CoinJoin](https://coinjoin.io/en). Para consultar un mixer de smart-contract de Ethereum que separa los depósitos de los retiros posteriores, visita [Tornado Cash](https://tornado.cash).

## PayJoin

Una variante de CoinJoin, **PayJoin** (o P2EP), disfraza la transacción entre dos partes (por ejemplo, un cliente y un comerciante) como una transacción normal, sin la característica distintiva de los outputs iguales de CoinJoin. Esto hace que sea extremadamente difícil de detectar y podría invalidar la heurística de propiedad común de inputs utilizada por las entidades que realizan vigilancia de transacciones.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transacciones como la anterior podrían ser PayJoin, mejorando la privacidad mientras siguen siendo indistinguibles de las transacciones estándar de Bitcoin.

**El uso de PayJoin podría alterar significativamente los métodos tradicionales de vigilancia**, convirtiéndolo en un desarrollo prometedor en la búsqueda de privacidad transaccional.

# Mejores prácticas para la privacidad en las criptomonedas

## **Técnicas de sincronización de wallets**

Para mantener la privacidad y la seguridad, es crucial sincronizar las wallets con la blockchain. Destacan dos métodos:

- **Full node**: Al descargar toda la blockchain, un full node garantiza la máxima privacidad. Todas las transacciones realizadas se almacenan localmente, lo que impide que los adversarios identifiquen qué transacciones o direcciones interesan al usuario.
- **Filtrado de bloques del lado del cliente**: Este método consiste en crear filtros para cada bloque de la blockchain, permitiendo que las wallets identifiquen las transacciones relevantes sin exponer intereses específicos a los observadores de la red. Las wallets ligeras descargan estos filtros y solo obtienen los bloques completos cuando encuentran una coincidencia con las direcciones del usuario.

## **Uso de Tor para el anonimato**

Dado que Bitcoin opera en una red peer-to-peer, se recomienda utilizar Tor para ocultar la dirección IP y mejorar la privacidad al interactuar con la red.

## **Prevención de la reutilización de direcciones**

Para proteger la privacidad, es fundamental utilizar una dirección nueva para cada transacción. Reutilizar direcciones puede comprometer la privacidad al vincular las transacciones con la misma entidad. Las wallets modernas desaconsejan la reutilización de direcciones mediante su diseño.

## **Estrategias para la privacidad de las transacciones**

- **Múltiples transacciones**: Dividir un pago en varias transacciones puede ocultar el importe de la transacción y frustrar los ataques contra la privacidad.
- **Evitar el cambio**: Optar por transacciones que no requieran outputs de cambio mejora la privacidad al dificultar los métodos de detección del cambio.
- **Múltiples outputs de cambio**: Si no es posible evitar el cambio, generar varios outputs de cambio puede seguir mejorando la privacidad.

# **Monero: Un faro del anonimato**

Monero está diseñado para priorizar la privacidad de las transacciones.

# **Ethereum: Gas y transacciones**

## **Comprender el Gas**

El Gas mide el esfuerzo computacional necesario para ejecutar operaciones en Ethereum y tiene un precio expresado en **gwei**. Por ejemplo, una transacción que cuesta 2,310,000 gwei (o 0.00231 ETH) implica un límite de gas y una comisión base, junto con una comisión de prioridad para incentivar su inclusión por parte de los validadores. Los usuarios pueden establecer una comisión máxima para asegurarse de no pagar de más; el excedente se reembolsa.<sup>[[5]](#references)</sup>

## **Ejecución de transacciones**

Las transacciones en Ethereum implican un remitente y un destinatario, que pueden ser direcciones de usuario o de smart contracts. Requieren una comisión y deben incluirse en un bloque. La información esencial de una transacción incluye el destinatario, la firma del remitente, el valor, los datos opcionales, el límite de gas y las comisiones. Cabe destacar que la dirección del remitente se deduce de la firma, por lo que no es necesario incluirla en los datos de la transacción.<sup>[[4]](#references)</sup>

Estas prácticas y mecanismos son fundamentales para cualquiera que desee interactuar con criptomonedas priorizando la privacidad y la seguridad.

## Red Teaming de Web3 centrado en el valor

- Inventariar los componentes que contienen valor (signers, oracles, bridges, automation) para comprender quién puede mover fondos y cómo.
- Asignar cada componente a las tácticas de MITRE AADAPT relevantes para exponer las rutas de escalada de privilegios.
- Ensayar cadenas de ataque de flash-loan/oracle/credential/cross-chain para validar el impacto y documentar las precondiciones explotables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromiso del flujo de firma de Web3

- La manipulación de la supply chain de las UIs de las wallets puede modificar los payloads EIP-712 justo antes de la firma, recopilando firmas válidas para takeovers de proxies basados en delegatecall (por ejemplo, la sobrescritura del slot-0 de `masterCopy` de Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Entre los modos de fallo comunes de las smart accounts se incluyen eludir el control de acceso de `EntryPoint`, campos de gas sin firmar, validación con estado, replay de ERC-1271 y drenaje de comisiones mediante revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Seguridad de smart contracts

- Mutation testing para encontrar puntos ciegos en las test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridad de los ZK Proof / zkVM Guest

Cuando un prover utiliza una **zkVM** o un circuito de proof específico de la aplicación para acreditar una afirmación, el verifier solo está comprobando que el **guest program se ejecutó tal como fue escrito**. Si el guest contiene **unsafe deserialization**, **undefined behavior** o **restricciones semánticas ausentes**, un prover malicioso puede generar una proof que se verifique mientras las **métricas públicas o el invariant declarado son falsos**.<sup>[[7]](#references)</sup>

### Unsafe deserialization dentro de los proof guests

- Tratar los bytes del private witness/circuit como **untrusted attacker input**, incluso si la proof los oculta.
- Evitar deserializarlos con helpers sin comprobaciones como `rkyv::access_unchecked`, salvo que los bytes ya hayan sido validados out-of-band.
- Los discriminantes de enum, los punteros relativos, las longitudes y los índices cargados desde datos serializados no confiables deben validarse antes de influir en el flujo de control o en el acceso a memoria.

Patrón práctico de auditoría:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Si un campo como `op.kind` es un enum y un atacante puede inyectar un **discriminante fuera de rango**, cada `match` posterior sobre ese valor se vuelve sospechoso.

### Bypass de contadores mediante jump-table / UB

Si Rust transforma un `match` grande en una **jump table**, un discriminante de enum no válido puede producir un **flujo de control indefinido**. Un patrón peligroso es:<sup>[[7]](#references)[[9]](#references)</sup>

1. Un `match` actualiza **contadores/restricciones críticas para la seguridad**.
2. Un segundo `match` ejecuta la **semántica real de la instrucción**.
3. Un discriminante fuera de rango indexa más allá de la primera jump table y aterriza en el código asociado con la segunda.

Resultado: la operación sigue ejecutándose, pero se omite la ruta de contabilidad. En una zkVM, esto puede falsificar proofs que informan métricas imposibles, como menos gates, menos operaciones costosas u otros recursos limitados falsificados.

Lista de comprobación:

- Busca enums controlados por el atacante y deserializados desde witness/private input.
- Inspecciona las sentencias `match` repetidas sobre el mismo campo de opcode/kind.
- Considera `unsafe` + deserialización sin comprobaciones + dispatch de opcodes grandes como una combinación de alto riesgo.
- Haz reverse engineering del binario generado cuando sea necesario; el diseño de la jump table puede ser más importante que el código fuente.

### Restricciones semánticas ausentes en intérpretes reversibles/especializados

No valides únicamente la seguridad de memoria; valida también las **reglas semánticas** que el proof debe aplicar.

En conjuntos de instrucciones reversibles/similares a los cuánticos, asegúrate de que los operandos que deben ser distintos estén realmente restringidos para que sean distintos. Una operación similar a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>
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
Esto crea un **primitivo de reset determinista**, rompe las suposiciones de reversibilidad y permite realizar cálculos no intencionados a menor coste. En los sistemas de prueba que certifican el uso de recursos, esto puede permitir a los atacantes satisfacer las comprobaciones funcionales mientras evaden el modelo de costes que el verificador cree estar aplicando.

### Qué probar en sistemas ZK

- Fuzz todos los parsers guest con codificaciones malformadas de witness/private-input.
- Verifica el rango del enum antes del dispatch de opcode.
- Añade comprobaciones semánticas para el aliasing de operandos y otras formas de instrucciones no válidas.
- Compara los contadores reportados/públicos con una implementación de referencia independiente.
- Recuerda que una prueba válida aún puede demostrar la **afirmación equivocada** si el programa guest tiene errores.

## Explotación de DeFi/AMM

Si estás investigando la explotación práctica de DEXes y AMM (hooks de Uniswap v4, abuso del redondeo/la precisión, swaps de cruce de umbral amplificados mediante flash loans), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados multi-asset que almacenan en caché los saldos virtuales y pueden ser envenenados cuando `supply == 0`, estudia:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Prueba de participación - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Explicación de la clave pública y la clave privada - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [¿Qué son las transacciones multi-firma? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transacciones | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas y comisiones | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacidad - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Hemos superado la zero-knowledge proof de Google sobre criptoanálisis cuántico](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Protección de las criptomonedas de curva elíptica frente a vulnerabilidades cuánticas: estimaciones de recursos y mitigaciones (versión corregida)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repositorio de proof-of-concept de Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
