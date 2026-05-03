# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** se definen como programas que se ejecutan en una blockchain cuando se cumplen ciertas condiciones, automatizando la ejecución de acuerdos sin intermediarios.
- **Decentralized Applications (dApps)** se construyen sobre smart contracts, y cuentan con un front-end fácil de usar y un back-end transparente y auditable.
- **Tokens & Coins** diferencian dónde las coins sirven como dinero digital, mientras que los tokens representan valor o propiedad en contextos específicos.
- **Utility Tokens** conceden acceso a servicios, y **Security Tokens** significan propiedad de activos.
- **DeFi** significa Decentralized Finance, ofreciendo servicios financieros sin autoridades centrales.
- **DEX** y **DAOs** se refieren a Decentralized Exchange Platforms y Decentralized Autonomous Organizations, respectivamente.

## Consensus Mechanisms

Los consensus mechanisms garantizan validaciones de transacciones seguras y acordadas en la blockchain:

- **Proof of Work (PoW)** depende de la capacidad computacional para la verificación de transacciones.
- **Proof of Stake (PoS)** exige que los validadores mantengan una cierta cantidad de tokens, reduciendo el consumo de energía en comparación con PoW.

## Bitcoin Essentials

### Transactions

Las transacciones de Bitcoin implican transferir fondos entre addresses. Las transacciones se validan mediante firmas digitales, asegurando que solo el propietario de la private key pueda iniciar transferencias.

#### Key Components:

- Las **Multisignature Transactions** requieren múltiples firmas para autorizar una transacción.
- Las transacciones constan de **inputs** (origen de los fondos), **outputs** (destino), **fees** (pagadas a los miners) y **scripts** (reglas de la transacción).

### Lightning Network

Tiene como objetivo mejorar la escalabilidad de Bitcoin permitiendo múltiples transacciones dentro de un channel, publicando solo el estado final a la blockchain.

## Bitcoin Privacy Concerns

Los ataques de privacidad, como **Common Input Ownership** y **UTXO Change Address Detection**, explotan patrones de transacción. Estrategias como **Mixers** y **CoinJoin** mejoran el anonimato al ocultar los vínculos de transacción entre usuarios.

## Acquiring Bitcoins Anonymously

Los métodos incluyen intercambios en efectivo, mining y el uso de mixers. **CoinJoin** mezcla múltiples transacciones para complicar la trazabilidad, mientras que **PayJoin** disfraza CoinJoins como transacciones normales para una mayor privacidad.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

En el mundo de Bitcoin, la privacidad de las transacciones y el anonimato de los usuarios suelen ser motivo de preocupación. Aquí tienes una visión simplificada de varios métodos comunes mediante los cuales los atacantes pueden comprometer la privacidad de Bitcoin.

## **Common Input Ownership Assumption**

Por lo general, rara vez se combinan inputs de diferentes usuarios en una sola transacción debido a la complejidad que implica. Por ello, **a menudo se asume que dos direcciones de input en la misma transacción pertenecen al mismo propietario**.

## **UTXO Change Address Detection**

Un UTXO, o **Unspent Transaction Output**, debe gastarse por completo en una transacción. Si solo una parte se envía a otra address, el resto va a una nueva change address. Los observadores pueden asumir que esta nueva address pertenece al remitente, comprometiendo la privacidad.

### Example

Para mitigar esto, los servicios de mixing o el uso de múltiples addresses pueden ayudar a ocultar la propiedad.

## **Social Networks & Forums Exposure**

A veces, los usuarios comparten sus direcciones de Bitcoin en línea, lo que hace que sea **fácil vincular la address con su propietario**.

## **Transaction Graph Analysis**

Las transacciones pueden visualizarse como grafos, revelando posibles conexiones entre usuarios basadas en el flujo de fondos.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Esta heurística se basa en analizar transacciones con múltiples inputs y outputs para adivinar qué output es el cambio que regresa al remitente.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si agregar más entradas hace que la salida del cambio sea mayor que cualquier entrada individual, puede confundir la heurística.

## **Forced Address Reuse**

Los attackers pueden enviar pequeñas cantidades a direcciones usadas previamente, con la esperanza de que el receptor las combine con otras entradas en transacciones futuras, vinculando así direcciones entre sí.

### Correct Wallet Behavior

Los wallets deberían evitar usar coins recibidas en direcciones ya usadas y vacías para prevenir este leak de privacidad.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Las transacciones sin change probablemente son entre dos direcciones propiedad del mismo usuario.
- **Round Numbers:** Un número redondo en una transacción sugiere que es un pago, y la salida no redonda probablemente sea el change.
- **Wallet Fingerprinting:** Distintos wallets tienen patrones únicos de creación de transacciones, lo que permite a los analistas identificar el software usado y potencialmente la dirección de change.
- **Amount & Timing Correlations:** Revelar tiempos o cantidades de transacciones puede hacer que sean rastreables.

## **Traffic Analysis**

Al monitorear el tráfico de red, los attackers pueden vincular potencialmente transacciones o blocks con direcciones IP, comprometiendo la privacidad del usuario. Esto es especialmente cierto si una entidad opera muchos nodos de Bitcoin, aumentando su capacidad para monitorear transacciones.

## More

Para una lista completa de privacy attacks y defenses, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Adquirir bitcoin mediante cash.
- **Cash Alternatives**: Comprar gift cards e intercambiarlas en línea por bitcoin.
- **Mining**: El método más privado para ganar bitcoins es mediante mining, especialmente cuando se hace en solitario porque los mining pools pueden conocer la IP address del miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teóricamente, robar bitcoin podría ser otro método para adquirirlo anónimamente, aunque es ilegal y no se recomienda.

## Mixing Services

Al usar un mixing service, un user puede **send bitcoins** y recibir **different bitcoins in return**, lo que dificulta rastrear al owner original. Aun así, esto requiere confiar en que el service no guarde logs y que realmente devuelva los bitcoins. Otras opciones de mixing incluyen Bitcoin casinos.

## CoinJoin

**CoinJoin** combina múltiples transactions de distintos users en una sola, complicando el proceso para cualquiera que intente hacer match entre inputs y outputs. A pesar de su efectividad, las transactions con tamaños únicos de input y output aún pueden ser rastreadas.

Ejemplo de transactions que pueden haber usado CoinJoin incluyen `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para más información, visita [CoinJoin](https://coinjoin.io/en). Para un servicio similar en Ethereum, revisa [Tornado Cash](https://tornado.cash), que anonimiza transactions con funds de miners.

## PayJoin

Una variante de CoinJoin, **PayJoin** (o P2EP), disfraza la transaction entre dos parties (p. ej., un customer y un merchant) como una transaction regular, sin la característica distintiva de outputs iguales propia de CoinJoin. Esto hace que sea extremadamente difícil de detectar y podría invalidar la common-input-ownership heuristic usada por entidades de surveillance de transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**La utilización de PayJoin podría alterar significativamente los métodos tradicionales de vigilancia**, convirtiéndolo en un desarrollo prometedor en la búsqueda de privacidad transaccional.

# Mejores prácticas para la privacidad en cryptocurrencies

## **Técnicas de sincronización de Wallet**

Para mantener la privacidad y la seguridad, sincronizar wallets con la blockchain es crucial. Destacan dos métodos:

- **Full node**: Al descargar toda la blockchain, un full node garantiza la máxima privacidad. Todas las transacciones realizadas alguna vez se almacenan localmente, lo que hace imposible que los adversarios identifiquen qué transacciones o direcciones interesan al usuario.
- **Client-side block filtering**: Este método consiste en crear filtros para cada bloque de la blockchain, lo que permite a las wallets identificar transacciones relevantes sin exponer intereses específicos a observadores de la red. Las lightweight wallets descargan estos filtros y solo obtienen bloques completos cuando se encuentra una coincidencia con las direcciones del usuario.

## **Utilizar Tor para el anonimato**

Dado que Bitcoin funciona sobre una red peer-to-peer, se recomienda usar Tor para ocultar tu dirección IP, mejorando la privacidad al interactuar con la red.

## **Evitar la reutilización de direcciones**

Para proteger la privacidad, es vital usar una nueva dirección para cada transacción. Reutilizar direcciones puede comprometer la privacidad al vincular transacciones con la misma entidad. Las wallets modernas desalientan la reutilización de direcciones mediante su diseño.

## **Estrategias para la privacidad de las transacciones**

- **Múltiples transacciones**: Dividir un pago en varias transacciones puede ocultar el monto de la transacción y frustrar ataques de privacidad.
- **Evitar change**: Optar por transacciones que no requieran salidas de change mejora la privacidad al dificultar los métodos de detección de change.
- **Múltiples salidas de change**: Si evitar change no es posible, generar múltiples salidas de change aún puede mejorar la privacidad.

# **Monero: Un faro de anonimato**

Monero aborda la necesidad de anonimato absoluto en las transacciones digitales, estableciendo un alto estándar de privacidad.

# **Ethereum: Gas y transacciones**

## **Entender Gas**

Gas mide el esfuerzo computacional necesario para ejecutar operaciones en Ethereum, con precio en **gwei**. Por ejemplo, una transacción que cuesta 2,310,000 gwei (o 0.00231 ETH) implica un gas limit y una base fee, con una propina para incentivar a los miners. Los users pueden fijar una max fee para asegurarse de no pagar de más, y el exceso se reembolsa.

## **Ejecutar transacciones**

Las transacciones en Ethereum implican un sender y un recipient, que pueden ser direcciones de user o smart contract. Requieren una fee y deben ser mined. La información esencial en una transacción incluye el recipient, la signature del sender, el value, data opcional, el gas limit y las fees. Cabe destacar que la address del sender se deduce a partir de la signature, eliminando la necesidad de incluirla en los transaction data.

Estas prácticas y mecanismos son fundamentales para cualquiera que quiera interactuar con cryptocurrencies priorizando la privacidad y la seguridad.

## Red Teaming de Web3 centrado en el valor

- Inventariar componentes con valor (signers, oracles, bridges, automation) para entender quién puede mover fondos y cómo.
- Mapear cada componente a las tácticas relevantes de MITRE AADAPT para exponer rutas de privilege escalation.
- Ensayar cadenas de ataque flash-loan/oracle/credential/cross-chain para validar el impacto y documentar precondiciones explotables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromiso del flujo de trabajo de signing en Web3

- La manipulación de la supply-chain de las UIs de wallet puede mutar payloads EIP-712 justo antes de firmar, obteniendo signatures válidas para takeover de proxy basado en delegatecall (por ejemplo, overwrite de slot-0 de Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Los modos de fallo comunes de smart-account incluyen bypass de `EntryPoint` access control, unsigned gas fields, stateful validation, ERC-1271 replay y fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing para encontrar puntos ciegos en suites de pruebas:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridad de la prueba ZK / guest de zkVM

Cuando un prover usa una **zkVM** o un circuito de prueba específico de la aplicación para atestiguar una afirmación, el verifier solo está aprendiendo que el **guest program se ejecutó tal como fue escrito**. Si el guest contiene **unsafe deserialization**, **undefined behavior** o **missing semantic constraints**, un prover malicioso puede generar una proof que verifica mientras las **métricas públicas o el invariant declarado son falsos**.

### Unsafe deserialization dentro de proof guests

- Trata los bytes privados de witness/circuit como **untrusted attacker input** incluso si están ocultos por la proof.
- Evita deserializarlos con helpers sin validación como `rkyv::access_unchecked` a menos que los bytes ya hayan sido validados fuera de banda.
- Los enum discriminants, relative pointers, lengths e indexes cargados desde datos serializados no confiables deben validarse antes de que influyan en el control flow o en el acceso a memoria.

Patrón práctico de auditoría:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Si un campo como `op.kind` es un enum y un atacante puede inyectar un **discriminante fuera de rango**, cada `match` posterior sobre ese valor se vuelve sospechoso.

### Omitir la tabla de salto / bypass de UB

Si Rust reduce un `match` grande a una **jump table**, un discriminante de enum inválido puede producir **flujo de control indefinido**. Un patrón peligroso es:

1. Un `match` actualiza **contadores/constraints críticos de seguridad**.
2. Un segundo `match` realiza la **semántica real de la instrucción**.
3. Un discriminante fuera de rango indexa más allá de la primera jump table y cae en código asociado con la segunda.

Resultado: la operación sigue ejecutándose, pero se omite la ruta de accounting. En un zkVM esto puede falsificar proofs que reporten métricas imposibles, como menos gates, menos operaciones costosas u otros recursos acotados falsificados.

Checklist de revisión:

- Busca enums controlados por el atacante deserializados desde witness/private input.
- Inspecciona sentencias `match` repetidas sobre el mismo opcode/kind field.
- Trata `unsafe` + deserialización sin comprobación + dispatch grande de opcodes como una combinación de alto riesgo.
- Reverse engineer el binario emitido cuando sea necesario; el layout de la jump table puede importar más que el source.

### Falta de constraints semánticas en interpreters reversibles/especializados

No valides solo la seguridad de memoria; valida también las **reglas semánticas** que la proof pretende imponer.

Para instruction sets reversibles/cuántico-like, asegúrate de que los operands que deben ser distintos estén realmente constrained para ser distintos. Una operación tipo Toffoli/CCX implementada como:
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
se vuelve inseguro si el invitado no rechaza:
```text
op.q_control1 == op.q_control2 == op.q_target
```
En ese caso, la transición se colapsa en:
```text
q = q ^ (q & q) = 0
```
Esto crea una **primitive de reset determinista**, rompiendo los supuestos de reversibilidad y permitiendo computaciones no intencionadas más baratas. En sistemas de proof que certifican el uso de recursos, esto puede permitir a los atacantes satisfacer checks funcionales mientras eluden el modelo de coste que el verifier cree que se está aplicando.

### Qué probar en sistemas ZK

- Haz fuzzing de todos los parsers del guest con codificaciones malformed de witness/private-input.
- Afirmar la validación del rango de enum antes del dispatch de opcode.
- Añadir semantic checks para operand aliasing y otras formas de instrucción invalid.
- Comparar los contadores reportados/public frente a una implementación de referencia independiente.
- Recuerda que un proof válido aún puede demostrar la **wrong statement** si el programa guest tiene bugs.

## Explotación DeFi/AMM

Si estás investigando explotación práctica de DEXes y AMMs (Uniswap v4 hooks, abuso de rounding/precision, threshold-crossing swaps amplificados por flash-loan), revisa:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados de múltiples activos que cachean virtual balances y pueden ser poisoned cuando `supply == 0`, estudia:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## Referencias

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [Google patched paper version](https://arxiv.org/abs/2603.28846v2)
- [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}
