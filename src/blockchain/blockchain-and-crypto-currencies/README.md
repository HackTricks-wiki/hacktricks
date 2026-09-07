# Blockchain y Criptomonedas

{{#include ../../banners/hacktricks-training.md}}

## Conceptos básicos

- Los **Smart Contracts** se definen como programas que se ejecutan en una blockchain cuando se cumplen ciertas condiciones, automatizando la ejecución de acuerdos sin intermediarios.
- Las **Aplicaciones descentralizadas (dApps)** se basan en smart contracts e incorporan un front-end fácil de usar y un back-end transparente y auditable.
- **Tokens y Coins** se diferencian en que las coins sirven como dinero digital, mientras que los tokens representan valor o propiedad en contextos específicos.
- Los **Utility Tokens** proporcionan acceso a servicios, mientras que los **Security Tokens** representan la propiedad de activos.
- **DeFi** significa Finanzas Descentralizadas y ofrece servicios financieros sin autoridades centrales.
- **DEX** y **DAOs** hacen referencia, respectivamente, a plataformas de intercambio descentralizadas y organizaciones autónomas descentralizadas.

## Mecanismos de consenso

Los mecanismos de consenso garantizan validaciones de transacciones seguras y acordadas en la blockchain:

- **Proof of Work (PoW)** depende de la potencia computacional para verificar las transacciones.
- **Proof of Stake (PoS)** exige que los validadores posean una cierta cantidad de tokens, reduciendo el consumo energético en comparación con PoW.<sup>[[1]](#references)</sup>

## Conceptos esenciales de Bitcoin

### Transacciones

Las transacciones de Bitcoin implican transferir fondos entre direcciones. Las transacciones se validan mediante firmas digitales, lo que garantiza que solo el propietario de la clave privada pueda iniciar transferencias.<sup>[[2]](#references)</sup>

#### Componentes principales:

- Las **Transacciones Multisignature** requieren varias firmas para autorizar una transacción.<sup>[[3]](#references)</sup>
- Las transacciones constan de **inputs** (fuente de los fondos), **outputs** (destino), **fees** (pagadas a los miners) y **scripts** (reglas de la transacción).

### Lightning Network

Su objetivo es mejorar la escalabilidad de Bitcoin permitiendo múltiples transacciones dentro de un canal y transmitiendo únicamente el estado final a la blockchain.

## Problemas de privacidad de Bitcoin

Los ataques contra la privacidad, como **Common Input Ownership** y **UTXO Change Address Detection**, explotan los patrones de las transacciones. Estrategias como **Mixers** y **CoinJoin** mejoran el anonimato al ocultar los vínculos entre las transacciones de los usuarios.

## Adquirir Bitcoins de forma anónima

Los métodos incluyen intercambios en efectivo, mining y el uso de mixers. **CoinJoin** mezcla múltiples transacciones para complicar la trazabilidad, mientras que **PayJoin** disfraza los CoinJoins como transacciones normales para mejorar la privacidad.

# Resumen de los ataques contra la privacidad de Bitcoin

En el mundo de Bitcoin, la privacidad de las transacciones y el anonimato de los usuarios suelen ser motivo de preocupación. A continuación se presenta una descripción simplificada de varios métodos comunes mediante los cuales los atacantes pueden comprometer la privacidad de Bitcoin.<sup>[[6]](#references)</sup>

## **Suposición de propiedad común de los inputs**

Por lo general, es poco frecuente que los inputs de distintos usuarios se combinen en una sola transacción debido a la complejidad implicada. Por ello, a menudo se supone que **las dos direcciones de input de una misma transacción pertenecen al mismo propietario**.

## **Detección de direcciones de cambio UTXO**

Un UTXO, o **Unspent Transaction Output**, debe gastarse por completo en una transacción. Si solo se envía una parte a otra dirección, el resto se envía a una nueva dirección de cambio. Los observadores pueden suponer que esta nueva dirección pertenece al remitente, comprometiendo la privacidad.

### Ejemplo

Para mitigar esto, los servicios de mixing o el uso de múltiples direcciones pueden ayudar a ocultar la propiedad.

## **Exposición en redes sociales y foros**

A veces, los usuarios comparten sus direcciones de Bitcoin en línea, lo que hace que sea **fácil vincular la dirección con su propietario**.

## **Análisis del grafo de transacciones**

Las transacciones pueden visualizarse como grafos, revelando posibles conexiones entre usuarios basadas en el flujo de fondos.

## **Heurística de inputs innecesarios (heurística de cambio óptimo)**

Esta heurística se basa en analizar transacciones con múltiples inputs y outputs para intentar determinar qué output corresponde al cambio que regresa al remitente.

### Ejemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si añadir más inputs hace que el change output sea mayor que cualquier input individual, puede confundir la heuristic.

## **Forced Address Reuse**

Los atacantes pueden enviar pequeñas cantidades a direcciones utilizadas anteriormente, con la esperanza de que el destinatario las combine con otros inputs en transacciones futuras, vinculando así las direcciones entre sí.

### Correct Wallet Behavior

Los wallets deben evitar utilizar coins recibidos en direcciones ya utilizadas y vacías para prevenir este privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Las transacciones sin change probablemente se realizan entre dos direcciones pertenecientes al mismo usuario.
- **Round Numbers:** Un número redondo en una transacción sugiere que se trata de un pago, mientras que el output no redondo probablemente sea el change.
- **Wallet Fingerprinting:** Los distintos wallets tienen patrones únicos de creación de transacciones, lo que permite a los analistas identificar el software utilizado y, potencialmente, la dirección de change.
- **Amount & Timing Correlations:** Revelar los horarios o las cantidades de las transacciones puede hacer que estas sean rastreables.

## **Traffic Analysis**

Al monitorizar el tráfico de red, los atacantes pueden potencialmente vincular transacciones o bloques con direcciones IP, comprometiendo la privacidad de los usuarios. Esto es especialmente cierto si una entidad opera muchos nodos de Bitcoin, mejorando su capacidad para monitorizar transacciones.

## More

Para consultar una lista completa de ataques y defensas de privacidad, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Adquirir bitcoin mediante efectivo.
- **Cash Alternatives**: Comprar gift cards e intercambiarlas online por bitcoin.
- **Mining**: El método más privado para obtener bitcoins es mediante mining, especialmente cuando se realiza en solitario, porque los mining pools pueden conocer la dirección IP del miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: En teoría, robar bitcoin podría ser otro método para adquirirlo de forma anónima, aunque es ilegal y no se recomienda.

## Mixing Services

Al utilizar un mixing service, un usuario puede **send bitcoins** y recibir **different bitcoins in return**, lo que dificulta rastrear al propietario original. Sin embargo, esto requiere confiar en que el servicio no conserve logs y realmente devuelva los bitcoins. Entre las opciones alternativas de mixing se incluyen los casinos de Bitcoin.

## CoinJoin

**CoinJoin** combina múltiples transacciones de diferentes usuarios en una sola, complicando el proceso para cualquiera que intente asociar inputs con outputs. A pesar de su eficacia, las transacciones con tamaños únicos de inputs y outputs aún pueden rastrearse potencialmente.

Entre las transacciones de ejemplo que pueden haber utilizado CoinJoin se incluyen `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para obtener más información, visita [CoinJoin](https://coinjoin.io/en). Para consultar un mixer de smart-contract de Ethereum que separa los depósitos de los retiros posteriores, visita [Tornado Cash](https://tornado.cash).

## PayJoin

Una variante de CoinJoin, **PayJoin** (o P2EP), disfraza la transacción entre dos partes (por ejemplo, un cliente y un merchant) como una transacción normal, sin los outputs iguales distintivos característicos de CoinJoin. Esto hace que sea extremadamente difícil de detectar y podría invalidar la common-input-ownership heuristic utilizada por las entidades de vigilancia de transacciones.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transacciones como la anterior podrían ser PayJoin, mejorando la privacidad mientras siguen siendo indistinguibles de las transacciones estándar de bitcoin.

**El uso de PayJoin podría alterar significativamente los métodos tradicionales de vigilancia**, convirtiéndolo en un desarrollo prometedor en la búsqueda de privacidad transaccional.

# Mejores prácticas para la privacidad en las criptomonedas

## **Técnicas de sincronización de wallets**

Para mantener la privacidad y la seguridad, es crucial sincronizar las wallets con la blockchain. Destacan dos métodos:

- **Full node**: Al descargar la blockchain completa, un full node garantiza la máxima privacidad. Todas las transacciones realizadas se almacenan localmente, lo que impide que los adversarios identifiquen qué transacciones o direcciones le interesan al usuario.
- **Client-side block filtering**: Este método consiste en crear filtros para cada bloque de la blockchain, lo que permite a las wallets identificar transacciones relevantes sin revelar intereses específicos a los observadores de la red. Las wallets ligeras descargan estos filtros y solo obtienen los bloques completos cuando encuentran una coincidencia con las direcciones del usuario.

## **Uso de Tor para el anonimato**

Dado que Bitcoin opera en una red peer-to-peer, se recomienda usar Tor para ocultar la dirección IP y mejorar la privacidad al interactuar con la red.

## **Prevención de la reutilización de direcciones**

Para proteger la privacidad, es fundamental usar una dirección nueva en cada transacción. Reutilizar direcciones puede comprometer la privacidad al vincular las transacciones con la misma entidad. Las wallets modernas desaconsejan la reutilización de direcciones mediante su diseño.

## **Estrategias para la privacidad de las transacciones**

- **Múltiples transacciones**: Dividir un pago en varias transacciones puede ocultar el importe de la transacción y frustrar los ataques contra la privacidad.
- **Evitar el cambio**: Optar por transacciones que no requieran outputs de cambio mejora la privacidad al dificultar los métodos de detección del cambio.
- **Múltiples outputs de cambio**: Si no es posible evitar el cambio, generar múltiples outputs de cambio aún puede mejorar la privacidad.

# **Monero: Un faro del anonimato**

Monero está diseñado para priorizar la privacidad de las transacciones.

# **Ethereum: Gas y transacciones**

## **Comprender el gas**

El gas mide el esfuerzo computacional necesario para ejecutar operaciones en Ethereum y se expresa en **gwei**. Por ejemplo, una transacción con un coste de 2.310.000 gwei (o 0,00231 ETH) implica un límite de gas y una comisión base, junto con una comisión de prioridad para incentivar la inclusión por parte del validador. Los usuarios pueden establecer una comisión máxima para asegurarse de no pagar de más, y el excedente se reembolsa.<sup>[[5]](#references)</sup>

## **Ejecución de transacciones**

Las transacciones en Ethereum implican un emisor y un destinatario, que pueden ser direcciones de usuario o de smart contracts. Requieren una comisión y deben incluirse en un bloque. La información esencial de una transacción incluye el destinatario, la firma del emisor, el valor, los datos opcionales, el límite de gas y las comisiones. Cabe destacar que la dirección del emisor se deduce de la firma, por lo que no es necesario incluirla en los datos de la transacción.<sup>[[4]](#references)</sup>

Estas prácticas y mecanismos son fundamentales para cualquiera que quiera interactuar con criptomonedas priorizando la privacidad y la seguridad.

## Red Teaming centrado en el valor de Web3

- Inventariar los componentes que contienen valor (signers, oracles, bridges, automation) para comprender quién puede mover fondos y cómo.
- Asignar cada componente a las tácticas relevantes de MITRE AADAPT para exponer rutas de escalada de privilegios.
- Ensayar cadenas de ataque de flash-loan/oracle/credential/cross-chain para validar el impacto y documentar las precondiciones explotables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Compromiso del flujo de firma de Web3

- La manipulación de la supply chain de las interfaces de wallet puede modificar los payloads EIP-712 justo antes de la firma, obteniendo firmas válidas para takeovers de proxies basados en delegatecall (por ejemplo, la sobrescritura del slot-0 de `masterCopy` de Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Entre los fallos comunes de los smart accounts se incluyen el bypass del control de acceso de `EntryPoint`, campos de gas sin firma, validación con estado, replay de ERC-1271 y drenaje de comisiones mediante revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Seguridad de smart contracts

- Mutation testing para encontrar puntos ciegos en las suites de pruebas:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridad de los ZK Proof / zkVM Guest

Cuando un prover utiliza una **zkVM** o un circuito de proof específico de una aplicación para demostrar una afirmación, el verifier solo aprende que el **guest program se ejecutó tal como está escrito**. Si el guest contiene **unsafe deserialization**, **undefined behavior** o **semantic constraints ausentes**, un prover malicioso puede generar un proof que se verifique aunque las **métricas públicas o el invariant declarado sean falsos**.<sup>[[7]](#references)</sup>

### Unsafe deserialization dentro de los proof guests

- Tratar los bytes privados del witness/circuit como **entrada no confiable controlada por el atacante**, incluso si están ocultos por el proof.
- Evitar deserializarlos con helpers sin comprobaciones como `rkyv::access_unchecked`, a menos que los bytes ya se hayan validado out-of-band.
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

Si Rust convierte un `match` grande en una **jump table**, un discriminante de enum no válido puede producir un **flujo de control indefinido**. Un patrón peligroso es:<sup>[[7]](#references)[[9]](#references)</sup>

1. Un `match` actualiza **contadores/restricciones críticos para la seguridad**.
2. Un segundo `match` ejecuta la **semántica real de la instrucción**.
3. Un discriminante fuera de rango indexa más allá de la primera jump table y aterriza en código asociado a la segunda.

Resultado: la operación se sigue ejecutando, pero se omite la ruta de contabilización. En una zkVM, esto puede falsificar proofs que informen métricas imposibles, como menos gates, menos operaciones costosas u otros recursos limitados falsificados.

Lista de comprobación de revisión:

- Busca enums controlados por el atacante y deserializados desde witness/private input.
- Inspecciona las sentencias `match` repetidas sobre el mismo campo de opcode/kind.
- Considera `unsafe` + deserialización sin comprobaciones + dispatch de opcode grande como una combinación de alto riesgo.
- Haz reverse engineering del binario generado cuando sea necesario; el diseño de la jump table puede ser más importante que el código fuente.

### Restricciones semánticas ausentes en intérpretes reversibles/especializados

No valides únicamente la seguridad de la memoria; valida también las **reglas semánticas** que el proof debe imponer.

En instruction sets reversibles/similares a los cuánticos, asegúrate de que los operandos que deben ser distintos estén realmente restringidos para que sean distintos. Una operación similar a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>
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
Esto crea una **primitiva de restablecimiento determinista**, rompe las suposiciones de reversibilidad y permite realizar cálculos no previstos a menor coste. En los sistemas de prueba que atestiguan el uso de recursos, esto puede permitir que los atacantes satisfagan las comprobaciones funcionales mientras evitan el modelo de costes que el verificador cree estar aplicando.

### Qué probar en sistemas ZK

- Aplicar fuzzing a todos los parsers del guest con codificaciones de witness/private-input malformadas.
- Asegurar la validación del rango de los enums antes del dispatch de opcodes.
- Añadir comprobaciones semánticas para el aliasing de operandos y otras formas de instrucciones no válidas.
- Comparar los contadores reportados/públicos con una implementación de referencia independiente.
- Recordar que una prueba válida aún puede demostrar la **afirmación equivocada** si el programa guest contiene errores.

## Autorización dependiente del estado

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## DeFi/AMM Exploitation

Si estás investigando la explotación práctica de DEXes y AMMs (hooks de Uniswap v4, abuso del redondeo/la precisión, swaps de cruce de umbral amplificados mediante flash-loan), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados multi-asset que almacenan en caché balances virtuales y pueden ser envenenados cuando `supply == 0`, estudia:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Clave pública y clave privada explicadas - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [¿Qué son las transacciones multi-firma? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transacciones | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas y comisiones | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacidad - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Superamos la prueba de conocimiento cero de Google sobre criptoanálisis cuántico](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Protección de las criptomonedas de curva elíptica frente a vulnerabilidades cuánticas: estimaciones de recursos y mitigaciones (versión corregida)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repositorio de prueba de concepto de Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}
