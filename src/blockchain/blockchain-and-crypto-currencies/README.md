# Blockchain y Criptomonedas

{{#include ../../banners/hacktricks-training.md}}

## Conceptos Básicos

- **Smart Contracts** se definen como programas que se ejecutan en una blockchain cuando se cumplen ciertas condiciones, automatizando la ejecución de acuerdos sin intermediarios.
- **Decentralized Applications (dApps)** se construyen sobre smart contracts, contando con una interfaz de usuario amigable y un back-end transparente y auditable.
- **Tokens & Coins** diferencian roles: las coins sirven como dinero digital, mientras que los tokens representan valor o propiedad en contextos específicos.
- **Utility Tokens** otorgan acceso a servicios, y **Security Tokens** indican propiedad de un activo.
- **DeFi** significa Decentralized Finance, ofreciendo servicios financieros sin autoridades centrales.
- **DEX** y **DAOs** se refieren a Decentralized Exchange Platforms y Decentralized Autonomous Organizations, respectivamente.

## Mecanismos de Consenso

Los mecanismos de consenso aseguran la validación segura y acordada de transacciones en la blockchain:

- **Proof of Work (PoW)** se basa en potencia computacional para la verificación de transacciones.
- **Proof of Stake (PoS)** exige que los validators posean una cierta cantidad de tokens, reduciendo el consumo energético en comparación con PoW.

## Esenciales de Bitcoin

### Transacciones

Las transacciones de Bitcoin implican transferir fondos entre direcciones. Las transacciones se validan mediante firmas digitales, asegurando que solo el propietario de la clave privada pueda iniciar transferencias.

#### Componentes clave:

- **Multisignature Transactions** requieren múltiples firmas para autorizar una transacción.
- Las transacciones consisten en **inputs** (fuente de fondos), **outputs** (destino), **fees** (pagados a los miners) y **scripts** (reglas de la transacción).

### Lightning Network

Tiene como objetivo mejorar la escalabilidad de Bitcoin permitiendo múltiples transacciones dentro de un canal, transmitiendo a la blockchain solo el estado final.

## Preocupaciones de Privacidad en Bitcoin

Los ataques a la privacidad, como **Common Input Ownership** y **UTXO Change Address Detection**, explotan patrones de transacción. Estrategias como **Mixers** y **CoinJoin** mejoran el anonimato al oscurecer los vínculos de transacción entre usuarios.

## Adquisición Anónima de Bitcoins

Los métodos incluyen intercambios en efectivo, minería y el uso de mixers. **CoinJoin** mezcla múltiples transacciones para complicar la trazabilidad, mientras que **PayJoin** disfraza CoinJoins como transacciones regulares para mayor privacidad.

# Ataques de Privacidad en Bitcoin

# Resumen de los Ataques de Privacidad en Bitcoin

En el mundo de Bitcoin, la privacidad de las transacciones y el anonimato de los usuarios suelen ser motivo de preocupación. Aquí hay una visión simplificada de varios métodos comunes mediante los cuales los atacantes pueden comprometer la privacidad en Bitcoin.

## **Common Input Ownership Assumption**

Generalmente es raro que inputs de diferentes usuarios se combinen en una sola transacción debido a la complejidad involucrada. Por lo tanto, **dos direcciones input en la misma transacción a menudo se asumen como pertenecientes al mismo propietario**.

## **UTXO Change Address Detection**

Un UTXO, o **Unspent Transaction Output**, debe gastarse completamente en una transacción. Si solo se envía una parte a otra dirección, el resto va a una nueva change address. Los observadores pueden asumir que esta nueva dirección pertenece al remitente, comprometiendo la privacidad.

### Ejemplo

Para mitigar esto, los servicios de mixing o el uso de múltiples direcciones pueden ayudar a oscurecer la propiedad.

## **Exposición en Redes Sociales y Foros**

Los usuarios a veces comparten sus direcciones de Bitcoin en línea, lo que hace **fácil vincular la dirección con su propietario**.

## **Análisis del Grafo de Transacciones**

Las transacciones pueden visualizarse como grafos, revelando posibles conexiones entre usuarios basadas en el flujo de fondos.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Esta heurística se basa en analizar transacciones con múltiples inputs y outputs para adivinar qué output es el cambio que regresa al remitente.

### Ejemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si añadir más entradas hace que la salida de cambio sea mayor que cualquier entrada individual, puede confundir la heurística.

## **Forced Address Reuse**

Los atacantes pueden enviar pequeñas cantidades a direcciones usadas previamente, esperando que el destinatario las combine con otras entradas en transacciones futuras, vinculando así las direcciones.

### Correct Wallet Behavior

Las wallets deben evitar usar monedas recibidas en direcciones ya usadas y vacías para prevenir esta leak de privacidad.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Las transacciones sin cambio probablemente sean entre dos direcciones propiedad del mismo usuario.
- **Round Numbers:** Un número redondo en una transacción sugiere que es un pago, siendo la salida no redonda probablemente el cambio.
- **Wallet Fingerprinting:** Diferentes wallets tienen patrones únicos de creación de transacciones, lo que permite a los analistas identificar el software usado y, potencialmente, la dirección de cambio.
- **Amount & Timing Correlations:** Revelar los tiempos o montos de transacciones puede hacer que las transacciones sean rastreables.

## **Traffic Analysis**

Al monitorizar el tráfico de red, los atacantes pueden potencialmente vincular transacciones o bloques a direcciones IP, comprometiendo la privacidad del usuario. Esto es especialmente cierto si una entidad opera muchos nodos Bitcoin, lo que mejora su capacidad para monitorear transacciones.

## More

Para una lista completa de ataques y defensas de privacidad, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transacciones anónimas de Bitcoin

## Formas de obtener Bitcoins de forma anónima

- **Cash Transactions**: Adquirir bitcoin con efectivo.
- **Cash Alternatives**: Comprar tarjetas de regalo y cambiarlas en línea por bitcoin.
- **Mining**: El método más privado para ganar bitcoins es la minería, especialmente si se realiza en solitario, porque los mining pools pueden conocer la dirección IP del minero. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teóricamente, robar bitcoin podría ser otro método para adquirirlo de forma anónima, aunque es ilegal y no recomendable.

## Mixing Services

Al usar un servicio de mezcla, un usuario puede **enviar bitcoins** y recibir **bitcoins distintos a cambio**, lo que dificulta rastrear al propietario original. Sin embargo, esto requiere confiar en que el servicio no guarde logs y que realmente devuelva los bitcoins. Opciones alternativas de mezcla incluyen casinos de Bitcoin.

## CoinJoin

**CoinJoin** combina múltiples transacciones de diferentes usuarios en una, complicando el proceso para cualquiera que intente emparejar entradas con salidas. A pesar de su efectividad, las transacciones con tamaños de entrada y salida únicos aún pueden ser trazadas potencialmente.

Transacciones de ejemplo que pueden haber usado CoinJoin incluyen `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para más información, visita [CoinJoin](https://coinjoin.io/en). Para un servicio similar en Ethereum, revisa [Tornado Cash](https://tornado.cash), que anonimiza transacciones con fondos de mineros.

## PayJoin

Una variante de CoinJoin, **PayJoin** (o P2EP), disfraza la transacción entre dos partes (por ejemplo, un cliente y un comerciante) como una transacción normal, sin las salidas iguales distintivas características de CoinJoin. Esto la hace extremadamente difícil de detectar y podría invalidar la heurística common-input-ownership usada por entidades de vigilancia de transacciones.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**La utilización de PayJoin podría alterar significativamente los métodos tradicionales de vigilancia**, convirtiéndolo en un avance prometedor en la búsqueda de privacidad transaccional.

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

Para mantener la privacidad y la seguridad, sincronizar las wallets con la blockchain es crucial. Dos métodos destacan:

- **Full node**: Descargando toda la blockchain, un full node garantiza la máxima privacidad. Todas las transacciones realizadas se almacenan localmente, haciendo imposible que los adversarios identifiquen qué transacciones o direcciones le interesan al usuario.
- **Client-side block filtering**: Este método consiste en crear filtros para cada bloque de la blockchain, permitiendo a las wallets identificar transacciones relevantes sin exponer intereses específicos a observadores de la red. Las lightweight wallets descargan estos filtros, solicitando bloques completos solo cuando hay una coincidencia con las direcciones del usuario.

## **Utilizing Tor for Anonymity**

Dado que Bitcoin opera en una red peer-to-peer, se recomienda usar Tor para enmascarar tu dirección IP, mejorando la privacidad al interactuar con la red.

## **Preventing Address Reuse**

Para proteger la privacidad, es vital usar una dirección nueva para cada transacción. Reutilizar direcciones puede comprometer la privacidad al vincular transacciones con la misma entidad. Las wallets modernas desaconsejan la reutilización de direcciones mediante su diseño.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Dividir un pago en varias transacciones puede ocultar el monto de la transacción, frustrando ataques de privacidad.
- **Change avoidance**: Optar por transacciones que no requieran outputs de cambio mejora la privacidad al dificultar los métodos de detección de cambio.
- **Multiple change outputs**: Si evitar el cambio no es factible, generar múltiples outputs de cambio aún puede mejorar la privacidad.

# **Monero: A Beacon of Anonymity**

Monero aborda la necesidad de anonimato absoluto en las transacciones digitales, estableciendo un alto estándar de privacidad.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas mide el esfuerzo computacional necesario para ejecutar operaciones en Ethereum, valorado en **gwei**. Por ejemplo, una transacción que cueste 2,310,000 gwei (o 0.00231 ETH) implica un gas limit y una base fee, con una propina para incentivar a los miners. Los usuarios pueden establecer una max fee para asegurarse de no pagar de más; el excedente se reembolsa.

## **Executing Transactions**

Las transacciones en Ethereum involucran un remitente y un destinatario, que pueden ser direcciones de usuario o de smart contract. Requieren una fee y deben ser minadas. La información esencial en una transacción incluye el destinatario, la firma del remitente, el valor, datos opcionales, gas limit y fees. Notablemente, la dirección del remitente se deduce de la firma, eliminando la necesidad de incluirla en los datos de la transacción.

Estas prácticas y mecanismos son fundamentales para cualquiera que quiera interactuar con criptomonedas priorizando privacidad y seguridad.

## Value-Centric Web3 Red Teaming

- Inventariar componentes portadores de valor (signers, oracles, bridges, automation) para entender quién puede mover fondos y cómo.
- Mapear cada componente a tácticas MITRE AADAPT relevantes para exponer rutas de escalada de privilegios.
- Ensayar cadenas de ataque flash-loan/oracle/credential/cross-chain para validar impacto y documentar precondiciones explotables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UIs puede mutar payloads EIP-712 justo antes de firmar, recolectando firmas válidas para takeovers de proxy basados en delegatecall (por ejemplo, overwrite de slot-0 del Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Modos de fallo comunes en smart-accounts incluyen la elusión del control de acceso de `EntryPoint`, campos de gas sin firmar, validación stateful, replay ERC-1271 y extracción de fees vía revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing para encontrar puntos ciegos en suites de pruebas:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

Si estás investigando explotación práctica de DEXes y AMMs (Uniswap v4 hooks, rounding/precision abuse, swaps amplificados por flash‑loan que cruzan umbrales), revisa:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados multi-asset que cachean balances virtuales y pueden ser envenenados cuando `supply == 0`, estudia:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
