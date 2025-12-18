# Blockchain y Criptomonedas

{{#include ../../banners/hacktricks-training.md}}

## Conceptos Básicos

- **Smart Contracts** se definen como programas que se ejecutan en una blockchain cuando se cumplen ciertas condiciones, automatizando la ejecución de acuerdos sin intermediarios.
- **Decentralized Applications (dApps)** se basan en smart contracts, contando con un front-end amigable y un back-end transparente y auditable.
- **Tokens & Coins** diferencian donde las coins sirven como dinero digital, mientras que los tokens representan valor o propiedad en contextos específicos.
- **Utility Tokens** otorgan acceso a servicios, y **Security Tokens** significan la propiedad de un activo.
- **DeFi** significa Decentralized Finance, ofreciendo servicios financieros sin autoridades centrales.
- **DEX** y **DAOs** se refieren a Decentralized Exchange Platforms y Decentralized Autonomous Organizations, respectivamente.

## Mecanismos de Consenso

Los mecanismos de consenso aseguran la validación segura y acordada de transacciones en la blockchain:

- **Proof of Work (PoW)** se basa en poder computacional para la verificación de transacciones.
- **Proof of Stake (PoS)** exige que los validadores posean una cierta cantidad de tokens, reduciendo el consumo energético en comparación con PoW.

## Conceptos Esenciales de Bitcoin

### Transacciones

Las transacciones de Bitcoin implican transferir fondos entre direcciones. Las transacciones se validan mediante firmas digitales, garantizando que solo el propietario de la clave privada pueda iniciar transferencias.

#### Componentes clave:

- **Multisignature Transactions** requieren múltiples firmas para autorizar una transacción.
- Las transacciones consisten en **inputs** (origen de los fondos), **outputs** (destino), **fees** (pagados a los miners) y **scripts** (reglas de la transacción).

### Lightning Network

Busca mejorar la escalabilidad de Bitcoin permitiendo múltiples transacciones dentro de un canal, publicando solo el estado final en la blockchain.

## Preocupaciones de Privacidad en Bitcoin

Los ataques a la privacidad, como **Common Input Ownership** y **UTXO Change Address Detection**, explotan patrones de transacción. Estrategias como **Mixers** y **CoinJoin** mejoran el anonimato al obscurecer los vínculos de las transacciones entre usuarios.

## Adquirir Bitcoins Anónimamente

Los métodos incluyen intercambios en efectivo, minado y el uso de mixers. **CoinJoin** mezcla múltiples transacciones para complicar la trazabilidad, mientras que **PayJoin** disfraza CoinJoins como transacciones regulares para mayor privacidad.

# Ataques de Privacidad en Bitcoin

# Resumen de Ataques de Privacidad en Bitcoin

En el mundo de Bitcoin, la privacidad de las transacciones y el anonimato de los usuarios son a menudo motivo de preocupación. Aquí hay un resumen simplificado de varios métodos comunes mediante los cuales los atacantes pueden comprometer la privacidad en Bitcoin.

## **Common Input Ownership Assumption**

Generalmente es raro que inputs de diferentes usuarios se combinen en una sola transacción debido a la complejidad involucrada. Por lo tanto, **dos direcciones de input en la misma transacción a menudo se asumen como pertenecientes al mismo propietario**.

## **UTXO Change Address Detection**

Un UTXO, o **Unspent Transaction Output**, debe gastarse completamente en una transacción. Si solo se envía una parte a otra dirección, el resto va a una nueva change address. Los observadores pueden asumir que esta nueva dirección pertenece al remitente, comprometiendo la privacidad.

### Ejemplo

Para mitigar esto, los servicios de mixing o el uso de múltiples direcciones pueden ayudar a obscurecer la pertenencia.

## Exposición en Redes Sociales y Foros

Los usuarios a veces comparten sus direcciones de Bitcoin en línea, lo que hace **fácil vincular la dirección con su propietario**.

## Análisis del Grafo de Transacciones

Las transacciones pueden visualizarse como grafos, revelando posibles conexiones entre usuarios basadas en el flujo de fondos.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Esta heurística se basa en analizar transacciones con múltiples inputs y outputs para adivinar cuál output es el change que regresa al remitente.

### Ejemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si agregar más entradas hace que la salida de cambio sea mayor que cualquier entrada individual, puede confundir la heurística.

## **Forced Address Reuse**

Los atacantes pueden enviar pequeñas cantidades a direcciones usadas previamente, esperando que el destinatario combine estas con otras entradas en transacciones futuras, vinculando así las direcciones.

### Correct Wallet Behavior

Los wallets deberían evitar usar monedas recibidas en direcciones ya usadas y vacías para prevenir esta privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Las transacciones sin salida de cambio probablemente sean entre dos direcciones pertenecientes al mismo usuario.
- **Round Numbers:** Un número redondo en una transacción sugiere que es un pago, y la salida no redonda probablemente sea la salida de cambio.
- **Wallet Fingerprinting:** Diferentes wallets tienen patrones únicos de creación de transacciones, lo que permite a los analistas identificar el software usado y potencialmente la dirección de cambio.
- **Amount & Timing Correlations:** Revelar los tiempos o las cantidades de las transacciones puede hacerlas rastreables.

## **Traffic Analysis**

Al monitorear el tráfico de la red, los atacantes pueden potencialmente vincular transacciones o bloques a direcciones IP, comprometiendo la privacidad del usuario. Esto es especialmente cierto si una entidad opera muchos nodos de Bitcoin, lo que mejora su capacidad para monitorear transacciones.

## More

Para una lista completa de privacy attacks and defenses, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Adquirir bitcoin con efectivo.
- **Cash Alternatives**: Comprar tarjetas de regalo y cambiarlas en línea por bitcoin.
- **Mining**: El método más privado para obtener bitcoins es mediante mining, especialmente si se hace en solitario porque los mining pools pueden conocer la dirección IP del minero. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teóricamente, robar bitcoin podría ser otro método para obtenerlo de forma anónima, aunque es ilegal y no recomendable.

## Mixing Services

Al usar un servicio de mezcla, un usuario puede **enviar bitcoins** y recibir **bitcoins diferentes a cambio**, lo que dificulta rastrear al propietario original. Sin embargo, esto requiere confiar en que el servicio no guarde logs y que realmente devuelva los bitcoins. Opciones alternativas de mezcla incluyen casinos de Bitcoin.

## CoinJoin

**CoinJoin** combina múltiples transacciones de diferentes usuarios en una sola, complicando el proceso para cualquiera que intente emparejar inputs con outputs. A pesar de su efectividad, las transacciones con tamaños únicos de inputs y outputs aún pueden potencialmente ser rastreadas.

Transacciones de ejemplo que pueden haber usado CoinJoin incluyen `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para más información, visita [CoinJoin](https://coinjoin.io/en). Para un servicio similar en Ethereum, revisa [Tornado Cash](https://tornado.cash), que anonimiza transacciones con fondos de mineros.

## PayJoin

Una variante de CoinJoin, **PayJoin** (o P2EP), disfraza la transacción entre dos partes (por ejemplo, un cliente y un comerciante) como una transacción normal, sin las salidas iguales distintivas características de CoinJoin. Esto hace que sea extremadamente difícil de detectar y podría invalidar la heurística common-input-ownership utilizada por entidades de vigilancia de transacciones.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transacciones como las anteriores podrían ser PayJoin, mejorando la privacidad a la vez que permanecen indistinguibles de las transacciones estándar de bitcoin.

**El uso de PayJoin podría perturbar significativamente los métodos tradicionales de vigilancia**, lo que lo convierte en un avance prometedor en la búsqueda de privacidad transaccional.

# Best Practices for Privacy in Cryptocurrencies

## **Wallet Synchronization Techniques**

Para mantener la privacidad y la seguridad, sincronizar wallets con la blockchain es crucial. Dos métodos destacan:

- **Full node**: Al descargar la blockchain completa, un full node asegura privacidad máxima. Todas las transacciones realizadas se almacenan localmente, haciendo imposible que los adversarios identifiquen qué transacciones o direcciones interesan al usuario.
- **Client-side block filtering**: Este método implica crear filtros para cada bloque de la blockchain, permitiendo que los wallets identifiquen transacciones relevantes sin exponer intereses específicos a los observadores de la red. Wallets ligeros descargan estos filtros, solo obteniendo bloques completos cuando hay una coincidencia con las direcciones del usuario.

## **Utilizing Tor for Anonymity**

Dado que Bitcoin opera en una red peer-to-peer, se recomienda usar Tor para ocultar tu dirección IP, mejorando la privacidad al interactuar con la red.

## **Preventing Address Reuse**

Para proteger la privacidad, es vital usar una dirección nueva para cada transacción. Reutilizar direcciones puede comprometer la privacidad al vincular transacciones con la misma entidad. Los wallets modernos desaconsejan la reutilización de direcciones mediante su diseño.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Dividir un pago en varias transacciones puede oscurecer el monto de la transacción, frustrando ataques a la privacidad.
- **Change avoidance**: Optar por transacciones que no requieran change outputs mejora la privacidad al dificultar los métodos de detección de change.
- **Multiple change outputs**: Si evitar el change no es factible, generar múltiples change outputs todavía puede mejorar la privacidad.

# **Monero: A Beacon of Anonymity**

Monero aborda la necesidad de anonimato absoluto en las transacciones digitales, estableciendo un alto estándar para la privacidad.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

El Gas mide el esfuerzo computacional necesario para ejecutar operaciones en Ethereum, valorado en **gwei**. Por ejemplo, una transacción que cuesta 2,310,000 gwei (o 0.00231 ETH) implica un gas limit y una base fee, con una propina (tip) para incentivar a los miners. Los usuarios pueden establecer un max fee para asegurarse de no pagar de más; el excedente se reembolsa.

## **Executing Transactions**

Las transacciones en Ethereum implican un emisor y un receptor, que pueden ser direcciones de usuario o de smart contracts. Requieren una fee y deben ser minadas. La información esencial en una transacción incluye el receptor, la firma del emisor, el valor, datos opcionales, gas limit y las fees. Cabe destacar que la dirección del emisor se deduce de la firma, por lo que no es necesaria en los datos de la transacción.

Estas prácticas y mecanismos son fundamentales para cualquiera que quiera interactuar con criptomonedas priorizando la privacidad y la seguridad.

## Value-Centric Web3 Red Teaming

- Inventariar los componentes que contienen valor (signers, oracles, bridges, automation) para entender quién puede mover fondos y cómo.
- Mapear cada componente a las tácticas relevantes de MITRE AADAPT para exponer rutas de escalada de privilegios.
- Ensayar cadenas de ataque de flash-loan/oracle/credential/cross-chain para validar el impacto y documentar las precondiciones explotables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

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

Si estás investigando la explotación práctica de DEXes y AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados multi-activo que cachean saldos virtuales y pueden ser envenenados cuando `supply == 0`, estudia:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
