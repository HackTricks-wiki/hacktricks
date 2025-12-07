# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** se definen como programas que se ejecutan en una blockchain cuando se cumplen ciertas condiciones, automatizando la ejecución de acuerdos sin intermediarios.
- **Decentralized Applications (dApps)** se construyen sobre smart contracts, con un front-end orientado al usuario y un back-end transparente y auditable.
- **Tokens & Coins** se diferencian en que las coins sirven como dinero digital, mientras que los tokens representan valor o propiedad en contextos específicos.
- **Utility Tokens** otorgan acceso a servicios, y **Security Tokens** significan propiedad de un activo.
- **DeFi** significa Decentralized Finance, ofreciendo servicios financieros sin autoridades centrales.
- **DEX** y **DAOs** se refieren a Decentralized Exchange Platforms y Decentralized Autonomous Organizations, respectivamente.

## Consensus Mechanisms

Los mecanismos de consenso aseguran validaciones de transacciones seguras y acordadas en la blockchain:

- **Proof of Work (PoW)** se basa en poder computacional para la verificación de transacciones.
- **Proof of Stake (PoS)** exige que los validadores posean una cierta cantidad de tokens, reduciendo el consumo de energía comparado con PoW.

## Bitcoin Essentials

### Transactions

Las transacciones de Bitcoin implican transferir fondos entre direcciones. Las transacciones se validan mediante firmas digitales, garantizando que sólo el propietario de la clave privada pueda iniciar transferencias.

#### Key Components:

- **Multisignature Transactions** requieren múltiples firmas para autorizar una transacción.
- Las transacciones consisten en **inputs** (origen de los fondos), **outputs** (destino), **fees** (pagadas a los miners) y **scripts** (reglas de la transacción).

### Lightning Network

Busca mejorar la escalabilidad de Bitcoin permitiendo múltiples transacciones dentro de un canal, transmitiendo a la blockchain sólo el estado final.

## Bitcoin Privacy Concerns

Los ataques a la privacidad, como **Common Input Ownership** y **UTXO Change Address Detection**, explotan patrones de transacción. Estrategias como **Mixers** y **CoinJoin** mejoran el anonimato al ocultar enlaces de transacciones entre usuarios.

## Acquiring Bitcoins Anonymously

Los métodos incluyen intercambios en efectivo, minería y el uso de mixers. **CoinJoin** mezcla múltiples transacciones para complicar el rastreo, mientras que **PayJoin** disfraza CoinJoins como transacciones regulares para mayor privacidad.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

En el mundo de Bitcoin, la privacidad de las transacciones y el anonimato de los usuarios suelen ser motivo de preocupación. Aquí hay un resumen simplificado de varios métodos comunes mediante los cuales los atacantes pueden comprometer la privacidad en Bitcoin.

## **Common Input Ownership Assumption**

Generalmente es raro que inputs de diferentes usuarios se combinen en una misma transacción debido a la complejidad involucrada. Por lo tanto, **dos direcciones de input en la misma transacción a menudo se asumen como pertenecientes al mismo propietario**.

## **UTXO Change Address Detection**

Un UTXO, o Salida de Transacción No Gastada, debe gastarse por completo en una transacción. Si sólo una parte se envía a otra dirección, el resto va a una nueva dirección de cambio. Los observadores pueden asumir que esta nueva dirección pertenece al remitente, comprometiendo la privacidad.

### Example

Para mitigar esto, los servicios de mezcla o el uso de múltiples direcciones pueden ayudar a ocultar la titularidad.

## **Social Networks & Forums Exposure**

Los usuarios a veces comparten sus direcciones de Bitcoin en línea, lo que hace **fácil vincular la dirección con su propietario**.

## **Transaction Graph Analysis**

Las transacciones pueden visualizarse como grafos, revelando conexiones potenciales entre usuarios basadas en el flujo de fondos.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Esta heurística se basa en analizar transacciones con múltiples inputs y outputs para adivinar cuál output es el cambio que vuelve al remitente.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si añadir más inputs hace que la salida de change sea mayor que cualquier input individual, puede confundir la heurística.

## **Forced Address Reuse**

Los atacantes pueden enviar pequeñas cantidades a direcciones previamente usadas, con la esperanza de que el destinatario las combine con otros inputs en transacciones futuras, vinculando así las direcciones entre sí.

### Correct Wallet Behavior

Wallets deberían evitar usar monedas recibidas en direcciones ya usadas y vacías para prevenir este privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Las transacciones sin change es probable que sean entre dos direcciones pertenecientes al mismo usuario.
- **Round Numbers:** Un número redondo en una transacción sugiere que es un pago, siendo la salida no redonda probablemente el change.
- **Wallet Fingerprinting:** Diferentes wallets tienen patrones únicos de creación de transacciones, permitiendo a los analistas identificar el software usado y potencialmente la dirección de change.
- **Amount & Timing Correlations:** Revelar los tiempos o montos de transacciones puede hacerlas trazables.

## **Traffic Analysis**

Monitorizando el tráfico de red, los atacantes pueden potencialmente vincular transacciones o bloques a direcciones IP, comprometiendo la privacidad del usuario. Esto es especialmente cierto si una entidad opera muchos nodos de Bitcoin, aumentando su capacidad para monitorizar transacciones.

## More

Para una lista comprensiva de ataques a la privacidad y defensas, visite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Adquirir bitcoin con efectivo.
- **Cash Alternatives**: Comprar gift cards y cambiarlas en línea por bitcoin.
- **Mining**: El método más privado para obtener bitcoins es mediante minería, especialmente si se hace en solitario, porque los mining pools pueden conocer la IP del minero. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teóricamente, robar bitcoin podría ser otro método para adquirirlos de forma anónima, aunque es ilegal y no recomendable.

## Mixing Services

Al usar un servicio de mixing, un usuario puede **enviar bitcoins** y recibir **bitcoins diferentes a cambio**, lo que dificulta rastrear al propietario original. Aun así, esto requiere confiar en que el servicio no guarde logs y que efectivamente devuelva los bitcoins. Opciones alternativas de mixing incluyen casinos de Bitcoin.

## CoinJoin

**CoinJoin** agrupa múltiples transacciones de diferentes usuarios en una sola, complicando el proceso para cualquiera que intente emparejar inputs con outputs. A pesar de su efectividad, las transacciones con tamaños únicos de inputs y outputs aún pueden ser rastreadas potencialmente.

Ejemplos de transacciones que pueden haber usado CoinJoin incluyen `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para más información, visite [CoinJoin](https://coinjoin.io/en). Para un servicio similar en Ethereum, vea [Tornado Cash](https://tornado.cash), que anonimiza transacciones con fondos de miners.

## PayJoin

Una variante de CoinJoin, **PayJoin** (or P2EP), disfraza la transacción entre dos partes (p. ej., un cliente y un comerciante) como una transacción normal, sin las salidas iguales distintivas características de CoinJoin. Esto la hace extremadamente difícil de detectar y podría invalidar la common-input-ownership heuristic usada por entidades de vigilancia de transacciones.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Las transacciones como la anterior podrían ser PayJoin, mejorando la privacidad mientras permanecen indistinguibles de las transacciones estándar de bitcoin.

**La utilización de PayJoin podría perturbar significativamente los métodos de vigilancia tradicionales**, lo que la convierte en un avance prometedor en la búsqueda de privacidad transaccional.

# Mejores prácticas para la privacidad en las criptomonedas

## **Técnicas de sincronización de wallets**

Para mantener la privacidad y la seguridad, sincronizar wallets con la blockchain es crucial. Destacan dos métodos:

- **Full node**: Al descargar toda la blockchain, un full node garantiza la máxima privacidad. Todas las transacciones realizadas se almacenan localmente, lo que hace imposible que adversarios identifiquen qué transacciones o direcciones le interesan al usuario.
- **Client-side block filtering**: Este método implica crear filtros para cada bloque de la blockchain, permitiendo que wallets identifiquen transacciones relevantes sin exponer intereses específicos a los observadores de la red. Lightweight wallets descargan estos filtros, solicitando los bloques completos solo cuando se encuentra una coincidencia con las direcciones del usuario.

## **Uso de Tor para anonimato**

Dado que Bitcoin opera en una red peer-to-peer, se recomienda usar Tor para ocultar tu dirección IP, mejorando la privacidad al interactuar con la red.

## **Prevención del reuso de direcciones**

Para proteger la privacidad, es vital usar una nueva dirección para cada transacción. Reusar direcciones puede comprometer la privacidad al vincular transacciones a la misma entidad. Las wallets modernas desalientan el reuso de direcciones mediante su diseño.

## **Estrategias para la privacidad de las transacciones**

- **Multiple transactions**: Dividir un pago en varias transacciones puede ocultar el monto, frustrando ataques de privacidad.
- **Change avoidance**: Optar por transacciones que no requieran change outputs mejora la privacidad al dificultar los métodos de detección de change.
- **Multiple change outputs**: Si evitar change no es factible, generar múltiples change outputs aún puede mejorar la privacidad.

# **Monero: Un faro de anonimato**

Monero aborda la necesidad de anonimato absoluto en las transacciones digitales, estableciendo un alto estándar para la privacidad.

# **Ethereum: Gas y transacciones**

## **Entendiendo Gas**

Gas mide el esfuerzo computacional necesario para ejecutar operaciones en Ethereum, valorado en **gwei**. Por ejemplo, una transacción que cuesta 2,310,000 gwei (o 0.00231 ETH) implica un gas limit y una base fee, con una propina para incentivar a los miners. Los usuarios pueden establecer una max fee para evitar pagar de más, y el excedente es reembolsado.

## **Ejecución de transacciones**

Las transacciones en Ethereum involucran un remitente y un destinatario, que pueden ser direcciones de usuario o de smart contract. Requieren una fee y deben ser minadas. La información esencial en una transacción incluye el destinatario, la firma del remitente, el valor, datos opcionales, gas limit y fees. Notablemente, la dirección del remitente se deduce de la firma, eliminando la necesidad de incluirla en los datos de la transacción.

Estas prácticas y mecanismos son fundamentales para cualquiera que quiera interactuar con las criptomonedas priorizando la privacidad y la seguridad.

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Referencias

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## Explotación de DeFi/AMM

Si estás investigando explotación práctica de DEXes y AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados multi-asset que cachean virtual balances y pueden ser envenenados cuando `supply == 0`, estudia:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
