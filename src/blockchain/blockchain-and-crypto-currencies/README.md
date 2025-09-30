# Blockchain y Criptomonedas

{{#include ../../banners/hacktricks-training.md}}

## Conceptos Básicos

- **Smart Contracts** se definen como programas que se ejecutan en una blockchain cuando se cumplen ciertas condiciones, automatizando la ejecución de acuerdos sin intermediarios.
- **Decentralized Applications (dApps)** se construyen sobre smart contracts, con un front-end amigable para el usuario y un back-end transparente y auditable.
- **Tokens & Coins** se diferencian en que las coins sirven como dinero digital, mientras que los tokens representan valor o propiedad en contextos específicos.
- **Utility Tokens** otorgan acceso a servicios, y **Security Tokens** significan la propiedad de un activo.
- **DeFi** significa Decentralized Finance, ofreciendo servicios financieros sin autoridades centrales.
- **DEX** y **DAOs** se refieren a Decentralized Exchange Platforms y Decentralized Autonomous Organizations, respectivamente.

## Mecanismos de Consenso

Los mecanismos de consenso aseguran la validación segura y acordada de transacciones en la blockchain:

- **Proof of Work (PoW)** se basa en potencia computacional para la verificación de transacciones.
- **Proof of Stake (PoS)** exige que los validators posean una cierta cantidad de tokens, reduciendo el consumo energético en comparación con PoW.

## Bitcoin Essentials

### Transactions

Las transacciones de Bitcoin implican transferir fondos entre direcciones. Las transacciones se validan mediante firmas digitales, asegurando que solo el propietario de la clave privada pueda iniciar transferencias.

#### Componentes clave:

- **Multisignature Transactions** requieren múltiples firmas para autorizar una transacción.
- Las transacciones consisten en **inputs** (fuente de fondos), **outputs** (destino), **fees** (pagados a miners) y **scripts** (reglas de la transacción).

### Lightning Network

Busca mejorar la escalabilidad de Bitcoin permitiendo múltiples transacciones dentro de un canal, publicando en la blockchain solo el estado final.

## Bitcoin Privacy Concerns

Los ataques a la privacidad, como **Common Input Ownership** y **UTXO Change Address Detection**, explotan patrones de transacción. Estrategias como **Mixers** y **CoinJoin** mejoran el anonimato al ocultar enlaces de transacción entre usuarios.

## Acquiring Bitcoins Anonymously

Los métodos incluyen intercambios en efectivo, mining y el uso de mixers. **CoinJoin** mezcla múltiples transacciones para complicar la trazabilidad, mientras que **PayJoin** disfraza CoinJoins como transacciones normales para mayor privacidad.

# Bitcoin Privacy Atacks

# Resumen de los ataques a la privacidad de Bitcoin

En el mundo de Bitcoin, la privacidad de las transacciones y el anonimato de los usuarios suelen ser motivo de preocupación. Aquí tienes una visión simplificada de varios métodos comunes mediante los cuales un atacante puede comprometer la privacidad en Bitcoin.

## **Common Input Ownership Assumption**

Generalmente es raro que inputs de diferentes usuarios se combinen en una misma transacción debido a la complejidad involucrada. Por tanto, **dos direcciones de input en la misma transacción a menudo se asumen como pertenecientes al mismo propietario**.

## **UTXO Change Address Detection**

Un UTXO, o **Unspent Transaction Output**, debe gastarse completamente en una transacción. Si solo se envía una parte a otra dirección, el resto va a una nueva change address. Los observadores pueden asumir que esta nueva dirección pertenece al remitente, comprometiendo la privacidad.

### Ejemplo

Para mitigar esto, los servicios de mixing o el uso de múltiples direcciones pueden ayudar a obscurecer la propiedad.

## **Social Networks & Forums Exposure**

Los usuarios a veces comparten sus direcciones de Bitcoin en línea, lo que hace **fácil vincular la dirección con su propietario**.

## **Transaction Graph Analysis**

Las transacciones pueden visualizarse como grafos, revelando conexiones potenciales entre usuarios según el flujo de fondos.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Este heurístico se basa en analizar transacciones con múltiples inputs y outputs para adivinar cuál output es el cambio que regresa al remitente.

### Ejemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si añadir más entradas hace que la salida de cambio sea mayor que cualquier entrada individual, puede confundir a la heurística.

## **Forced Address Reuse**

Los atacantes pueden enviar pequeñas cantidades a direcciones ya usadas, con la esperanza de que el destinatario las combine con otras entradas en transacciones futuras, vinculando así las direcciones.

### Correct Wallet Behavior

Wallets deberían evitar usar monedas recibidas en direcciones vacías ya usadas para prevenir este privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Las transacciones sin cambio probablemente sean entre dos direcciones pertenecientes al mismo usuario.
- **Round Numbers:** Un número redondo en una transacción sugiere que es un pago, siendo la salida no redonda probablemente el cambio.
- **Wallet Fingerprinting:** Diferentes wallets tienen patrones únicos al crear transacciones, lo que permite a los analistas identificar el software usado y potencialmente la dirección de cambio.
- **Amount & Timing Correlations:** Revelar los tiempos o montos de transacciones puede hacerlas rastreables.

## **Traffic Analysis**

Al monitorizar el tráfico de la red, los atacantes pueden potencialmente vincular transacciones o bloques a direcciones IP, comprometiendo la privacidad del usuario. Esto es especialmente cierto si una entidad opera muchos nodos Bitcoin, lo que mejora su capacidad para monitorizar transacciones.

## More

Para una lista completa de ataques y defensas de privacidad, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Adquirir bitcoin en efectivo.
- **Cash Alternatives**: Comprar tarjetas regalo y cambiarlas en línea por bitcoin.
- **Mining**: El método más privado para ganar bitcoins es mediante minería, especialmente si se hace en solitario, porque los mining pools pueden conocer la IP del minero. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teóricamente, robar bitcoin podría ser otro método para adquirirlo de forma anónima, aunque es ilegal y no recomendable.

## Mixing Services

Al usar un servicio de mezcla, un usuario puede **enviar bitcoins** y recibir **bitcoins diferentes a cambio**, lo que dificulta rastrear al propietario original. Aun así, esto requiere confiar en que el servicio no guarde logs y que realmente devuelva los bitcoins. Opciones alternativas de mezcla incluyen casinos Bitcoin.

## CoinJoin

**CoinJoin** combina múltiples transacciones de diferentes usuarios en una sola, complicando el proceso para quien intente emparejar entradas con salidas. A pesar de su efectividad, las transacciones con tamaños únicos de entradas y salidas aún pueden potencialmente ser rastreadas.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), disfraza la transacción entre dos partes (p. ej., un cliente y un comerciante) como una transacción normal, sin las salidas iguales distintivas características de CoinJoin. Esto la hace extremadamente difícil de detectar y podría invalidar la heurística common-input-ownership usada por entidades de vigilancia de transacciones.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transacciones como la anterior podrían ser PayJoin, mejorando la privacidad mientras permanecen indistinguibles de las transacciones estándar de bitcoin.

**La utilización de PayJoin podría perturbar significativamente los métodos tradicionales de vigilancia**, lo que la convierte en un avance prometedor en la búsqueda de privacidad transaccional.

# Mejores prácticas para la privacidad en criptomonedas

## **Técnicas de sincronización de wallet**

Para mantener la privacidad y la seguridad, sincronizar las wallets con la blockchain es crucial. Destacan dos métodos:

- **Full node**: Al descargar la blockchain completa, un full node garantiza la máxima privacidad. Todas las transacciones realizadas se almacenan localmente, haciendo imposible que los adversarios identifiquen qué transacciones o direcciones interesan al usuario.
- **Client-side block filtering**: Este método consiste en crear filtros para cada bloque de la blockchain, permitiendo a las wallets identificar transacciones relevantes sin exponer intereses específicos a los observadores de la red. Las wallets ligeras descargan estos filtros, solo obteniendo bloques completos cuando se encuentra una coincidencia con las direcciones del usuario.

## **Uso de Tor para anonimato**

Dado que bitcoin opera en una red peer-to-peer, se recomienda usar Tor para ocultar tu dirección IP, mejorando la privacidad al interactuar con la red.

## **Evitar la reutilización de direcciones**

Para proteger la privacidad, es vital usar una dirección nueva para cada transacción. Reutilizar direcciones puede comprometer la privacidad al vincular transacciones con la misma entidad. Las wallets modernas desincentivan la reutilización de direcciones a través de su diseño.

## **Estrategias para la privacidad de las transacciones**

- **Multiple transactions**: Dividir un pago en varias transacciones puede oscurecer la cantidad, frustrando ataques contra la privacidad.
- **Change avoidance**: Optar por transacciones que no requieran outputs de cambio mejora la privacidad al dificultar los métodos de detección de cambio.
- **Multiple change outputs**: Si evitar el cambio no es factible, generar múltiples outputs de cambio aún puede mejorar la privacidad.

# **Monero: Un faro de anonimato**

Monero aborda la necesidad de anonimato absoluto en las transacciones digitales, estableciendo un alto estándar para la privacidad.

# **Ethereum: Gas y transacciones**

## **Comprendiendo Gas**

Gas mide el esfuerzo computacional necesario para ejecutar operaciones en Ethereum, valorado en **gwei**. Por ejemplo, una transacción que cuesta 2,310,000 gwei (o 0.00231 ETH) implica un gas limit y una base fee, con un tip para incentivar a los mineros. Los usuarios pueden establecer un max fee para asegurarse de no pagar de más, con el exceso reembolsado.

## **Ejecución de transacciones**

Las transacciones en Ethereum involucran un remitente y un destinatario, que pueden ser direcciones de usuario o de smart contracts. Requieren una fee y deben ser minadas. La información esencial en una transacción incluye el destinatario, la firma del remitente, el valor, datos opcionales, gas limit y fees. Notablemente, la dirección del remitente se deduce de la firma, eliminando la necesidad de incluirla en los datos de la transacción.

Estas prácticas y mecanismos son fundamentales para cualquiera que quiera interactuar con criptomonedas mientras prioriza la privacidad y la seguridad.

## Referencias

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## Explotación DeFi/AMM

Si investigas la explotación práctica de DEXes y AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
