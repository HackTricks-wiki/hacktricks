# Blockchain y Cripto-monedas

{{#include ../../banners/hacktricks-training.md}}

## Conceptos básicos

- **Contratos inteligentes (Smart Contracts)** son programas que se ejecutan en una blockchain cuando se cumplen ciertas condiciones, automatizando la ejecución de acuerdos sin intermediarios.
- **dApps (Decentralized Applications)** se construyen sobre contratos inteligentes, con un front-end amigable para el usuario y un back-end transparente y auditable.
- **Tokens & Coins** se diferencian en que las coins sirven como dinero digital, mientras que los tokens representan valor o propiedad en contextos específicos.
- **Utility Tokens** otorgan acceso a servicios, y **Security Tokens** representan la propiedad de un activo.
- **DeFi** significa Decentralized Finance, ofreciendo servicios financieros sin autoridades centrales.
- **DEX** y **DAOs** se refieren a plataformas de intercambio descentralizadas y organizaciones autónomas descentralizadas, respectivamente.

## Mecanismos de consenso

Los mecanismos de consenso aseguran la validación segura y acordada de transacciones en la blockchain:

- **Proof of Work (PoW)** se basa en la potencia computacional para la verificación de transacciones.
- **Proof of Stake (PoS)** requiere que los validadores mantengan una cierta cantidad de tokens, reduciendo el consumo energético en comparación con PoW.

## Conceptos esenciales de Bitcoin

### Transacciones

Las transacciones de Bitcoin implican transferir fondos entre direcciones. Las transacciones se validan mediante firmas digitales, asegurando que solo el propietario de la clave privada pueda iniciar transferencias.

#### Componentes clave:

- **Transacciones multifirma (Multisignature Transactions)** requieren múltiples firmas para autorizar una transacción.
- Las transacciones consisten en **inputs** (origen de los fondos), **outputs** (destino), **fees** (pagados a los miners) y **scripts** (reglas de la transacción).

### Lightning Network

Busca mejorar la escalabilidad de Bitcoin permitiendo múltiples transacciones dentro de un canal, solo transmitiendo el estado final a la blockchain.

## Preocupaciones de privacidad en Bitcoin

Los ataques a la privacidad, como **Common Input Ownership** y **UTXO Change Address Detection**, explotan patrones de las transacciones. Estrategias como **Mixers** y **CoinJoin** mejoran el anonimato al ocultar los enlaces entre transacciones de diferentes usuarios.

## Adquisición anónima de Bitcoins

Los métodos incluyen cambios en efectivo, minería y el uso de mixers. **CoinJoin** mezcla múltiples transacciones para complicar la trazabilidad, mientras que **PayJoin** disfraza CoinJoins como transacciones normales para mayor privacidad.

# Ataques de privacidad en Bitcoin

# Resumen de ataques de privacidad en Bitcoin

En el mundo de Bitcoin, la privacidad de las transacciones y el anonimato de los usuarios son a menudo motivo de preocupación. Aquí hay una visión simplificada de varios métodos comunes mediante los cuales los atacantes pueden comprometer la privacidad en Bitcoin.

## **Suposición de propiedad común de inputs (Common Input Ownership Assumption)**

Generalmente es raro que inputs de diferentes usuarios se combinen en una sola transacción debido a la complejidad involucrada. Por lo tanto, **dos direcciones input en la misma transacción a menudo se asumen pertenecen al mismo propietario**.

## **Detección de dirección de cambio UTXO (UTXO Change Address Detection)**

Un UTXO (Unspent Transaction Output) debe gastarse completamente en una transacción. Si solo se envía una parte a otra dirección, el resto va a una nueva dirección de cambio. Los observadores pueden asumir que esta nueva dirección pertenece al remitente, comprometiendo la privacidad.

### Ejemplo

Para mitigar esto, los servicios de mixing o el uso de múltiples direcciones pueden ayudar a ocultar la propiedad.

## **Exposición en redes sociales y foros**

Los usuarios a veces comparten sus direcciones de Bitcoin en línea, lo que facilita **vincular la dirección con su propietario**.

## **Análisis del grafo de transacciones**

Las transacciones pueden visualizarse como grafos, revelando conexiones potenciales entre usuarios basadas en el flujo de fondos.

## **Heurística de input innecesario (Optimal Change Heuristic)**

Esta heurística se basa en analizar transacciones con múltiples inputs y outputs para adivinar cuál output es el cambio que regresa al remitente.

### Ejemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si añadir más inputs hace que la salida de change sea más grande que cualquier input individual, puede confundir a la heurística.

## **Forced Address Reuse**

Los atacantes pueden enviar pequeñas cantidades a direcciones usadas anteriormente, con la esperanza de que el receptor las combine con otros inputs en transacciones futuras, enlazando así las direcciones entre sí.

### Comportamiento correcto del wallet

Las wallets deberían evitar usar coins recibidas en direcciones vacías ya usadas para prevenir este privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Las transacciones sin change probablemente sean entre dos direcciones propiedad del mismo usuario.
- **Round Numbers:** Un número redondo en una transacción sugiere que es un pago, y la salida no redonda probablemente sea el change.
- **Wallet Fingerprinting:** Diferentes wallets tienen patrones únicos de creación de transacciones, lo que permite a los analistas identificar el software usado y potencialmente la dirección de change.
- **Amount & Timing Correlations:** Revelar los tiempos o montos de transacciones puede hacer a las transacciones rastreables.

## **Traffic Analysis**

Al monitorizar el tráfico de red, los atacantes pueden potencialmente vincular transacciones o bloques a direcciones IP, comprometiendo la privacidad del usuario. Esto es especialmente cierto si una entidad opera muchos nodos de Bitcoin, lo que mejora su capacidad para supervisar transacciones.

## Más

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transacciones anónimas de Bitcoin

## Formas de obtener Bitcoins de forma anónima

- **Cash Transactions**: Adquirir bitcoin con efectivo.
- **Cash Alternatives**: Comprar tarjetas regalo y cambiarlas en línea por bitcoin.
- **Mining**: El método más privado para obtener bitcoins es la minería, especialmente si se hace en solitario, ya que los mining pools pueden conocer la dirección IP del minero. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: En teoría, robar bitcoin podría ser otro método para adquirirlo anónimamente, aunque es ilegal y no recomendable.

## Mixing Services

Al usar un servicio de mezcla, un usuario puede **enviar bitcoins** y recibir **bitcoins diferentes a cambio**, lo que complica rastrear al propietario original. Sin embargo, esto requiere confiar en que el servicio no guarde logs y que realmente devuelva los bitcoins. Opciones alternativas de mezclado incluyen casinos de Bitcoin.

## CoinJoin

CoinJoin combina múltiples transacciones de distintos usuarios en una sola, complicando el proceso de emparejar inputs con outputs. A pesar de su efectividad, las transacciones con tamaños únicos de inputs y outputs aún pueden ser rastreadas potencialmente.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para más información, visita [CoinJoin](https://coinjoin.io/en). Para un servicio similar en Ethereum, consulta [Tornado Cash](https://tornado.cash), que anonimiza transacciones con fondos de los mineros.

## PayJoin

Una variante de CoinJoin, **PayJoin** (o P2EP), disfraza la transacción entre dos partes (p. ej., un cliente y un comerciante) como una transacción normal, sin las salidas iguales distintivas características de CoinJoin. Esto hace que sea extremadamente difícil de detectar y podría invalidar la common-input-ownership heuristic usada por entidades de vigilancia de transacciones.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transacciones como la anterior podrían ser PayJoin, mejorando la privacidad mientras permanecen indistinguibles de las transacciones estándar de bitcoin.

**La utilización de PayJoin podría perturbar significativamente los métodos tradicionales de vigilancia**, convirtiéndolo en un avance prometedor en la búsqueda de privacidad transaccional.

# Mejores prácticas para la privacidad en criptomonedas

## **Técnicas de sincronización de wallets**

Para mantener la privacidad y la seguridad, sincronizar las wallets con la blockchain es crucial. Destacan dos métodos:

- **Full node**: Al descargar toda la blockchain, un nodo completo garantiza la máxima privacidad. Todas las transacciones realizadas se almacenan localmente, haciendo imposible que los adversarios identifiquen cuáles transacciones o direcciones interesan al usuario.
- **Client-side block filtering**: Este método consiste en crear filtros para cada bloque de la blockchain, permitiendo a las wallets identificar transacciones relevantes sin exponer intereses específicos a los observadores de la red. Las wallets ligeras descargan estos filtros, solicitando bloques completos solo cuando hay una coincidencia con las direcciones del usuario.

## **Utilizar Tor para anonimato**

Dado que Bitcoin opera en una red peer-to-peer, se recomienda usar Tor para ocultar tu dirección IP, mejorando la privacidad al interactuar con la red.

## **Prevenir la reutilización de direcciones**

Para salvaguardar la privacidad, es vital usar una dirección nueva para cada transacción. Reutilizar direcciones puede comprometer la privacidad al vincular transacciones con la misma entidad. Las wallets modernas desalientan la reutilización de direcciones mediante su diseño.

## **Estrategias para la privacidad de las transacciones**

- **Múltiples transacciones**: Dividir un pago en varias transacciones puede ocultar el monto de la transacción, frustrando ataques de privacidad.
- **Evitación del cambio**: Optar por transacciones que no requieran salidas de cambio mejora la privacidad al dificultar los métodos de detección de cambio.
- **Múltiples salidas de cambio**: Si evitar el cambio no es factible, generar múltiples salidas de cambio todavía puede mejorar la privacidad.

# **Monero: Un faro de anonimato**

Monero responde a la necesidad de anonimato absoluto en las transacciones digitales, estableciendo un alto estándar para la privacidad.

# **Ethereum: Gas y transacciones**

## **Entendiendo el gas**

El gas mide el esfuerzo computacional necesario para ejecutar operaciones en Ethereum, valorado en **gwei**. Por ejemplo, una transacción que cuesta 2,310,000 gwei (o 0.00231 ETH) implica un gas limit y una base fee, con una propina para incentivar a los mineros. Los usuarios pueden establecer una tarifa máxima para asegurarse de no pagar de más, con el exceso reembolsado.

## **Ejecución de transacciones**

Las transacciones en Ethereum involucran un remitente y un destinatario, que pueden ser direcciones de usuario o de smart contracts. Requieren una tarifa y deben ser minadas. La información esencial en una transacción incluye el destinatario, la firma del remitente, el valor, datos opcionales, límite de gas y tarifas. Cabe destacar que la dirección del remitente se deduce de la firma, eliminando la necesidad de incluirla en los datos de la transacción.

Estas prácticas y mecanismos son fundamentales para cualquiera que quiera interactuar con criptomonedas priorizando la privacidad y la seguridad.

## Smart Contract Security

- Pruebas de mutación para encontrar puntos ciegos en los conjuntos de pruebas:

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

## Explotación DeFi/AMM

Si estás investigando la explotación práctica de DEXes y AMMs (Uniswap v4 hooks, abuso de redondeo/precisión, swaps de cruce de umbral amplificados por flash‑loan), consulta:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
