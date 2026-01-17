# Blockchain y Criptomonedas

{{#include ../../banners/hacktricks-training.md}}

## Conceptos Básicos

- **Smart Contracts** se definen como programas que se ejecutan en una blockchain cuando se cumplen ciertas condiciones, automatizando la ejecución de acuerdos sin intermediarios.
- **Decentralized Applications (dApps)** se basan en smart contracts, con un front-end amigable para el usuario y un back-end transparente y auditable.
- **Tokens & Coins** se diferencian en que las coins sirven como dinero digital, mientras que los tokens representan valor o propiedad en contextos específicos.
- **Utility Tokens** otorgan acceso a servicios, y **Security Tokens** señalan la propiedad de un activo.
- **DeFi** significa Decentralized Finance (Finanzas Descentralizadas), ofreciendo servicios financieros sin autoridades centrales.
- **DEX** y **DAOs** se refieren a Decentralized Exchange Platforms (plataformas de intercambio descentralizadas) y Decentralized Autonomous Organizations (organizaciones autónomas descentralizadas), respectivamente.

## Mecanismos de Consenso

Los mecanismos de consenso aseguran validaciones de transacciones seguras y acordadas en la blockchain:

- **Proof of Work (PoW)** se basa en poder computacional para la verificación de transacciones.
- **Proof of Stake (PoS)** exige que los validadores posean una cierta cantidad de tokens, reduciendo el consumo de energía en comparación con PoW.

## Conceptos Esenciales de Bitcoin

### Transacciones

Las transacciones de Bitcoin implican transferir fondos entre direcciones. Las transacciones se validan mediante firmas digitales, garantizando que solo el propietario de la clave privada pueda iniciar transferencias.

#### Componentes clave:

- **Multisignature Transactions** requieren múltiples firmas para autorizar una transacción.
- Las transacciones consisten en **inputs** (fuente de fondos), **outputs** (destino), **fees** (pagadas a los mineros) y **scripts** (reglas de la transacción).

### Lightning Network

Tiene como objetivo mejorar la escalabilidad de Bitcoin permitiendo múltiples transacciones dentro de un canal, transmitiendo a la blockchain solo el estado final.

## Preocupaciones de privacidad de Bitcoin

Los ataques a la privacidad, como **Common Input Ownership** y **UTXO Change Address Detection**, explotan patrones de transacciones. Estrategias como **Mixers** y **CoinJoin** mejoran el anonimato al ocultar los enlaces entre transacciones de los usuarios.

## Adquirir Bitcoins de forma anónima

Los métodos incluyen intercambios en efectivo, minería y el uso de mixers. **CoinJoin** mezcla múltiples transacciones para complicar la trazabilidad, mientras que **PayJoin** disfraza CoinJoins como transacciones regulares para mayor privacidad.

# Ataques de privacidad en Bitcoin

# Resumen de ataques de privacidad en Bitcoin

En el mundo de Bitcoin, la privacidad de las transacciones y el anonimato de los usuarios suelen ser motivo de preocupación. Aquí hay una visión simplificada de varios métodos comunes mediante los cuales los atacantes pueden comprometer la privacidad en Bitcoin.

## **Common Input Ownership Assumption**

Generalmente es raro que inputs de diferentes usuarios se combinen en una sola transacción debido a la complejidad que implica. Por lo tanto, **dos direcciones de input en la misma transacción a menudo se asumen como pertenecientes al mismo propietario**.

## **UTXO Change Address Detection**

Un UTXO, o **Unspent Transaction Output**, debe gastarse completamente en una transacción. Si solo una parte se envía a otra dirección, el resto va a una nueva dirección de cambio. Los observadores pueden asumir que esta nueva dirección pertenece al remitente, comprometiendo la privacidad.

### Ejemplo

Para mitigar esto, los servicios de mixing o usar múltiples direcciones pueden ayudar a ocultar la propiedad.

## **Social Networks & Forums Exposure**

Los usuarios a veces comparten sus direcciones de Bitcoin en línea, lo que hace **fácil vincular la dirección con su propietario**.

## **Transaction Graph Analysis**

Las transacciones pueden visualizarse como grafos, revelando conexiones potenciales entre usuarios basadas en el flujo de fondos.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Esta heurística se basa en analizar transacciones con múltiples inputs y outputs para adivinar qué output es el cambio que regresa al remitente.

### Ejemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si añadir más entradas hace que la salida de cambio sea mayor que cualquier entrada individual, puede confundir la heurística.

## **Forced Address Reuse**

Los atacantes pueden enviar pequeñas cantidades a direcciones usadas anteriormente, esperando que el destinatario combine estas con otras entradas en transacciones futuras, vinculando así direcciones entre sí.

### Comportamiento correcto del monedero

Los monederos deberían evitar usar monedas recibidas en direcciones ya usadas y vacías para prevenir esta privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Las transacciones sin cambio probablemente sean entre dos direcciones propiedad del mismo usuario.
- **Round Numbers:** Un número redondo en una transacción sugiere que es un pago, siendo la salida no redonda probablemente el cambio.
- **Wallet Fingerprinting:** Diferentes wallets tienen patrones únicos de creación de transacciones, lo que permite a los analistas identificar el software usado y potencialmente la dirección de cambio.
- **Amount & Timing Correlations:** Revelar tiempos o cantidades de transacciones puede hacer que las transacciones sean rastreables.

## **Traffic Analysis**

Monitoreando el tráfico de la red, los atacantes pueden potencialmente vincular transacciones o bloques a direcciones IP, comprometiendo la privacidad del usuario. Esto es especialmente cierto si una entidad opera muchos nodos de Bitcoin, lo que mejora su capacidad para monitorear transacciones.

## More

Para una lista completa de ataques a la privacidad y defensas, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Adquirir bitcoin con efectivo.
- **Cash Alternatives**: Comprar gift cards y cambiarlas en línea por bitcoin.
- **Mining**: El método más privado para obtener bitcoins es la minería, especialmente cuando se hace en solitario, porque los pools de minería pueden conocer la dirección IP del minero. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teóricamente, robar bitcoin podría ser otro método para adquirirlo de forma anónima, aunque es ilegal y no recomendable.

## Mixing Services

Usando un servicio de mixing, un usuario puede **send bitcoins** y recibir **different bitcoins in return**, lo que dificulta rastrear al propietario original. Aun así, esto requiere confiar en que el servicio no guarde logs y que realmente devuelva los bitcoins. Opciones alternativas de mixing incluyen casinos de Bitcoin.

## CoinJoin

**CoinJoin** combina múltiples transacciones de diferentes usuarios en una sola, complicando el proceso para cualquiera que intente emparejar entradas con salidas. A pesar de su eficacia, las transacciones con tamaños únicos de entrada y salida todavía pueden ser rastreadas potencialmente.

Ejemplos de transacciones que pueden haber usado CoinJoin incluyen `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para más información, visita [CoinJoin](https://coinjoin.io/en). Para un servicio similar en Ethereum, consulta [Tornado Cash](https://tornado.cash), que anonimiza transacciones con fondos de mineros.

## PayJoin

Una variante de CoinJoin, **PayJoin** (o P2EP), disfraza la transacción entre dos partes (por ejemplo, un cliente y un comerciante) como una transacción normal, sin las salidas iguales distintivas características de CoinJoin. Esto la hace extremadamente difícil de detectar y podría invalidar la common-input-ownership heuristic usada por entidades de vigilancia de transacciones.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transacciones como las anteriores podrían ser PayJoin, mejorando la privacidad mientras permanecen indistinguibles de las transacciones estándar de bitcoin.

**La utilización de PayJoin podría alterar significativamente los métodos tradicionales de vigilancia**, convirtiéndola en un avance prometedor en la búsqueda de privacidad transaccional.

# Mejores prácticas para la privacidad en criptomonedas

## **Wallet Synchronization Techniques**

Para mantener la privacidad y la seguridad, sincronizar las wallets con la blockchain es crucial. Destacan dos métodos:

- **Full node**: Al descargar la blockchain completa, un full node garantiza la máxima privacidad. Todas las transacciones realizadas se almacenan localmente, haciendo imposible que los adversarios identifiquen qué transacciones o direcciones le interesan al usuario.
- **Client-side block filtering**: Este método implica crear filtros para cada bloque en la blockchain, permitiendo a las wallets identificar transacciones relevantes sin exponer intereses específicos a los observadores de la red. Las lightweight wallets descargan estos filtros, y solo obtienen los bloques completos cuando hay una coincidencia con las direcciones del usuario.

## **Uso de Tor para el anonimato**

Dado que Bitcoin funciona en una red peer-to-peer, se recomienda usar Tor para ocultar tu dirección IP, mejorando la privacidad al interactuar con la red.

## **Prevención de la reutilización de direcciones**

Para proteger la privacidad, es vital usar una nueva dirección para cada transacción. Reutilizar direcciones puede comprometer la privacidad al vincular transacciones con la misma entidad. Las wallets modernas desaconsejan la reutilización de direcciones mediante su diseño.

## **Estrategias para la privacidad en transacciones**

- **Multiple transactions**: Dividir un pago en varias transacciones puede ocultar el monto, frustrando ataques contra la privacidad.
- **Change avoidance**: Optar por transacciones que no requieran change outputs mejora la privacidad al romper los métodos de detección de change.
- **Multiple change outputs**: Si evitar change no es factible, generar múltiples change outputs puede aún mejorar la privacidad.

# **Monero: Un faro de anonimato**

Monero aborda la necesidad de anonimato absoluto en las transacciones digitales, marcando un estándar alto para la privacidad.

# **Ethereum: Gas y transacciones**

## **Comprendiendo Gas**

Gas mide el esfuerzo computacional necesario para ejecutar operaciones en Ethereum, valorado en **gwei**. Por ejemplo, una transacción que cuesta 2,310,000 gwei (o 0.00231 ETH) implica un gas limit y una base fee, con una propina para incentivar a los miners. Los usuarios pueden establecer un max fee para asegurarse de no pagar de más, con el excedente reembolsado.

## **Ejecución de transacciones**

Las transacciones en Ethereum involucran un sender y un recipient, que pueden ser direcciones de usuario o de smart contracts. Requieren una fee y deben ser minadas. La información esencial en una transacción incluye el recipient, la firma del sender, el valor, datos opcionales, gas limit y fees. Notablemente, la dirección del sender se deduce de la firma, eliminando la necesidad de incluirla en los datos de la transacción.

Estas prácticas y mecanismos son fundamentales para cualquiera que quiera interactuar con criptomonedas priorizando la privacidad y la seguridad.

## Value-Centric Web3 Red Teaming

- Inventariar los componentes que contienen valor (signers, oracles, bridges, automation) para entender quién puede mover fondos y cómo.
- Mapear cada componente a las tácticas MITRE AADAPT relevantes para exponer rutas de escalada de privilegios.
- Ensayar cadenas de ataque flash-loan/oracle/credential/cross-chain para validar el impacto y documentar precondiciones explotables.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- La manipulación de la supply-chain de los wallet UIs puede mutar payloads EIP-712 justo antes de la firma, recolectando firmas válidas para delegatecall-based proxy takeovers (p. ej., overwrite de slot-0 del Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Smart Contract Security

- Mutation testing para encontrar puntos ciegos en los test suites:

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

Si estás investigando explotación práctica de DEXes y AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), revisa:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados multi-asset que cachean virtual balances y pueden ser envenenados cuando `supply == 0`, estudia:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
