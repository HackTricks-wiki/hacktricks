{{#include ../banners/hacktricks-training.md}}

## Conceptos Básicos

- **Smart Contracts** se definen como programas que se ejecutan en una blockchain cuando se cumplen ciertas condiciones, automatizando la ejecución de acuerdos sin intermediarios.
- **Decentralized Applications (dApps)** se basan en smart contracts, presentando una interfaz amigable para el usuario y un back-end transparente y auditable.
- **Tokens & Coins** diferencian donde las coins sirven como dinero digital, mientras que los tokens representan valor o propiedad en contextos específicos.
- **Utility Tokens** otorgan acceso a servicios, y **Security Tokens** significan propiedad de activos.
- **DeFi** significa Finanzas Descentralizadas, ofreciendo servicios financieros sin autoridades centrales.
- **DEX** y **DAOs** se refieren a Plataformas de Intercambio Descentralizadas y Organizaciones Autónomas Descentralizadas, respectivamente.

## Mecanismos de Consenso

Los mecanismos de consenso aseguran validaciones de transacciones seguras y acordadas en la blockchain:

- **Proof of Work (PoW)** se basa en el poder computacional para la verificación de transacciones.
- **Proof of Stake (PoS)** exige que los validadores mantengan una cierta cantidad de tokens, reduciendo el consumo de energía en comparación con PoW.

## Esenciales de Bitcoin

### Transacciones

Las transacciones de Bitcoin implican la transferencia de fondos entre direcciones. Las transacciones se validan a través de firmas digitales, asegurando que solo el propietario de la clave privada pueda iniciar transferencias.

#### Componentes Clave:

- **Multisignature Transactions** requieren múltiples firmas para autorizar una transacción.
- Las transacciones constan de **inputs** (fuente de fondos), **outputs** (destino), **fees** (pagados a los mineros) y **scripts** (reglas de transacción).

### Lightning Network

Aumenta la escalabilidad de Bitcoin permitiendo múltiples transacciones dentro de un canal, transmitiendo solo el estado final a la blockchain.

## Preocupaciones de Privacidad de Bitcoin

Los ataques a la privacidad, como **Common Input Ownership** y **UTXO Change Address Detection**, explotan patrones de transacción. Estrategias como **Mixers** y **CoinJoin** mejoran el anonimato al oscurecer los vínculos de transacción entre usuarios.

## Adquiriendo Bitcoins de Manera Anónima

Los métodos incluyen intercambios en efectivo, minería y el uso de mixers. **CoinJoin** mezcla múltiples transacciones para complicar la trazabilidad, mientras que **PayJoin** disfraza CoinJoins como transacciones regulares para una mayor privacidad.

# Ataques a la Privacidad de Bitcoin

# Resumen de Ataques a la Privacidad de Bitcoin

En el mundo de Bitcoin, la privacidad de las transacciones y el anonimato de los usuarios son a menudo temas de preocupación. Aquí hay una visión simplificada de varios métodos comunes a través de los cuales los atacantes pueden comprometer la privacidad de Bitcoin.

## **Suposición de Propiedad de Entrada Común**

Es generalmente raro que las entradas de diferentes usuarios se combinen en una sola transacción debido a la complejidad involucrada. Por lo tanto, **se asume a menudo que dos direcciones de entrada en la misma transacción pertenecen al mismo propietario**.

## **Detección de Dirección de Cambio UTXO**

Un UTXO, o **Unspent Transaction Output**, debe ser completamente gastado en una transacción. Si solo una parte se envía a otra dirección, el resto va a una nueva dirección de cambio. Los observadores pueden asumir que esta nueva dirección pertenece al remitente, comprometiendo la privacidad.

### Ejemplo

Para mitigar esto, los servicios de mezcla o el uso de múltiples direcciones pueden ayudar a oscurecer la propiedad.

## **Exposición en Redes Sociales y Foros**

Los usuarios a veces comparten sus direcciones de Bitcoin en línea, lo que hace **fácil vincular la dirección a su propietario**.

## **Análisis de Gráficos de Transacciones**

Las transacciones pueden visualizarse como gráficos, revelando conexiones potenciales entre usuarios basadas en el flujo de fondos.

## **Heurística de Entrada Innecesaria (Heurística de Cambio Óptimo)**

Esta heurística se basa en analizar transacciones con múltiples entradas y salidas para adivinar cuál salida es el cambio que regresa al remitente.

### Ejemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Si agregar más entradas hace que el cambio de salida sea mayor que cualquier entrada individual, puede confundir la heurística.

## **Reutilización Forzada de Direcciones**

Los atacantes pueden enviar pequeñas cantidades a direcciones previamente utilizadas, con la esperanza de que el destinatario las combine con otras entradas en transacciones futuras, vinculando así las direcciones entre sí.

### Comportamiento Correcto de la Billetera

Las billeteras deben evitar usar monedas recibidas en direcciones ya utilizadas y vacías para prevenir esta fuga de privacidad.

## **Otras Técnicas de Análisis de Blockchain**

- **Montos de Pago Exactos:** Las transacciones sin cambio son probablemente entre dos direcciones propiedad del mismo usuario.
- **Números Redondos:** Un número redondo en una transacción sugiere que es un pago, siendo la salida no redonda probablemente el cambio.
- **Huella Digital de Billetera:** Diferentes billeteras tienen patrones únicos de creación de transacciones, lo que permite a los analistas identificar el software utilizado y potencialmente la dirección de cambio.
- **Correlaciones de Monto y Tiempo:** Divulgar los tiempos o montos de las transacciones puede hacer que las transacciones sean rastreables.

## **Análisis de Tráfico**

Al monitorear el tráfico de la red, los atacantes pueden potencialmente vincular transacciones o bloques a direcciones IP, comprometiendo la privacidad del usuario. Esto es especialmente cierto si una entidad opera muchos nodos de Bitcoin, mejorando su capacidad para monitorear transacciones.

## Más

Para una lista completa de ataques a la privacidad y defensas, visita [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transacciones Anónimas de Bitcoin

## Formas de Obtener Bitcoins Anónimamente

- **Transacciones en Efectivo**: Adquirir bitcoin a través de efectivo.
- **Alternativas en Efectivo**: Comprar tarjetas de regalo y cambiarlas en línea por bitcoin.
- **Minería**: El método más privado para ganar bitcoins es a través de la minería, especialmente cuando se hace solo, ya que los grupos de minería pueden conocer la dirección IP del minero. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Robo**: Teóricamente, robar bitcoin podría ser otro método para adquirirlo de forma anónima, aunque es ilegal y no se recomienda.

## Servicios de Mezcla

Al usar un servicio de mezcla, un usuario puede **enviar bitcoins** y recibir **diferentes bitcoins a cambio**, lo que dificulta rastrear al propietario original. Sin embargo, esto requiere confianza en el servicio para no mantener registros y devolver realmente los bitcoins. Las opciones de mezcla alternativas incluyen casinos de Bitcoin.

## CoinJoin

**CoinJoin** combina múltiples transacciones de diferentes usuarios en una, complicando el proceso para cualquiera que intente emparejar entradas con salidas. A pesar de su efectividad, las transacciones con tamaños de entrada y salida únicos aún pueden ser potencialmente rastreadas.

Las transacciones de ejemplo que pueden haber utilizado CoinJoin incluyen `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para más información, visita [CoinJoin](https://coinjoin.io/en). Para un servicio similar en Ethereum, consulta [Tornado Cash](https://tornado.cash), que anonimiza transacciones con fondos de mineros.

## PayJoin

Una variante de CoinJoin, **PayJoin** (o P2EP), disfraza la transacción entre dos partes (por ejemplo, un cliente y un comerciante) como una transacción regular, sin las características distintivas de salidas iguales propias de CoinJoin. Esto hace que sea extremadamente difícil de detectar y podría invalidar la heurística de propiedad de entrada común utilizada por las entidades de vigilancia de transacciones.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transacciones como la anterior podrían ser PayJoin, mejorando la privacidad mientras permanecen indistinguibles de las transacciones estándar de bitcoin.

**La utilización de PayJoin podría interrumpir significativamente los métodos de vigilancia tradicionales**, lo que lo convierte en un desarrollo prometedor en la búsqueda de la privacidad transaccional.

# Mejores Prácticas para la Privacidad en Criptomonedas

## **Técnicas de Sincronización de Monederos**

Para mantener la privacidad y la seguridad, es crucial sincronizar los monederos con la blockchain. Dos métodos destacan:

- **Nodo completo**: Al descargar toda la blockchain, un nodo completo asegura la máxima privacidad. Todas las transacciones realizadas se almacenan localmente, lo que hace imposible que los adversarios identifiquen qué transacciones o direcciones le interesan al usuario.
- **Filtrado de bloques del lado del cliente**: Este método implica crear filtros para cada bloque en la blockchain, permitiendo que los monederos identifiquen transacciones relevantes sin exponer intereses específicos a los observadores de la red. Los monederos ligeros descargan estos filtros, obteniendo bloques completos solo cuando se encuentra una coincidencia con las direcciones del usuario.

## **Utilizando Tor para la Anonimidad**

Dado que Bitcoin opera en una red peer-to-peer, se recomienda usar Tor para enmascarar tu dirección IP, mejorando la privacidad al interactuar con la red.

## **Prevención de la Reutilización de Direcciones**

Para salvaguardar la privacidad, es vital usar una nueva dirección para cada transacción. Reutilizar direcciones puede comprometer la privacidad al vincular transacciones a la misma entidad. Los monederos modernos desincentivan la reutilización de direcciones a través de su diseño.

## **Estrategias para la Privacidad de Transacciones**

- **Múltiples transacciones**: Dividir un pago en varias transacciones puede oscurecer el monto de la transacción, frustrando ataques a la privacidad.
- **Evitación de cambios**: Optar por transacciones que no requieran salidas de cambio mejora la privacidad al interrumpir los métodos de detección de cambios.
- **Múltiples salidas de cambio**: Si evitar el cambio no es factible, generar múltiples salidas de cambio aún puede mejorar la privacidad.

# **Monero: Un Faro de Anonimato**

Monero aborda la necesidad de anonimato absoluto en las transacciones digitales, estableciendo un alto estándar para la privacidad.

# **Ethereum: Gas y Transacciones**

## **Entendiendo el Gas**

El gas mide el esfuerzo computacional necesario para ejecutar operaciones en Ethereum, tasado en **gwei**. Por ejemplo, una transacción que cuesta 2,310,000 gwei (o 0.00231 ETH) implica un límite de gas y una tarifa base, con una propina para incentivar a los mineros. Los usuarios pueden establecer una tarifa máxima para asegurarse de no pagar de más, con el exceso reembolsado.

## **Ejecutando Transacciones**

Las transacciones en Ethereum involucran un remitente y un destinatario, que pueden ser direcciones de usuario o de contrato inteligente. Requieren una tarifa y deben ser minadas. La información esencial en una transacción incluye el destinatario, la firma del remitente, el valor, datos opcionales, límite de gas y tarifas. Notablemente, la dirección del remitente se deduce de la firma, eliminando la necesidad de incluirla en los datos de la transacción.

Estas prácticas y mecanismos son fundamentales para cualquiera que busque participar en criptomonedas mientras prioriza la privacidad y la seguridad.

## Referencias

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

{{#include ../banners/hacktricks-training.md}}
