<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Terminología básica

* **Contrato inteligente**: Los contratos inteligentes son simplemente **programas almacenados en una cadena de bloques que se ejecutan cuando se cumplen condiciones predeterminadas**. Por lo general, se utilizan para automatizar la **ejecución** de un **acuerdo** para que todos los participantes puedan estar inmediatamente seguros del resultado, sin la participación de intermediarios o pérdida de tiempo. (De [aquí](https://www.ibm.com/topics/smart-contracts)).
  * Básicamente, un contrato inteligente es un **fragmento de código** que se ejecutará cuando las personas accedan y acepten el contrato. Los contratos inteligentes **se ejecutan en cadenas de bloques** (por lo que los resultados se almacenan de forma inmutable) y pueden ser leídos por las personas antes de aceptarlos.
* **dApps**: Las **aplicaciones descentralizadas** se implementan sobre **contratos inteligentes**. Por lo general, tienen una interfaz de usuario donde el usuario puede interactuar con la aplicación, el **backend** es público (por lo que puede ser auditado) y se implementa como un **contrato inteligente**. A veces se necesita el uso de una base de datos, la cadena de bloques Ethereum asigna cierto almacenamiento a cada cuenta.
* **Tokens y monedas**: Una **moneda** es una criptomoneda que actúa como **dinero digital** y un **token** es algo que **representa** algún **valor** pero no es una moneda.
  * **Tokens de utilidad**: Estos tokens permiten al usuario **acceder a cierto servicio más tarde** (es algo que tiene algún valor en un entorno específico).
  * **Tokens de seguridad**: Estos representan la **propiedad** o algún activo.
* **DeFi**: **Finanzas descentralizadas**.
* **DEX: Plataformas de intercambio descentralizadas**.
* **DAOs**: **Organizaciones autónomas descentralizadas**.

# Mecanismos de consenso

Para que una transacción de cadena de bloques sea reconocida, debe ser **añadida** a la **cadena de bloques**. Los validadores (mineros) llevan a cabo esta adición; en la mayoría de los protocolos, **reciben una recompensa** por hacerlo. Para que la cadena de bloques siga siendo segura, debe tener un mecanismo para **evitar que un usuario o grupo malintencionado tome el control de la mayoría de la validación**.

La prueba de trabajo, otro mecanismo de consenso comúnmente utilizado, utiliza una validación de destreza computacional para verificar transacciones, requiriendo que un posible atacante adquiera una gran fracción del poder computacional de la red de validadores.

## Prueba de trabajo (PoW)

Esto utiliza una **validación de destreza computacional** para verificar transacciones, requiriendo que un posible atacante adquiera una gran fracción del poder computacional de la red de validadores.\
Los **mineros** seleccionarán varias transacciones y luego comenzarán a **calcular la prueba de trabajo**. El **minero con los mayores recursos de cálculo** es más probable que **termine antes** la prueba de trabajo y obtenga las tarifas de todas las transacciones.

## Prueba de participación (PoS)

PoS logra esto al **requerir que los validadores tengan una cierta cantidad de tokens de cadena de bloques**, requiriendo que **los posibles atacantes adquieran una gran fracción de los tokens** en la cadena de bloques para montar un ataque.\
En este tipo de consenso, cuanto más tokens tenga un minero, es más probable que se le pida al minero que cree el siguiente bloque.\
En comparación con PoW, esto reduce en gran medida el consumo de energía que los mineros están gastando.

# Bitcoin

## Transacciones

Una **transacción** simple es un **movimiento de dinero** desde una dirección a otra.\
Una **dirección** en Bitcoin es el hash de la **clave pública**, por lo tanto, alguien para realizar una transacción desde una dirección necesita conocer la clave privada asociada a esa clave pública (la dirección).\
Entonces, cuando se realiza una **transacción**, se **firma** con la clave privada de la dirección para mostrar que la transacción es **legítima**.

La primera parte de producir una firma digital en Bitcoin se puede representar matemáticamente de la siguiente manera:\
_**Sig**_ = _**Fsig**_(_**Fhash**_(_**m**_),_**dA**_)

Donde:

* \_d\_A es la **clave privada** de firma
* _m_ es la **transacción**
## Detección de direcciones de cambio UTXO

**UTXO** significa **Salidas de transacciones no gastadas** (Unspent Transaction Outputs). En una transacción que utiliza la salida de una transacción anterior como entrada, **toda la salida debe ser gastada** (para evitar ataques de doble gasto). Por lo tanto, si la intención era **enviar** solo **parte** del dinero de esa salida a una dirección y **mantener** la **otra** **parte**, aparecerán **2 salidas diferentes**: la **prevista** y una **nueva dirección de cambio aleatoria** donde se guardará el resto del dinero.

Entonces, un observador puede suponer que **la nueva dirección de cambio generada pertenece al propietario del UTXO**.

## Redes sociales y foros

Algunas personas proporcionan datos sobre sus direcciones de bitcoin en diferentes sitios web en Internet. **Esto hace que sea bastante fácil identificar al propietario de una dirección**.

## Gráficos de transacciones

Al representar las transacciones en gráficos, es posible saber con cierta probabilidad a dónde fue el dinero de una cuenta. Por lo tanto, es posible saber algo sobre los **usuarios** que están **relacionados** en la cadena de bloques.

## **Heurística de entrada innecesaria**

También llamada "heurística de cambio óptimo". Considere esta transacción de bitcoin. Tiene dos entradas por un valor de 2 BTC y 3 BTC y dos salidas por un valor de 4 BTC y 1 BTC.
```
2 btc --> 4 btc
3 btc     1 btc
```
Suponiendo que una de las salidas es el cambio y la otra salida es el pago. Hay dos interpretaciones: la salida de pago es o la salida de 4 BTC o la salida de 1 BTC. Pero si la salida de 1 BTC es la cantidad de pago, entonces la entrada de 3 BTC es innecesaria, ya que la billetera podría haber gastado solo la entrada de 2 BTC y pagado tarifas de minero más bajas por hacerlo. Esto indica que la salida real de pago es de 4 BTC y que 1 BTC es la salida de cambio.

Este es un problema para las transacciones que tienen más de una entrada. Una forma de solucionar esta fuga es agregar más entradas hasta que la salida de cambio sea mayor que cualquier entrada, por ejemplo:
```
2 btc --> 4 btc
3 btc     6 btc
5 btc
```
## Reutilización forzada de direcciones

La **reutilización forzada de direcciones** o **reutilización incentivada de direcciones** es cuando un adversario paga una cantidad (a menudo pequeña) de bitcoin a direcciones que ya han sido utilizadas en la cadena de bloques. El adversario espera que los usuarios o su software de billetera **utilicen los pagos como entradas a una transacción más grande que revelará otras direcciones a través de la heurística de propiedad común de entrada**. Estos pagos pueden entenderse como una forma de obligar al propietario de la dirección a una reutilización de direcciones no intencional.

A veces, este ataque se llama incorrectamente **ataque de polvo**.

El comportamiento correcto de las billeteras es no gastar monedas que hayan caído en direcciones vacías ya utilizadas.

## Otras análisis de Blockchain

* **Importes exactos de pago**: Para evitar transacciones con cambio, el pago debe ser igual al UTXO (lo que es muy inesperado). Por lo tanto, una **transacción sin dirección de cambio probablemente sea una transferencia entre 2 direcciones del mismo usuario**.
* **Números redondos**: En una transacción, si una de las salidas es un "**número redondo**", es muy probable que se trate de un **pago a un humano que puso ese precio de "número redondo"**, por lo que la otra parte debe ser el sobrante.
* **Identificación de billetera**: Un analista cuidadoso a veces puede deducir qué software creó una determinada transacción, porque los **diferentes softwares de billetera no siempre crean transacciones de la misma manera**. La identificación de billetera se puede utilizar para detectar salidas de cambio porque una salida de cambio es la que se gasta con la misma identificación de billetera.
* **Correlaciones de cantidad y tiempo**: Si la persona que realizó la transacción **revela** el **tiempo** y/o **cantidad** de la transacción, puede ser fácilmente **descubrible**.

## Análisis de tráfico

Algunas organizaciones que **interceptan su tráfico** pueden ver que está comunicándose en la red de Bitcoin.\
Si el adversario ve una transacción o bloque **saliendo de su nodo que no entró previamente**, entonces puede saber con casi certeza que **la transacción fue realizada por usted o el bloque fue minado por usted**. Como las conexiones a Internet están involucradas, el adversario podrá **vincular la dirección IP con la información de Bitcoin descubierta**.

Un atacante que no puede interceptar todo el tráfico de Internet pero que tiene **muchos nodos de Bitcoin** para estar **más cerca** de las fuentes podría ser capaz de conocer las direcciones IP que anuncian transacciones o bloques.\
Además, algunas billeteras retransmiten periódicamente sus transacciones no confirmadas para que tengan más probabilidades de propagarse ampliamente a través de la red y ser minadas.

## Otros ataques para encontrar información sobre el propietario de las direcciones

Para obtener más información sobre los ataques, lea [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy)

# Bitcoins anónimos

## Obtención de Bitcoins de forma anónima

* **Intercambios en efectivo:** Compre bitcoins en efectivo.
* **Sustituto de efectivo:** Compre tarjetas de regalo o similares e intercámbielas por bitcoins en línea.
* **Minería:** La minería es la forma más anónima de obtener bitcoins. Esto se aplica a la minería en solitario ya que los [pools de minería](https://en.bitcoin.it/wiki/Pooled\_mining) generalmente conocen la dirección IP del minero.
* **Robo:** En teoría, otra forma de obtener bitcoins anónimos es robándolos.

## Mezcladores

Un usuario **enviaría bitcoins a un servicio de mezcla** y el servicio **enviaría diferentes bitcoins de vuelta al usuario**, menos una tarifa. En teoría, un adversario que observe la cadena de bloques no podría **vincular** las transacciones entrantes y salientes.

Sin embargo, el usuario debe confiar en el servicio de mezcla para devolver los bitcoins y también para no estar guardando registros sobre las relaciones entre el dinero recibido y enviado.\
Algunos otros servicios también se pueden utilizar como mezcladores, como los casinos de Bitcoin donde se pueden enviar bitcoins y recuperarlos más tarde.

## CoinJoin

**CoinJoin** mezclará varias transacciones de diferentes usuarios en una sola para hacer más **difícil** para un observador encontrar **qué entrada está relacionada con qué salida**.\
Esto ofrece un nuevo nivel de privacidad, sin embargo, **algunas** **transacciones** donde algunos montos de entrada y salida están correlacionados o son muy diferentes del resto de las entradas y salidas **todavía pueden estar correlacionados** por el observador externo.

Ejemplos de IDs de transacciones de CoinJoin (probablemente) en la cadena de bloques de Bitcoin son `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

[**https://coinjoin.io/en**](https://coinjoin.io/en)\
**Similar a CoinJoin pero mejor y para Ethereum tienes** [**Tornado Cash**](https://tornado.cash) **(el dinero es entregado por los mineros, por lo que solo aparece en tu billetera).**

## PayJoin

El tipo de CoinJoin discutido en la sección anterior se puede identificar fácilmente como tal mediante la verificación de las múltiples salidas con el mismo valor.

PayJoin (también llamado pay-to-end-point o P2EP) es un tipo especial de CoinJoin entre dos partes donde una parte paga a la otra. La transacción entonces **no tiene las múltiples salidas distintivas** con el mismo valor, y por lo tanto no es visiblemente obvia como un CoinJoin de salida igual. Considere esta transacción:
```
2 btc --> 3 btc
5 btc     4 btc
```
Se podría interpretar como una simple transacción pagando a algún lugar con cambio sobrante (ignorando por ahora la cuestión de cuál es la salida de pago y cuál es el cambio). Otra forma de interpretar esta transacción es que los 2 BTC de entrada son propiedad de un comerciante y los 5 BTC son propiedad de su cliente, y que esta transacción implica que el cliente pague 1 BTC al comerciante. No hay forma de saber cuál de estas dos interpretaciones es correcta. El resultado es una transacción de coinjoin que rompe la heurística común de propiedad de entrada y mejora la privacidad, pero también es **indetectable e indistinguible de cualquier transacción de bitcoin regular**.

Si las transacciones PayJoin se usaran moderadamente, entonces harían que la **heurística común de propiedad de entrada sea completamente defectuosa en la práctica**. Como son indetectables, ni siquiera sabríamos si se están usando hoy en día. Como las empresas de vigilancia de transacciones dependen en su mayoría de esa heurística, a partir de 2019 hay una gran emoción en torno a la idea de PayJoin.

# Buenas prácticas de privacidad de Bitcoin

## Sincronización de billetera

Las billeteras de Bitcoin deben obtener información sobre su saldo e historial de alguna manera. A finales de 2018, las soluciones prácticas y privadas más existentes son usar una **billetera de nodo completo** (que es máximamente privada) y **filtrado de bloque del lado del cliente** (que es muy bueno).

* **Nodo completo:** Los nodos completos descargan toda la cadena de bloques que contiene todas las [transacciones](https://en.bitcoin.it/wiki/Transaction) en cadena que han ocurrido en Bitcoin. Por lo tanto, un adversario que observe la conexión a Internet del usuario no podrá aprender qué transacciones o direcciones le interesan al usuario.
* **Filtrado de bloque del lado del cliente:** El filtrado de bloque del lado del cliente funciona creando **filtros** que contienen todas las **direcciones** para cada transacción en un bloque. Los filtros pueden probar si un **elemento está en el conjunto**; los falsos positivos son posibles pero no los falsos negativos. Una billetera liviana **descargaría** todos los filtros para cada **bloque** en la **cadena de bloques** y verificaría las coincidencias con sus **propias** **direcciones**. Los bloques que contienen coincidencias se descargarían por completo de la red peer-to-peer, y esos bloques se usarían para obtener el historial y el saldo actual de la billetera.

## Tor

La red de Bitcoin utiliza una red peer-to-peer, lo que significa que otros pares pueden conocer su dirección IP. Por eso se recomienda **conectarse a través de Tor cada vez que se quiera interactuar con la red de Bitcoin**.

## Evitar la reutilización de direcciones

**Las direcciones que se usan más de una vez son muy perjudiciales para la privacidad porque vinculan más transacciones de la cadena de bloques con la prueba de que fueron creadas por la misma entidad**. La forma más privada y segura de usar Bitcoin es enviar una **nueva dirección a cada persona que le pague**. Después de que se hayan gastado las monedas recibidas, la dirección nunca debe usarse de nuevo. Además, se debe exigir una nueva dirección de Bitcoin al enviar Bitcoin. Todas las buenas billeteras de Bitcoin tienen una interfaz de usuario que desalienta la reutilización de direcciones.

## Múltiples transacciones

**Pagar** a alguien con **más de una transacción en cadena** puede reducir en gran medida el poder de los ataques de privacidad basados en la cantidad, como la correlación de la cantidad y los números redondos. Por ejemplo, si el usuario quiere pagar 5 BTC a alguien y no quiere que el valor de 5 BTC sea fácilmente buscado, entonces puede enviar dos transacciones por el valor de 2 BTC y 3 BTC que juntas suman 5 BTC.

## Evitar el cambio

La evitación del cambio es donde se eligen cuidadosamente las entradas y salidas de la transacción para no requerir una salida de cambio en absoluto. **No tener una salida de cambio es excelente para la privacidad**, ya que rompe las heurísticas de detección de cambio.

## Múltiples salidas de cambio

Si la evitación del cambio no es una opción, entonces **crear más de una salida de cambio puede mejorar la privacidad**. Esto también rompe las heurísticas de detección de cambio que generalmente asumen que solo hay una salida de cambio. Como este método utiliza más espacio de bloque de lo habitual, se prefiere la evitación del cambio.

# Monero

Cuando se desarrolló Monero, la gran necesidad de **anonimato completo** fue lo que se buscó resolver, y en gran medida, ha llenado ese vacío.

# Ethereum

## Gas

Gas se refiere a la unidad que mide la **cantidad** de **esfuerzo computacional** requerido para ejecutar operaciones específicas en la red Ethereum. Gas se refiere a la **tarifa** requerida para realizar una **transacción** con éxito en Ethereum.

Los precios del gas se indican en **gwei**, que es una denominación de ETH: cada gwei es igual a **0,000000001 ETH** (10-9 ETH). Por ejemplo, en lugar de decir que su gas cuesta 0,000000001 ether, puede decir que su gas cuesta 1 gwei. La palabra 'gwei' en sí misma significa 'giga-wei', y es igual a **1.000.000.000 wei**. Wei en sí es la **unidad más pequeña de ETH**.

Para calcular el gas que va a costar una transacción, lea este ejemplo:

Supongamos que Jordan tiene que pagarle a Taylor 1 ETH. En la transacción, el límite de gas es de 21.000 unidades y la tarifa base es de 100 gwei. Jordan incluye una propina de 10 gwei.

Usando la fórmula anterior, podemos calcular esto como `21.000 * (100 + 10) = 2.310.000 gwei` o 0,00231 ETH.

Cuando Jordan envía el dinero, se deducirán 1,00231 ETH de la cuenta de Jordan. Taylor recibirá 1,0000 ETH. El minero recibirá la propina de 0,00021 ETH. La tarifa base de 0,0021 ETH se quema.

Además, Jordan también puede establecer una tarifa máxima (`maxFeePerGas`) para la transacción. La diferencia entre la tarifa máxima y la tarifa real se reembolsa a Jordan, es decir, `reembolso = tarifa máxima - (tarifa base + tarifa de prioridad)`. Jordan puede establecer una cantidad máxima a pagar por la transacción para ejecutarla y no preocuparse por pagar en exceso "más allá" de la tarifa base cuando se ejecute la transacción.

Como la tarifa base se calcula
