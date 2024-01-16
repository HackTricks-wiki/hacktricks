<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Terminología Básica

* **Smart contract**: Los smart contracts son simplemente **programas almacenados en una blockchain que se ejecutan cuando se cumplen condiciones preestablecidas**. Típicamente se usan para automatizar la **ejecución** de un **acuerdo** de modo que todos los participantes puedan estar inmediatamente seguros del resultado, sin la intervención de intermediarios ni pérdida de tiempo. (De [aquí](https://www.ibm.com/topics/smart-contracts)).
* Básicamente, un smart contract es un **fragmento de código** que se ejecutará cuando las personas accedan y acepten el contrato. Los smart contracts **funcionan en blockchains** (por lo que los resultados se almacenan de forma inmutable) y pueden ser leídos por las personas antes de aceptarlos.
* **dApps**: Las **aplicaciones descentralizadas** se implementan sobre **smart contracts**. Usualmente tienen un front-end donde el usuario puede interactuar con la app, el **back-end** es público (por lo que puede ser auditado) y está implementado como un **smart contract**. A veces se necesita el uso de una base de datos, la blockchain de Ethereum asigna cierto almacenamiento a cada cuenta.
* **Tokens & coins**: Una **coin** es una criptomoneda que actúa como **dinero digital** y un **token** es algo que **representa** algún **valor** pero no es una coin.
* **Utility Tokens**: Estos tokens permiten al usuario **acceder a cierto servicio más adelante** (es algo que tiene valor en un entorno específico).
* **Security Tokens**: Estos representan la **propiedad** de algún activo.
* **DeFi**: **Finanzas Descentralizadas**.
* **DEX: Plataformas de Intercambio Descentralizadas**.
* **DAOs**: **Organizaciones Autónomas Descentralizadas**.

# Mecanismos de Consenso

Para que una transacción en blockchain sea reconocida, debe ser **añadida** a la **blockchain**. Los validadores (mineros) llevan a cabo este añadido; en la mayoría de los protocolos, **reciben una recompensa** por hacerlo. Para que la blockchain permanezca segura, debe tener un mecanismo para **prevenir que un usuario malicioso o grupo tome control de la mayoría de la validación**.

Proof of work, otro mecanismo de consenso comúnmente utilizado, usa una validación de proeza computacional para verificar transacciones, requiriendo que un atacante potencial adquiera una gran fracción del poder computacional de la red de validadores.

## Proof Of Work (PoW)

Esto utiliza una **validación de proeza computacional** para verificar transacciones, requiriendo que un atacante potencial adquiera una gran fracción del poder computacional de la red de validadores.\
Los **mineros** seleccionarán varias transacciones y luego comenzarán a **computar el Proof Of Work**. El **minero con mayores recursos computacionales** probablemente **terminará antes** el Proof of Work y obtendrá las tarifas de todas las transacciones.

## Proof Of Stake (PoS)

PoS logra esto al **requerir que los validadores posean cierta cantidad de tokens de la blockchain**, requiriendo que **los atacantes potenciales adquieran una gran fracción de los tokens** en la blockchain para lanzar un ataque.\
En este tipo de consenso, cuanto más tokens tenga un minero, más probable será que se le pida crear el siguiente bloque.\
Comparado con PoW, esto reduce significativamente el **consumo de energía** que los mineros están gastando.

# Bitcoin

## Transacciones

Una **transacción** simple es un **movimiento de dinero** de una dirección a otra.\
Una **dirección** en bitcoin es el hash de la **clave pública**, por lo tanto, alguien para realizar una transacción desde una dirección necesita conocer la clave privada asociada a esa clave pública (la dirección).\
Entonces, cuando se realiza una **transacción**, se **firma** con la clave privada de la dirección para demostrar que la transacción es **legítima**.

La primera parte de la producción de una firma digital en Bitcoin puede representarse matemáticamente de la siguiente manera:\
_**Sig**_ = _**Fsig**_(_**Fhash**_(_**m**_),_**dA**_)

Donde:

* \_d\_A es la **clave privada** de firma
* _m_ es la **transacción**
* Fhash es la función de hashing
* Fsig es el algoritmo de firma
* Sig es la firma resultante

La función de firma (Fsig) produce una firma (Sig) que consta de dos valores: R y S:

* Sig = (R, S)

Una vez que se han calculado R y S, se serializan en un flujo de bytes que se codifica utilizando un esquema de codificación estándar internacional conocido como Distinguished Encoding Rules (o DER). Para verificar que la firma es válida, se utiliza un algoritmo de verificación de firma. La verificación de una firma digital requiere lo siguiente:

* Firma (R y S)
* Hash de la transacción
* La clave pública que corresponde a la clave privada que se utilizó para crear la firma

La verificación de una firma efectivamente significa que solo el propietario de la clave privada (que generó la clave pública) podría haber producido la firma en la transacción. El algoritmo de verificación de firma devolverá 'TRUE' si la firma es válida.

### Transacciones Multifirma

Una **dirección** multifirma es una dirección que está asociada con más de una clave privada ECDSA. El tipo más simple es una dirección m-de-n - está asociada con n claves privadas, y enviar bitcoins desde esta dirección requiere firmas de al menos m claves. Una **transacción** multifirma es una que envía fondos desde una dirección multifirma.

### Campos de las Transacciones

Cada transacción de bitcoin tiene varios campos:

* **Entradas**: La cantidad y dirección **desde** donde se **transfieren** los **bitcoins**
* **Salidas**: La dirección y cantidades que se **transfieren** a **cada** **salida**
* **Comisión:** La cantidad de **dinero** que se **paga** al **minero** de la transacción
* **Script\_sig**: Firma del script de la transacción
* **Script\_type**: Tipo de transacción

Hay **2 tipos principales** de transacciones:

* **P2PKH: "Pay To Public Key Hash"**: Así es como se realizan las transacciones. Se requiere que el **emisor** proporcione una **firma válida** (de la clave privada) y **clave pública**. El script de salida de la transacción usará la firma y la clave pública y mediante algunas funciones criptográficas comprobará **si coincide** con el hash de la clave pública, si es así, entonces los **fondos** serán **gastables**. Este método oculta tu clave pública en forma de hash para mayor seguridad.
* **P2SH: "Pay To Script Hash":** Las salidas de una transacción son solo **scripts** (esto significa que la persona que quiere este dinero envía un script) que, si se **ejecutan con parámetros específicos, resultarán en un booleano de `true` o `false`**. Si un minero ejecuta el script de salida con los parámetros suministrados y resulta en `true`, el **dinero será enviado a la salida deseada**. `P2SH` se utiliza para **billeteras multifirma** haciendo que los scripts de salida **lógica que verifica múltiples firmas antes de aceptar la transacción**. `P2SH` también puede usarse para permitir que cualquiera, o nadie, gaste los fondos. Si el script de salida de una transacción P2SH es solo `1` para verdadero, entonces intentar gastar la salida sin suministrar parámetros simplemente resultará en `1` haciendo que el dinero sea gastable por cualquiera que lo intente. Esto también se aplica a scripts que devuelven `0`, haciendo que la salida sea gastable por nadie.

## Lightning Network

Este protocolo ayuda a **realizar varias transacciones en un canal** y **solo enviar** el **estado final** a la blockchain para guardarlo.\
Esto **mejora** la **velocidad** de la blockchain de bitcoin (solo permite 7 pagos por segundo) y permite crear **transacciones más difíciles de rastrear** ya que el canal se crea a través de nodos de la blockchain de bitcoin:

![](<../../.gitbook/assets/image (611).png>)

El uso normal de la Lightning Network consiste en **abrir un canal de pago** comprometiendo una transacción de financiamiento a la blockchain base relevante (capa 1), seguido de realizar **cualquier número** de transacciones de Lightning Network que actualicen la distribución tentativa de los fondos del canal **sin transmitirlos a la blockchain**, opcionalmente seguido por cerrar el canal de pago **transmitiendo** la **versión final** de la transacción de liquidación para distribuir los fondos del canal.

Nota que cualquiera de los dos miembros del canal puede detener y enviar el estado final del canal a la blockchain en cualquier momento.

# Ataques a la Privacidad de Bitcoin

## Entrada Común

Teóricamente las entradas de una transacción pueden pertenecer a diferentes usuarios, pero en realidad eso es inusual ya que requiere pasos adicionales. Por lo tanto, muy a menudo se puede asumir que **2 direcciones de entrada en la misma transacción pertenecen al mismo propietario**.

## Detección de Dirección de Cambio UTXO

**UTXO** significa **Salidas de Transacción No Gastadas** (UTXOs). En una transacción que utiliza la salida de una transacción anterior como entrada, se **debe gastar toda la salida** (para evitar ataques de doble gasto). Por lo tanto, si la intención era **enviar** solo **parte** del dinero de esa salida a una dirección y **conservar** la **otra parte**, aparecerán **2 salidas diferentes**: la **destinada** y una **nueva dirección de cambio aleatoria** donde se guardará el resto del dinero.

Entonces, un observador puede asumir que **la nueva dirección de cambio generada pertenece al propietario del UTXO**.

## Redes Sociales & Foros

Algunas personas dan datos sobre sus direcciones de bitcoin en diferentes sitios web en Internet. **Esto hace bastante fácil identificar al propietario de una dirección**.

## Gráficos de Transacciones

Al representar las transacciones en gráficos, **es posible saber con cierta probabilidad hacia dónde fue el dinero de una cuenta**. Por lo tanto, es posible saber algo sobre **usuarios** que están **relacionados** en la blockchain.

## **Heurística de entrada innecesaria**

También llamada la "heurística de cambio óptimo". Considere esta transacción de bitcoin. Tiene dos entradas por valor de 2 BTC y 3 BTC y dos salidas por valor de 4 BTC y 1 BTC.
```
2 btc --> 4 btc
3 btc     1 btc
```
Asumiendo que una de las salidas es el cambio y la otra salida es el pago. Hay dos interpretaciones: la salida del pago es o bien la salida de 4 BTC o la salida de 1 BTC. Pero si la salida de 1 BTC es la cantidad del pago, entonces la entrada de 3 BTC es innecesaria, ya que la billetera podría haber gastado solo la entrada de 2 BTC y haber pagado comisiones de mineros más bajas por hacerlo. Esto indica que la salida de pago real es de 4 BTC y que 1 BTC es la salida de cambio.

Este es un problema para las transacciones que tienen más de una entrada. Una forma de solucionar esta fuga es agregar más entradas hasta que la salida de cambio sea mayor que cualquier entrada, por ejemplo:
```
2 btc --> 4 btc
3 btc     6 btc
5 btc
```
## Reutilización forzada de direcciones

La **reutilización forzada de direcciones** o **reutilización incentivada de direcciones** es cuando un adversario paga una cantidad (a menudo pequeña) de bitcoin a direcciones que ya se han utilizado en la cadena de bloques. El adversario espera que los usuarios o su software de billetera **utilicen los pagos como entradas para una transacción más grande que revelará otras direcciones a través de la heurística de propiedad común de entrada**. Estos pagos pueden entenderse como una forma de coaccionar al propietario de la dirección para que reutilice la dirección sin intención.

Este ataque a veces se llama incorrectamente un **ataque de polvo**.

El comportamiento correcto por parte de las billeteras es no gastar monedas que han llegado a direcciones ya utilizadas y vacías.

## Otras análisis de Blockchain

* **Cantidades exactas de pago**: Para evitar transacciones con cambio, el pago debe ser igual al UTXO (lo cual es muy inesperado). Por lo tanto, una **transacción sin dirección de cambio probablemente sea una transferencia entre 2 direcciones del mismo usuario**.
* **Números redondos**: En una transacción, si una de las salidas es un "**número redondo**", es muy probable que este sea un **pago a un humano que puso ese precio** de "número redondo", por lo que la otra parte debe ser el sobrante.
* **Huella digital de billetera:** Un analista cuidadoso a veces puede deducir qué software creó una cierta transacción, porque los **diferentes softwares de billetera no siempre crean transacciones de exactamente la misma manera**. La huella digital de billetera se puede utilizar para detectar salidas de cambio porque una salida de cambio es la que se gasta con la misma huella digital de billetera.
* **Correlaciones de cantidad y tiempo**: Si la persona que realizó la transacción **divulga** el **tiempo** y/o la **cantidad** de la transacción, puede ser fácilmente **descubrible**.

## Análisis de tráfico

Una organización que **intercepte su tráfico** puede verle comunicándose en la red de bitcoin.\
Si el adversario ve una transacción o bloque **saliendo de su nodo que no entró previamente**, entonces puede saber con casi certeza que **la transacción fue realizada por usted o el bloque fue minado por usted**. Como se involucran conexiones a Internet, el adversario podrá **vincular la dirección IP con la información de bitcoin descubierta**.

Un atacante que no pueda interceptar todo el tráfico de Internet pero que tenga **muchos nodos de Bitcoin** para estar **más cerca** de las **fuentes** podría ser capaz de conocer la dirección IP que está anunciando transacciones o bloques.\
Además, algunas billeteras retransmiten periódicamente sus transacciones no confirmadas para que sean más propensas a propagarse ampliamente a través de la red y ser minadas.

## Otros ataques para encontrar información sobre el propietario de direcciones

Para más ataques lea [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy)

# Bitcoins Anónimos

## Obtención de Bitcoins de forma anónima

* **Comercio con efectivo:** Compre bitcoin con efectivo.
* **Sustituto de efectivo:** Compre tarjetas de regalo o similares e intercámbielas por bitcoin en línea.
* **Minería:** La minería es la forma más anónima de obtener bitcoin. Esto se aplica a la minería en solitario ya que los [pools de minería](https://en.bitcoin.it/wiki/Pooled\_mining) generalmente conocen la dirección IP del minero.
* **Robo:** En teoría, otra forma de obtener bitcoin anónimamente es robarlos.

## Mezcladores

Un usuario **enviaría bitcoins a un servicio de mezcla** y el servicio **devolvería diferentes bitcoins al usuario**, menos una comisión. En teoría, un adversario que observa la cadena de bloques sería **incapaz de vincular** las transacciones entrantes y salientes.

Sin embargo, el usuario necesita confiar en el servicio de mezcla para que devuelva los bitcoin y también para que no guarde registros sobre las relaciones entre el dinero recibido y enviado.\
Otros servicios también pueden usarse como mezcladores, como los casinos de Bitcoin donde puedes enviar bitcoins y recuperarlos más tarde.

## CoinJoin

**CoinJoin** **mezclará varias transacciones de diferentes usuarios en solo una** para hacer más **difícil** para un observador averiguar **qué entrada está relacionada con qué salida**.\
Esto ofrece un nuevo nivel de privacidad, sin embargo, **algunas** **transacciones** donde algunas cantidades de entrada y salida están correlacionadas o son muy diferentes del resto de las entradas y salidas **todavía pueden ser correlacionadas** por el observador externo.

Ejemplos de identificadores de transacciones (probablemente) CoinJoin en la cadena de bloques de bitcoin son `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

[**https://coinjoin.io/en**](https://coinjoin.io/en)\
**Similar a coinjoin pero mejor y para ethereum tienes** [**Tornado Cash**](https://tornado.cash) **(el dinero lo proporcionan los mineros, así que simplemente aparece en tu billetera).**

## PayJoin

El tipo de CoinJoin discutido en la sección anterior puede ser fácilmente identificado como tal al buscar las múltiples salidas con el mismo valor.

PayJoin (también llamado pago-a-punto-final o P2EP) es un tipo especial de CoinJoin entre dos partes donde una parte paga a la otra. La transacción entonces **no tiene las distintivas múltiples salidas** con el mismo valor, y por lo tanto no es obviamente visible como un CoinJoin de salidas iguales. Considere esta transacción:
```
2 btc --> 3 btc
5 btc     4 btc
```
Podría interpretarse como una simple transacción que paga a algún lugar con cambio sobrante (ignora por ahora la pregunta de cuál salida es el pago y cuál es el cambio). Otra forma de interpretar esta transacción es que la entrada de 2 BTC es propiedad de un comerciante y 5 BTC es propiedad de su cliente, y que esta transacción implica que el cliente paga 1 BTC al comerciante. No hay forma de saber cuál de estas dos interpretaciones es correcta. El resultado es una transacción coinjoin que rompe la heurística de propiedad común de entrada y mejora la privacidad, pero también es **indetectable e indistinguible de cualquier transacción regular de bitcoin**.

Si las transacciones PayJoin se utilizaran incluso moderadamente, harían que la **heurística de propiedad común de entrada fuera completamente defectuosa en la práctica**. Como son indetectables, ni siquiera sabríamos si se están utilizando hoy en día. Dado que las empresas de vigilancia de transacciones dependen principalmente de esa heurística, a partir de 2019 hay una gran expectación sobre la idea de PayJoin.

# Buenas Prácticas de Privacidad en Bitcoin

## Sincronización de Cartera

Las carteras de Bitcoin deben obtener de alguna manera información sobre su saldo e historial. A finales de 2018, las soluciones existentes más prácticas y privadas son usar una **cartera de nodo completo** (que es máximamente privada) y **filtrado de bloques del lado del cliente** (que es muy bueno).

* **Nodo completo:** Los nodos completos descargan toda la blockchain, que contiene cada [transacción](https://en.bitcoin.it/wiki/Transaction) en cadena que ha ocurrido en bitcoin. Por lo tanto, un adversario que observe la conexión a internet del usuario no podrá saber qué transacciones o direcciones le interesan al usuario.
* **Filtrado de bloques del lado del cliente:** El filtrado de bloques del lado del cliente funciona creando **filtros** que contienen todas las **direcciones** para cada transacción en un bloque. Los filtros pueden probar si un **elemento está en el conjunto**; son posibles falsos positivos pero no falsos negativos. Una cartera ligera **descargaría** todos los filtros para cada **bloque** en la **blockchain** y buscaría coincidencias con sus **propias** **direcciones**. Los bloques que contengan coincidencias se descargarían completamente de la red peer-to-peer, y esos bloques se utilizarían para obtener el historial y el saldo actual de la cartera.

## Tor

La red Bitcoin utiliza una red peer-to-peer, lo que significa que otros pares pueden conocer tu dirección IP. Por eso se recomienda **conectarse a través de Tor cada vez que quieras interactuar con la red de bitcoin**.

## Evitar la reutilización de direcciones

**El uso de direcciones más de una vez es muy perjudicial para la privacidad porque eso vincula más transacciones de la blockchain con la prueba de que fueron creadas por la misma entidad**. La forma más privada y segura de usar bitcoin es enviar una **nueva dirección a cada persona que te pague**. Una vez que se hayan gastado las monedas recibidas, la dirección nunca debería usarse de nuevo. Además, se debe exigir una nueva dirección de bitcoin al enviar bitcoin. Todas las buenas carteras de bitcoin tienen una interfaz de usuario que desalienta la reutilización de direcciones.

## Múltiples transacciones

**Pagar** a alguien con **más de una transacción en cadena** puede reducir enormemente el poder de los ataques de privacidad basados en montos, como la correlación de montos y números redondos. Por ejemplo, si el usuario quiere pagar 5 BTC a alguien y no quiere que el valor de 5 BTC sea fácilmente buscable, entonces pueden enviar dos transacciones por el valor de 2 BTC y 3 BTC que juntas suman 5 BTC.

## Evitar el cambio

La evitación de cambio es donde se eligen cuidadosamente las entradas y salidas de la transacción para no requerir una salida de cambio en absoluto. **No tener una salida de cambio es excelente para la privacidad**, ya que rompe las heurísticas de detección de cambio.

## Múltiples salidas de cambio

Si la evitación de cambio no es una opción, entonces **crear más de una salida de cambio puede mejorar la privacidad**. Esto también rompe las heurísticas de detección de cambio que generalmente asumen que solo hay una salida de cambio. Como este método utiliza más espacio de bloque que lo habitual, la evitación de cambio es preferible.

# Monero

Cuando se desarrolló Monero, la necesidad apremiante de **anonimato completo** fue lo que buscó resolver, y en gran medida, ha llenado ese vacío.

# Ethereum

## Gas

Gas se refiere a la unidad que mide la **cantidad** de **esfuerzo computacional** requerido para ejecutar operaciones específicas en la red Ethereum. Gas se refiere a la **tarifa** requerida para llevar a cabo con éxito una **transacción** en Ethereum.

Los precios del gas se denotan en **gwei**, que es una denominación de ETH - cada gwei es igual a **0.000000001 ETH** (10-9 ETH). Por ejemplo, en lugar de decir que tu gas cuesta 0.000000001 ether, puedes decir que tu gas cuesta 1 gwei. La palabra 'gwei' significa 'giga-wei', y es igual a **1,000,000,000 wei**. Wei es la **unidad más pequeña de ETH**.

Para calcular el gas que va a costar una transacción lee este ejemplo:

Digamos que Jordan tiene que pagarle a Taylor 1 ETH. En la transacción el límite de gas es de 21,000 unidades y la tarifa base es de 100 gwei. Jordan incluye una propina de 10 gwei.

Usando la fórmula anterior podemos calcular esto como `21,000 * (100 + 10) = 2,310,000 gwei` o 0.00231 ETH.

Cuando Jordan envíe el dinero, se deducirán 1.00231 ETH de la cuenta de Jordan. Taylor será acreditado con 1.0000 ETH. El minero recibe la propina de 0.00021 ETH. La tarifa base de 0.0021 ETH se quema.

Además, Jordan también puede establecer una tarifa máxima (`maxFeePerGas`) para la transacción. La diferencia entre la tarifa máxima y la tarifa real se reembolsa a Jordan, es decir, `reembolso = tarifa máxima - (tarifa base + tarifa de prioridad)`. Jordan puede establecer una cantidad máxima a pagar por la transacción para ejecutarse y no preocuparse por pagar de más "más allá" de la tarifa base cuando se ejecute la transacción.

Dado que la tarifa base es calculada por la red basada en la demanda de espacio de bloque, este último parámetro: maxFeePerGas ayuda a controlar la tarifa máxima que se va a pagar.

## Transacciones

Ten en cuenta que en la red de **Ethereum** una transacción se realiza entre 2 direcciones y estas pueden ser **direcciones de usuario o de contrato inteligente**.\
Los **Contratos Inteligentes** se almacenan en el libro mayor distribuido a través de una **transacción** **especial**.

Las transacciones, que cambian el estado de la EVM, necesitan ser transmitidas a toda la red. Cualquier nodo puede transmitir una solicitud para que se ejecute una transacción en la EVM; después de que esto suceda, un **minero** **ejecutará** la **transacción** y propagará el cambio de estado resultante al resto de la red.\
Las transacciones requieren una **tarifa** y deben ser minadas para ser válidas.

Una transacción enviada incluye la siguiente información:

* `recipient` – la dirección receptora (si es una cuenta de propiedad externa, la transacción transferirá valor. Si es una cuenta de contrato, la transacción ejecutará el código del contrato)
* `signature` – el identificador del remitente. Esto se genera cuando la clave privada del remitente firma la transacción y confirma que el remitente ha autorizado esta transacción
* `value` – cantidad de ETH para transferir del remitente al receptor (en WEI, una denominación de ETH)
* `data` – campo opcional para incluir datos arbitrarios
* `gasLimit` – la cantidad máxima de unidades de gas que puede consumir la transacción. Las unidades de gas representan pasos computacionales
* `maxPriorityFeePerGas` - la cantidad máxima de gas a incluir como propina al minero
* `maxFeePerGas` - la cantidad máxima de gas dispuesta a pagar por la transacción (incluyendo `baseFeePerGas` y `maxPriorityFeePerGas`)

Nota que no hay ningún campo para la dirección de origen, esto es porque esto se puede extrapolar de la firma.

# Referencias

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)


<details>

<summary><strong>¡Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) en github.

</details>
