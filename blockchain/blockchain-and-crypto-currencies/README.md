<details>

<summary><strong>Aprende a hackear AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


# Terminología Básica

* **Contrato inteligente**: Los contratos inteligentes son simplemente **programas almacenados en una cadena de bloques que se ejecutan cuando se cumplen condiciones predeterminadas**. Normalmente se utilizan para automatizar la **ejecución** de un **acuerdo** para que todos los participantes puedan estar inmediatamente seguros del resultado, sin la intervención de intermediarios ni pérdida de tiempo. (De [aquí](https://www.ibm.com/topics/smart-contracts)).
* Básicamente, un contrato inteligente es un **fragmento de código** que se ejecutará cuando las personas accedan y acepten el contrato. Los contratos inteligentes **se ejecutan en cadenas de bloques** (por lo que los resultados se almacenan de forma inmutable) y pueden ser leídos por las personas antes de aceptarlos.
* **dApps**: Las **aplicaciones descentralizadas** se implementan sobre **contratos** **inteligentes**. Normalmente tienen un front-end donde el usuario puede interactuar con la aplicación, el **back-end** es público (por lo que puede ser auditado) y se implementa como un **contrato inteligente**. A veces se necesita el uso de una base de datos, la cadena de bloques de Ethereum asigna cierto almacenamiento a cada cuenta.
* **Tokens y monedas**: Una **moneda** es una criptomoneda que actúa como **dinero digital** y un **token** es algo que **representa** algún **valor** pero no es una moneda.
* **Tokens de utilidad**: Estos tokens permiten al usuario **acceder a cierto servicio más adelante** (es algo que tiene algún valor en un entorno específico).
* **Tokens de seguridad**: Estos representan la **propiedad** o algún activo.
* **DeFi**: **Finanzas Descentralizadas**.
* **DEX: Plataformas de Intercambio Descentralizado**.
* **DAOs**: **Organizaciones Autónomas Descentralizadas**.

# Mecanismos de Consenso

Para que una transacción de cadena de bloques sea reconocida, debe ser **añadida** a la **cadena de bloques**. Los validadores (mineros) llevan a cabo esta adición; en la mayoría de los protocolos, **reciben una recompensa** por hacerlo. Para que la cadena de bloques permanezca segura, debe tener un mecanismo para **evitar que un usuario malintencionado o un grupo se apodere de la mayoría de la validación**.

La Prueba de Trabajo, otro mecanismo de consenso comúnmente utilizado, utiliza una validación de destreza computacional para verificar transacciones, requiriendo que un posible atacante adquiera una gran fracción del poder computacional de la red de validadores.

## Prueba de Trabajo (PoW)

Esto utiliza una **validación de destreza computacional** para verificar transacciones, requiriendo que un posible atacante adquiera una gran fracción del poder computacional de la red de validadores.\
Los **mineros** **seleccionarán varias transacciones** y luego comenzarán a **calcular la Prueba de Trabajo**. El **minero con los mayores recursos computacionales** es más probable que **termine antes** la Prueba de Trabajo y obtenga las tarifas de todas las transacciones.

## Prueba de Participación (PoS)

PoS logra esto al **requerir que los validadores tengan una cierta cantidad de tokens de cadena de bloques**, requiriendo que **los posibles atacantes adquieran una gran fracción de los tokens** en la cadena de bloques para lanzar un ataque.\
En este tipo de consenso, cuantos más tokens tenga un minero, más probable será que se le pida al minero que cree el siguiente bloque.\
En comparación con PoW, esto **reduce en gran medida el consumo de energía** que los mineros están gastando.

# Bitcoin

## Transacciones

Una **transacción** simple es un **movimiento de dinero** de una dirección a otra.\
Una **dirección** en bitcoin es el hash de la **clave pública**, por lo tanto, para que alguien realice una transacción desde una dirección, necesita conocer la clave privada asociada a esa clave pública (la dirección).\
Entonces, cuando se realiza una **transacción**, se **firma** con la clave privada de la dirección para mostrar que la transacción es **legítima**.

La primera parte de la producción de una firma digital en Bitcoin se puede representar matemáticamente de la siguiente manera:\
_**Sig**_ = _**Fsig**_(_**Fhash**_(_**m**_),_**dA**_)

Donde:

* \_d\_A es la **clave privada** de firma
* _m_ es la **transacción**
* Fhash es la función de hash
* Fsig es el algoritmo de firma
* Sig es la firma resultante

La función de firma (Fsig) produce una firma (Sig) que consta de dos valores: R y S:

* Sig = (R, S)

Una vez que se han calculado R y S, se serializan en un flujo de bytes que se codifica utilizando un esquema de codificación estándar internacional conocido como Reglas de Codificación Distinguidas (o DER). Para verificar que la firma es válida, se utiliza un algoritmo de verificación de firma. La verificación de una firma digital requiere lo siguiente:

* Firma (R y S)
* Hash de la transacción
* La clave pública que corresponde a la clave privada que se utilizó para crear la firma

La verificación de una firma efectivamente significa que solo el propietario de la clave privada (que generó la clave pública) podría haber producido la firma en la transacción. El algoritmo de verificación de firma devolverá 'VERDADERO' si la firma es realmente válida.

### Transacciones Multifirma

Una **dirección multifirma** es una dirección asociada con más de una clave privada ECDSA. El tipo más simple es una dirección m-de-n: está asociada con n claves privadas, y enviar bitcoins desde esta dirección requiere firmas de al menos m claves. Una **transacción multifirma** es aquella que envía fondos desde una dirección multifirma.

### Campos de Transacciones

Cada transacción de bitcoin tiene varios campos:

* **Entradas**: La cantidad y la dirección **desde** donde se **están transfiriendo** los **bitcoins**
* **Salidas**: La dirección y las cantidades que se transfieren a **cada** **salida**
* **Tarifa:** La cantidad de **dinero** que se **paga** al **minero** de la transacción
* **Script\_sig**: Firma de script de la transacción
* **Script\_type**: Tipo de transacción

Hay **2 tipos principales** de transacciones:

* **P2PKH: "Pagar a la Clave Pública Hash"**: Así es como se realizan las transacciones. Se requiere que el **remitente** proporcione una **firma** válida (de la clave privada) y **clave** **pública**. El script de salida de la transacción utilizará la firma y la clave pública y, a través de algunas funciones criptográficas, verificará **si coincide** con el hash de la clave pública, si lo hace, entonces los **fondos** serán **gastables**. Este método oculta tu clave pública en forma de hash para mayor seguridad.
* **P2SH: "Pagar a Script Hash":** Las salidas de una transacción son simplemente **scripts** (esto significa que la persona que desea este dinero envía un script) que, si se **ejecutan con parámetros específicos, darán como resultado un booleano de `true` o `false`**. Si un minero ejecuta el script de salida con los parámetros suministrados y da como resultado `true`, el **dinero se enviará a la salida deseada**. `P2SH` se utiliza para **monederos multifirma** haciendo que los scripts de salida sean **lógica que verifica múltiples firmas antes de aceptar la transacción**. `P2SH` también se puede utilizar para permitir que cualquiera, o nadie, gaste los fondos. Si el script de salida de una transacción P2SH es simplemente `1` para verdadero, entonces intentar gastar la salida sin suministrar parámetros simplemente dará como resultado `1`, haciendo que el dinero sea gastable por cualquiera que lo intente. Esto también se aplica a los scripts que devuelven `0`, haciendo que la salida sea gastable por nadie.

## Red Lightning

Este protocolo ayuda a **realizar varias transacciones a un canal** y **solo** **enviar** el **estado final** a la cadena de bloques para guardarlo.\
Esto **mejora** la **velocidad** de la cadena de bloques de bitcoin (solo permite 7 pagos por segundo) y permite crear **transacciones más difíciles de rastrear** ya que el canal se crea a través de nodos de la cadena de bloques de bitcoin:

![](<../../.gitbook/assets/image (611).png>)

El uso normal de la Red Lightning consiste en **abrir un canal de pago** comprometiendo una transacción de financiación a la cadena de bloques base relevante (capa 1), seguido de realizar **cualquier número** de transacciones de la Red Lightning que actualizan la distribución tentativa de los fondos del canal **sin transmitirlas a la cadena de bloques**, seguido opcionalmente por cerrar el canal de pago al **transmitir** la **versión final** de la transacción de liquidación para distribuir los fondos del canal.

Cabe destacar que cualquiera de los dos miembros del canal puede detenerse y enviar el estado final del canal a la cadena de bloques en cualquier momento.

# Ataques a la Privacidad de Bitcoin

## Entrada Común

Teóricamente, las entradas de una transacción pueden pertenecer a diferentes usuarios, pero en realidad eso es inusual ya que requiere pasos adicionales. Por lo tanto, muy a menudo se puede asumir que **2 direcciones de entrada en la misma transacción pertenecen al mismo propietario**.

## Detección de Direcciones de Cambio UTXO

**UTXO** significa **Salidas de Transacción No Gastadas** (UTXOs). En una transacción que utiliza la salida de una transacción anterior como entrada, **toda la salida debe ser gastada** (para evitar ataques de doble gasto). Por lo tanto, si la intención era **enviar** solo **parte** del dinero de esa salida a una dirección y **mantener** la **otra** **parte**, aparecerán **2 salidas diferentes**: la **intencionada** y una **nueva dirección de cambio aleatoria** donde se guardará el resto del dinero.

Entonces, un observador puede asumir que **la nueva dirección de cambio generada pertenece al propietario del UTXO**.

## Redes Sociales y Foros

Algunas personas comparten datos sobre sus direcciones de bitcoin en diferentes sitios web en Internet. **Esto hace bastante fácil identificar al propietario de una dirección**.

## Gráficos de Transacciones

Al representar las transacciones en gráficos, **es posible saber con cierta probabilidad a dónde fueron a parar los fondos de una cuenta**. Por lo tanto, es posible saber algo sobre los **usuarios** que están **relacionados** en la cadena de bloques.

## **Heurística de Entrada Innecesaria**

También llamada "heurística de cambio óptimo". Considera esta transacción de bitcoin. Tiene dos entradas por un valor de 2 BTC y 3 BTC y dos salidas por un valor de 4 BTC y 1 BTC.
```
2 btc --> 4 btc
3 btc     1 btc
```
Suponiendo que una de las salidas es el cambio y la otra salida es el pago. Hay dos interpretaciones: la salida de pago es o bien la salida de 4 BTC o la salida de 1 BTC. Pero si la salida de 1 BTC es la cantidad de pago, entonces la entrada de 3 BTC es innecesaria, ya que la billetera podría haber gastado solo la entrada de 2 BTC y pagado tarifas de minero más bajas por hacerlo. Esto indica que la salida real de pago es de 4 BTC y que 1 BTC es la salida de cambio.

Esto es un problema para transacciones que tienen más de una entrada. Una forma de solucionar esta fuga es agregar más entradas hasta que la salida de cambio sea mayor que cualquier entrada, por ejemplo:
```
2 btc --> 4 btc
3 btc     6 btc
5 btc
```
## Reutilización forzada de direcciones

La **reutilización forzada de direcciones** o **reutilización incentivada de direcciones** ocurre cuando un adversario paga una cantidad (a menudo pequeña) de bitcoin a direcciones que ya han sido utilizadas en la cadena de bloques. El adversario espera que los usuarios o su software de billetera **utilicen los pagos como insumos para una transacción más grande que revelará otras direcciones a través de la heurística de propiedad de entrada común**. Estos pagos pueden entenderse como una forma de obligar al propietario de la dirección a una reutilización de direcciones no intencional.

A veces, este ataque se llama incorrectamente **ataque de polvo**.

El comportamiento correcto de las billeteras es no gastar monedas que hayan llegado a direcciones vacías ya utilizadas.

## Otras Análisis de Blockchain

* **Montos de pago exactos**: Para evitar transacciones con cambio, el pago debe ser igual al UTXO (lo cual es altamente inesperado). Por lo tanto, una **transacción sin dirección de cambio probablemente sea una transferencia entre 2 direcciones del mismo usuario**.
* **Números redondos**: En una transacción, si una de las salidas es un "**número redondo**", es altamente probable que sea un **pago a un humano que colocó ese** "número redondo" **de precio**, por lo que la otra parte debe ser el sobrante.
* **Identificación de billeteras**: Un analista cuidadoso a veces puede deducir qué software creó una determinada transacción, ya que los **diferentes softwares de billeteras no siempre crean transacciones de la misma manera**. La identificación de billeteras se puede utilizar para detectar salidas de cambio porque una salida de cambio es aquella gastada con la misma identificación de billetera.
* **Correlaciones de monto y tiempo**: Si la persona que realizó la transacción **revela** el **tiempo** y/o **monto** de la transacción, puede ser fácilmente **descubrible**.

## Análisis de tráfico

Algunas organizaciones que **interceptan su tráfico** pueden ver que usted está comunicándose en la red de bitcoin.\
Si el adversario ve una transacción o bloque **saliendo de su nodo que no había entrado previamente**, entonces puede saber con casi total certeza que **la transacción fue realizada por usted o el bloque fue minado por usted**. Dado que las conexiones a Internet están involucradas, el adversario podrá **vincular la dirección IP con la información de bitcoin descubierta**.

Un atacante que no puede interceptar todo el tráfico de Internet pero que tiene **muchos nodos de Bitcoin** para permanecer **más cerca** de las fuentes podría ser capaz de conocer las direcciones IP que están anunciando transacciones o bloques.\
Además, algunas billeteras retransmiten periódicamente sus transacciones no confirmadas para que tengan más probabilidades de propagarse ampliamente a través de la red y ser minadas.

## Otros ataques para encontrar información sobre el propietario de direcciones

Para más ataques, leer [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy)

# Bitcoins Anónimos

## Obtención de Bitcoins de forma anónima

* **Intercambios en efectivo:** Comprar bitcoins usando efectivo.
* **Sustituto de efectivo:** Comprar tarjetas de regalo u similares e intercambiarlas por bitcoins en línea.
* **Minería:** La minería es la forma más anónima de obtener bitcoins. Esto se aplica a la minería en solitario ya que los [pools de minería](https://en.bitcoin.it/wiki/Pooled\_mining) generalmente conocen la dirección IP del minero.
* **Robo:** En teoría, otra forma de obtener bitcoin de forma anónima es robándolos.

## Mezcladores

Un usuario **enviaría bitcoins a un servicio de mezcla** y el servicio **enviaría diferentes bitcoins de vuelta al usuario**, menos una tarifa. En teoría, un adversario que observe la cadena de bloques sería **incapaz de vincular** las transacciones entrantes y salientes.

Sin embargo, el usuario debe confiar en el servicio de mezcla para devolver los bitcoins y también para no estar guardando registros sobre las relaciones entre el dinero recibido y enviado.\
Algunos otros servicios también pueden usarse como mezcladores, como los casinos de Bitcoin donde se pueden enviar bitcoins y recuperarlos más tarde.

## CoinJoin

**CoinJoin** **mezclará varias transacciones de diferentes usuarios en solo una** para hacer más **difícil** para un observador encontrar **qué entrada está relacionada con qué salida**.\
Esto ofrece un nuevo nivel de privacidad, sin embargo, **algunas** **transacciones** donde algunos montos de entrada y salida están correlacionados o son muy diferentes del resto de las entradas y salidas **todavía pueden ser correlacionadas** por el observador externo.

Ejemplos de IDs de transacciones (probablemente) CoinJoin en la cadena de bloques de bitcoin son `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` y `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

[**https://coinjoin.io/en**](https://coinjoin.io/en)\
**Similar a CoinJoin pero mejor y para ethereum tienes** [**Tornado Cash**](https://tornado.cash) **(el dinero es proporcionado por los mineros, por lo que simplemente aparece en tu billetera).**

## PayJoin

El tipo de CoinJoin discutido en la sección anterior puede identificarse fácilmente como tal al verificar las múltiples salidas con el mismo valor.

PayJoin (también llamado pago al punto final o P2EP) es un tipo especial de CoinJoin entre dos partes donde una parte paga a la otra. La transacción entonces **no tiene las múltiples salidas distintivas** con el mismo valor, por lo que no es visible de manera obvia como un CoinJoin de salidas iguales. Considere esta transacción:
```
2 btc --> 3 btc
5 btc     4 btc
```
Podría interpretarse como una simple transacción pagando a algún lugar con cambio sobrante (ignorando por ahora la cuestión de cuál salida es el pago y cuál es el cambio). Otra forma de interpretar esta transacción es que la entrada de 2 BTC es propiedad de un comerciante y 5 BTC es propiedad de su cliente, y que esta transacción implica que el cliente pague 1 BTC al comerciante. No hay forma de saber cuál de estas dos interpretaciones es correcta. El resultado es una transacción de coinjoin que rompe la heurística común de propiedad de entrada y mejora la privacidad, pero también es **indetectable e indistinguible de cualquier transacción de bitcoin regular**.

Si las transacciones PayJoin se utilizan moderadamente, harían que la **heurística común de propiedad de entrada sea completamente defectuosa en la práctica**. Como son indetectables, ni siquiera sabríamos si se están utilizando hoy en día. Dado que las empresas de vigilancia de transacciones dependen en su mayoría de esa heurística, a partir de 2019 hay un gran entusiasmo por la idea de PayJoin.

# Buenas Prácticas de Privacidad en Bitcoin

## Sincronización de Monederos

Los monederos de Bitcoin deben obtener de alguna manera información sobre su saldo e historial. A finales de 2018, las soluciones existentes más prácticas y privadas son usar un **monedero de nodo completo** (que es máximo privado) y **filtrado de bloques del lado del cliente** (que es muy bueno).

* **Nodo completo:** Los nodos completos descargan toda la cadena de bloques que contiene cada [transacción en cadena](https://en.bitcoin.it/wiki/Transaction) que ha ocurrido en bitcoin. Por lo tanto, un adversario que observe la conexión a internet del usuario no podrá saber qué transacciones o direcciones le interesan al usuario.
* **Filtrado de bloques del lado del cliente:** El filtrado de bloques del lado del cliente funciona creando **filtros** que contienen todas las **direcciones** de cada transacción en un bloque. Los filtros pueden probar si un **elemento está en el conjunto**; los falsos positivos son posibles pero no los falsos negativos. Un monedero ligero **descargaría** todos los filtros de cada **bloque** en la **cadena de bloques** y verificaría si hay coincidencias con sus **propias** **direcciones**. Los bloques que contienen coincidencias se descargarían por completo de la red peer-to-peer, y esos bloques se usarían para obtener el historial y el saldo actual del monedero.

## Tor

La red de Bitcoin utiliza una red peer-to-peer, lo que significa que otros pares pueden conocer tu dirección IP. Por eso se recomienda **conectarse a través de Tor cada vez que desees interactuar con la red de Bitcoin**.

## Evitar la reutilización de direcciones

**La reutilización de direcciones es muy perjudicial para la privacidad porque vincula más transacciones en la cadena de bloques con la prueba de que fueron creadas por la misma entidad**. La forma más privada y segura de usar Bitcoin es enviar una **nueva dirección a cada persona que te pague**. Después de que las monedas recibidas hayan sido gastadas, la dirección nunca debería usarse de nuevo. Además, se debe exigir una nueva dirección de Bitcoin al enviar bitcoins. Todos los buenos monederos de Bitcoin tienen una interfaz de usuario que desalienta la reutilización de direcciones.

## Múltiples transacciones

**Pagar** a alguien con **más de una transacción en cadena** puede reducir en gran medida el poder de los ataques de privacidad basados en la cantidad, como la correlación de cantidades y los números redondos. Por ejemplo, si el usuario quiere pagar 5 BTC a alguien y no quiere que el valor de 5 BTC sea fácilmente rastreable, entonces puede enviar dos transacciones por el valor de 2 BTC y 3 BTC que juntas suman 5 BTC.

## Evitar el cambio

Evitar el cambio es cuando las entradas y salidas de la transacción se eligen cuidadosamente para no requerir una salida de cambio en absoluto. **No tener una salida de cambio es excelente para la privacidad**, ya que rompe las heurísticas de detección de cambio.

## Múltiples salidas de cambio

Si evitar el cambio no es una opción, **crear más de una salida de cambio puede mejorar la privacidad**. Esto también rompe las heurísticas de detección de cambio que suelen asumir que solo hay una salida de cambio. Dado que este método utiliza más espacio de bloque de lo habitual, evitar el cambio es preferible.

# Monero

Cuando se desarrolló Monero, la gran necesidad de **anonimato completo** fue lo que buscó resolver, y en gran medida, ha llenado ese vacío.

# Ethereum

## Gas

Gas se refiere a la unidad que mide la **cantidad** de **esfuerzo computacional** requerido para ejecutar operaciones específicas en la red Ethereum. Gas se refiere a la **tarifa** requerida para realizar con éxito una **transacción** en Ethereum.

Los precios de gas se indican en **gwei**, que a su vez es una denominación de ETH: cada gwei es igual a **0.000000001 ETH** (10-9 ETH). Por ejemplo, en lugar de decir que tu gas cuesta 0.000000001 ether, puedes decir que tu gas cuesta 1 gwei. La palabra 'gwei' en sí misma significa 'giga-wei', y es igual a **1,000,000,000 wei**. Wei en sí es la **unidad más pequeña de ETH**.

Para calcular el gas que va a costar una transacción, lee este ejemplo:

Supongamos que Jordan tiene que pagarle a Taylor 1 ETH. En la transacción, el límite de gas es de 21,000 unidades y la tarifa base es de 100 gwei. Jordan incluye una propina de 10 gwei.

Usando la fórmula anterior, podemos calcular esto como `21,000 * (100 + 10) = 2,310,000 gwei` o 0.00231 ETH.

Cuando Jordan envía el dinero, se deducirán 1.00231 ETH de la cuenta de Jordan. Taylor recibirá 1.0000 ETH. El minero recibirá la propina de 0.00021 ETH. La tarifa base de 0.0021 ETH se quema.

Además, Jordan también puede establecer una tarifa máxima (`maxFeePerGas`) para la transacción. La diferencia entre la tarifa máxima y la tarifa real se reembolsa a Jordan, es decir, `reembolso = tarifa máxima - (tarifa base + tarifa de prioridad)`. Jordan puede establecer un monto máximo a pagar por la ejecución de la transacción y no preocuparse por pagar en exceso "más allá" de la tarifa base cuando se ejecute la transacción.

Dado que la tarifa base se calcula por la red en función de la demanda de espacio de bloque, este último parámetro: maxFeePerGas ayuda a controlar la tarifa máxima que se va a pagar.

## Transacciones

Ten en cuenta que en la red **Ethereum** una transacción se realiza entre 2 direcciones y estas pueden ser **direcciones de usuario o de contratos inteligentes**.\
Los **Contratos Inteligentes** se almacenan en el libro mayor distribuido a través de una **transacción especial**.

Las transacciones, que cambian el estado del EVM, deben ser difundidas a toda la red. Cualquier nodo puede difundir una solicitud para que se ejecute una transacción en el EVM; después de que esto sucede, un **minero** ejecutará la **transacción** y propagará el cambio de estado resultante al resto de la red.\
Las transacciones requieren una **tarifa** y deben ser minadas para ser válidas.

Una transacción enviada incluye la siguiente información:

* `destinatario` – la dirección receptora (si es una cuenta de propiedad externa, la transacción transferirá valor. Si es una cuenta de contrato, la transacción ejecutará el código del contrato)
* `firma` – el identificador del remitente. Esto se genera cuando la clave privada del remitente firma la transacción y confirma que el remitente ha autorizado esta transacción
* `valor` – cantidad de ETH a transferir del remitente al destinatario (en WEI, una denominación de ETH)
* `datos` – campo opcional para incluir datos arbitrarios
* `gasLimit` – la cantidad máxima de unidades de gas que puede consumir la transacción. Las unidades de gas representan pasos computacionales
* `maxPriorityFeePerGas` - la cantidad máxima de gas que se incluirá como propina al minero
* `maxFeePerGas` - la cantidad máxima de gas dispuesta a pagar por la transacción (incluida `baseFeePerGas` y `maxPriorityFeePerGas`)

Ten en cuenta que no hay ningún campo para la dirección de origen, esto se debe a que esto se puede extrapolar de la firma.

# Referencias

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)
