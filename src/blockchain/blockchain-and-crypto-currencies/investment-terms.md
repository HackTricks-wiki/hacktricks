# Términos de inversión

{{#include ../../banners/hacktricks-training.md}}

## Al contado

La negociación al contado intercambia un activo para su entrega inmediata. Una orden limitada especifica la cantidad y el precio límite; se ejecuta solo cuando el mercado puede satisfacer ese precio o uno mejor. Una orden de mercado, en cambio, busca ejecutarse rápidamente a los mejores precios disponibles en ese momento y puede sufrir deslizamiento.<sup>[[4]](#references)</sup>

Una orden stop-limit tiene un precio stop que activa una orden limitada. Puede restringir el precio de ejecución, pero no garantiza que se ejecute si el mercado supera el límite.<sup>[[4]](#references)</sup>

## Futuros

Un contrato de futuros es un acuerdo estandarizado para comprar o vender una materia prima o un instrumento financiero especificado en una fecha futura. Por ejemplo, dos partes podrían acordar un precio de 70.000 $ por un bitcoin, con liquidación en seis meses.<sup>[[1]](#references)</sup>

Si el precio de liquidación es de 80.000 $, la parte con una posición larga obtiene ganancias y la parte con una posición corta sufre pérdidas con respecto al precio contractual de 70.000 $. Si es de 60.000 $, ocurre lo contrario. Los futuros negociados en bolsas se valoran a mercado y, por lo general, se cierran o se renuevan antes del vencimiento, por lo que este es un ejemplo simplificado.<sup>[[2]](#references)</sup>

Los productores y consumidores usan futuros para cubrir el riesgo de precio; otros participantes los usan para buscar ganancias o aportar liquidez.<sup>[[1]](#references)</sup>

- Una **posición larga** suele generar ganancias cuando sube el precio del contrato.
- Una **posición corta** suele generar ganancias cuando baja el precio del contrato.<sup>[[2]](#references)</sup>

### Cobertura con futuros

Si un gestor de fondos prevé que una cartera bajará, podría vender en corto un contrato de futuros sobre un índice bursátil suficientemente correlacionado. Las ganancias de la cobertura corta pueden compensar parte de las pérdidas de la cartera; el riesgo de base hace que la compensación rara vez sea exacta. Un futuro de bitcoin cubriría la exposición a bitcoin, no automáticamente una cartera de acciones.

Si el mercado cubierto baja, la posición corta en futuros podría generar ganancias mientras las posiciones de la cartera pierden valor. Si sube, las posiciones de la cartera podrían generar ganancias mientras la cobertura pierde valor. La cobertura reduce riesgos específicos, pero no garantiza ganancias.<sup>[[1]](#references)</sup>

### Futuros perpetuos

Los contratos perpetuos son derivados sin una fecha de vencimiento fija. Las plataformas de criptomonedas suelen usar pagos periódicos de financiación para ayudar a mantener su precio cerca del precio al contado del activo subyacente; las condiciones varían según la plataforma.<sup>[[3]](#references)</sup>

Las ganancias y pérdidas cambian a medida que varía el precio de referencia. Un movimiento del precio del 1 % produce aproximadamente un movimiento del 1 % en el valor nominal de la posición, antes de comisiones y financiación, pero el apalancamiento puede convertirlo en un porcentaje mucho mayor del colateral depositado.

### Futuros con apalancamiento

El **apalancamiento** permite a un operador controlar una posición de mayor valor nominal con un depósito de margen menor. Las pérdidas no siempre se limitan al margen inicial: la liquidación, los saltos de precio, las comisiones y las reglas de la plataforma pueden generar pérdidas adicionales.<sup>[[3]](#references)</sup>

Por ejemplo, 100 $ de margen con un apalancamiento de 50x controlan una posición de 5.000 $. Sin tener en cuenta las comisiones, la financiación ni los mecanismos de liquidación, un movimiento favorable del 1 % produce una ganancia de 50 $ (el 50 % del margen inicial), mientras que un movimiento desfavorable del 1 % produce una pérdida de 50 $. Un movimiento desfavorable del 2 % equivale a 100 $, aunque normalmente una plataforma liquidará la posición antes de que se agote todo el margen.

El apalancamiento amplifica tanto las ganancias como las pérdidas y permite que una variación adversa relativamente pequeña provoque una liquidación.

## Diferencias entre futuros y opciones

El comprador de una opción recibe un derecho, no una obligación, de ejercerla conforme a las condiciones del contrato. El emisor de la opción tiene la obligación correspondiente si el comprador la ejerce. El comprador paga una prima al emisor a cambio de ese derecho.<sup>[[4]](#references)</sup>

### 1. **Obligación frente a derecho:**

* **Futuros:** Al comprar o vender un contrato de futuros, se establece un **acuerdo vinculante** para comprar o vender un activo a un precio específico en una fecha futura. Tanto el comprador como el vendedor están **obligados** a cumplir el contrato al vencimiento (salvo que lo cierren antes).
* **Opciones:** Con las opciones, se tiene el **derecho, pero no la obligación**, de comprar (en el caso de una **opción de compra**) o vender (en el caso de una **opción de venta**) un activo a un precio específico antes de una fecha de vencimiento determinada o en esa fecha. El **comprador** puede ejecutar la opción, mientras que el **vendedor** está obligado a cumplir la operación si el comprador decide ejercerla.

### 2. **Riesgo:**

* **Futuros:** Ambas partes pueden sufrir pérdidas considerables. Que las pérdidas sean matemáticamente ilimitadas depende de la posición y del activo subyacente: una posición corta puede tener pérdidas teóricas ilimitadas, mientras que una posición larga no puede perder más que el valor nominal si el activo subyacente no puede caer por debajo de cero.
* **Opciones:** Un comprador que no emita otra opción generalmente arriesga la prima pagada. El emisor de una opción de compra descubierta puede afrontar pérdidas teóricamente ilimitadas; otras estrategias de emisión de opciones tienen perfiles de riesgo limitados o ilimitados, según el caso.

### 3. **Costo:**

* **Futuros:** No hay un costo inicial aparte del margen necesario para mantener la posición, ya que tanto el comprador como el vendedor están obligados a completar la operación.
* **Opciones:** El comprador debe pagar por adelantado una **prima de opción** por el derecho a ejercerla. Esta prima es, esencialmente, el costo de la opción.

### 4. **Potencial de ganancias:**

* **Futuros:** Las ganancias o pérdidas se basan en la diferencia entre el precio de mercado al vencimiento y el precio acordado en el contrato.
* **Opciones:** El comprador obtiene ganancias cuando el mercado se mueve favorablemente más allá del precio de ejercicio por un importe superior a la prima pagada. El vendedor obtiene ganancias si conserva la prima cuando no se ejerce la opción.

## References

- [1] [CFTC - El propósito económico de los mercados de futuros](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Conceptos básicos del mercado de futuros](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Comprenda los riesgos de operar con monedas virtuales](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [Glosario de la CFTC - Opción, prima y ejercicio](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
