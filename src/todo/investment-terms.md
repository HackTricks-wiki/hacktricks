# Términos de inversión

{{#include ../banners/hacktricks-training.md}}

## Spot

El trading Spot intercambia un activo para su entrega inmediata. Una orden limitada especifica la cantidad y el precio límite; solo se ejecuta cuando el mercado puede satisfacer ese precio o uno mejor. Una orden de mercado, en cambio, busca una ejecución rápida a los mejores precios disponibles en ese momento y puede experimentar slippage.<sup>[[4]](#references)</sup>

Una orden stop-limit tiene un precio stop que activa una orden limitada. Puede restringir el precio de ejecución, pero no garantiza la ejecución si el mercado atraviesa el límite.<sup>[[4]](#references)</sup>

## Futuros

Un contrato de futuros es un acuerdo estandarizado para comprar o vender una materia prima o instrumento financiero específico en una fecha futura. Por ejemplo, dos partes podrían acordar un precio de 70.000 $ por un bitcoin, con liquidación en seis meses.<sup>[[1]](#references)</sup>

Si el precio de liquidación es de 80.000 $, la posición long obtiene ganancias y la posición short sufre pérdidas en relación con el precio contractual de 70.000 $. Si es de 60.000 $, la dirección se invierte. Los futuros negociados en exchanges reales se ajustan al mercado y normalmente se cierran o se renuevan antes del vencimiento, por lo que esta es una explicación simplificada.<sup>[[2]](#references)</sup>

Los productores y consumidores utilizan futuros para cubrir el riesgo de precio; otros participantes los utilizan para buscar beneficios o proporcionar liquidez.<sup>[[1]](#references)</sup>

- Una **posición long** generalmente obtiene beneficios cuando sube el precio del contrato.
- Una **posición short** generalmente obtiene beneficios cuando baja el precio del contrato.<sup>[[2]](#references)</sup>

### Cobertura con futuros

Si un gestor de fondos espera que una cartera baje, podría abrir una posición short en un contrato de futuros sobre un índice bursátil suficientemente correlacionado. Las ganancias de la cobertura short pueden compensar parte de las pérdidas de la cartera; el riesgo de base significa que la compensación rara vez es exacta. Un futuro de bitcoin cubriría la exposición a bitcoin, no automáticamente una cartera de acciones.

Si el mercado cubierto baja, la posición short en futuros puede ganar valor mientras las posiciones mantenidas lo pierden. Si sube, las posiciones mantenidas pueden ganar valor mientras la cobertura pierde. La cobertura reduce un riesgo específico en lugar de crear un beneficio garantizado.<sup>[[1]](#references)</sup>

### Futuros perpetuos

Los contratos perpetuos son derivados sin una fecha de vencimiento fija. Las plataformas de criptomonedas suelen utilizar pagos periódicos de funding para ayudar a mantener su precio cerca del precio Spot subyacente; las condiciones varían según la plataforma.<sup>[[3]](#references)</sup>

Las ganancias y pérdidas cambian a medida que se mueve el precio de referencia. Un movimiento del precio del 1 % produce aproximadamente un movimiento del 1 % sobre el valor nocional de la posición antes de comisiones y funding, pero el apalancamiento puede convertirlo en un porcentaje mucho mayor del colateral depositado.

### Futuros con apalancamiento

El **apalancamiento** permite a un trader controlar una posición nocional mayor con un depósito de margen menor. Las pérdidas no siempre se limitan al margen inicial: la liquidación, los gaps, las comisiones y las reglas de la plataforma pueden producir pérdidas adicionales.<sup>[[3]](#references)</sup>

Por ejemplo, un margen de 100 $ con un apalancamiento de 50x controla una posición de 5.000 $. Ignorando las comisiones, el funding y los mecanismos de liquidación, un movimiento favorable del 1 % produce una ganancia de 50 $ (el 50 % del margen inicial), mientras que un movimiento adverso del 1 % produce una pérdida de 50 $. Un movimiento adverso del 2 % equivale a 100 $, aunque normalmente una plataforma liquidará la posición antes de que se agote todo el margen.

El apalancamiento amplifica tanto las ganancias como las pérdidas y hace posible la liquidación después de un movimiento adverso comparativamente pequeño.

## Diferencias entre futuros y opciones

El comprador de una opción recibe un derecho, no una obligación, de ejercerla según las condiciones del contrato. El vendedor de la opción tiene la obligación correspondiente si el comprador ejerce. El comprador paga al vendedor una prima por ese derecho.<sup>[[4]](#references)</sup>

### 1. **Obligación frente a derecho:**

* **Futuros:** Cuando compras o vendes un contrato de futuros, estás entrando en un **acuerdo vinculante** para comprar o vender un activo a un precio específico en una fecha futura. Tanto el comprador como el vendedor están **obligados** a cumplir el contrato al vencimiento (salvo que el contrato se cierre antes).
* **Opciones:** Con las opciones, tienes el **derecho, pero no la obligación**, de comprar (en el caso de una **opción call**) o vender (en el caso de una **opción put**) un activo a un precio específico antes de una fecha de vencimiento determinada o en ella. El **comprador** tiene la opción de ejecutar, mientras que el **vendedor** está obligado a cumplir la operación si el comprador decide ejercer la opción.

### 2. **Riesgo:**

* **Futuros:** Ambas partes pueden sufrir pérdidas sustanciales. Que la pérdida sea matemáticamente ilimitada depende de la posición y del activo subyacente: una posición short puede tener una pérdida teórica ilimitada, mientras que una posición long no puede perder más que el valor nocional si el subyacente no puede caer por debajo de cero.
* **Opciones:** Un comprador que no venda otra opción generalmente arriesga la prima pagada. El vendedor de una call naked puede enfrentarse a una pérdida teóricamente ilimitada; otras estrategias de venta de opciones tienen perfiles de riesgo limitados o ilimitados diferentes.

### 3. **Coste:**

* **Futuros:** No hay un coste inicial aparte del margen necesario para mantener la posición, ya que tanto el comprador como el vendedor están obligados a completar la operación.
* **Opciones:** El comprador debe pagar por adelantado una **prima de opción** por el derecho a ejercerla. Esta prima es esencialmente el coste de la opción.

### 4. **Potencial de beneficios:**

* **Futuros:** La ganancia o pérdida se basa en la diferencia entre el precio de mercado al vencimiento y el precio acordado en el contrato.
* **Opciones:** El comprador obtiene beneficios cuando el mercado se mueve favorablemente más allá del precio de ejercicio por un importe superior a la prima pagada. El vendedor obtiene beneficios al conservar la prima si la opción no se ejerce.

## References

- [1] [CFTC - El propósito económico de los mercados de futuros](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Conceptos básicos del mercado de futuros](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Comprender los riesgos del trading de monedas virtuales](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [Glosario de la CFTC - Opción, prima y ejercicio](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../banners/hacktricks-training.md}}
