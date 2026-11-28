# Términos de inversión

{{#include ../../banners/hacktricks-training.md}}

## Al contado

El trading al contado intercambia un activo para su entrega inmediata. Una orden limitada especifica la cantidad y el precio límite; solo se ejecuta cuando el mercado puede satisfacer ese precio o uno mejor. En cambio, una orden de mercado busca ejecutarse de inmediato a los mejores precios disponibles en ese momento y puede experimentar deslizamiento.<sup>[[4]](#references)</sup>

Una orden stop-limit tiene un precio stop que activa una orden limitada. Puede restringir el precio de ejecución, pero no garantiza que se ejecute si el mercado supera el límite.<sup>[[4]](#references)</sup>

## Futuros

Un contrato de futuros es un acuerdo estandarizado para comprar o vender una materia prima o un instrumento financiero determinado en una fecha futura. Por ejemplo, dos partes podrían acordar un precio de $70,000 por un bitcoin, con liquidación dentro de seis meses.<sup>[[1]](#references)</sup>

Si el precio de liquidación es de $80,000, la posición larga obtiene ganancias y la corta pierde en relación con el precio contractual de $70,000. Si es de $60,000, ocurre lo contrario. Los futuros negociados en bolsa se valoran a mercado y suelen cerrarse o renovarse antes de su vencimiento, por lo que este es un ejemplo simplificado.<sup>[[2]](#references)</sup>

Los productores y consumidores usan futuros para cubrir el riesgo de precio; otros participantes los usan para buscar ganancias o proporcionar liquidez.<sup>[[1]](#references)</sup>

- Una **posición larga** generalmente obtiene ganancias cuando sube el precio del contrato.
- Una **posición corta** generalmente obtiene ganancias cuando baja el precio del contrato.<sup>[[2]](#references)</sup>

### Cobertura con futuros

Si un gestor de fondos espera que una cartera pierda valor, podría vender en corto un contrato de futuros sobre un índice bursátil con suficiente correlación. Las ganancias de la cobertura corta pueden compensar parte de las pérdidas de la cartera; el riesgo de base implica que la compensación rara vez es exacta. Un futuro de bitcoin cubriría la exposición al bitcoin, no automáticamente una cartera de acciones.

Si el mercado cubierto cae, la posición corta en futuros podría generar ganancias mientras las tenencias pierden valor. Si sube, las tenencias podrían ganar valor mientras la cobertura pierde. La cobertura reduce riesgos específicos, pero no garantiza ganancias.<sup>[[1]](#references)</sup>

### Futuros perpetuos

Los contratos perpetuos son derivados sin una fecha de vencimiento fija. Las plataformas de criptomonedas suelen usar pagos periódicos de financiación para ayudar a mantener su precio cerca del precio al contado subyacente; las condiciones varían según la plataforma.<sup>[[3]](#references)</sup>

Para pruebas de abuso de la tasa de financiación en protocolos perpetuos on-chain, consulta [Explotación de la tasa de financiación de perpetuos](perpetual-funding-rate-exploitation.md).

Las ganancias y pérdidas varían a medida que cambia el precio de referencia. Un movimiento del precio del 1% genera aproximadamente un movimiento del 1% en el valor nocional de la posición, antes de comisiones y pagos de financiación, pero el apalancamiento puede hacer que ese cambio represente un porcentaje mucho mayor del colateral aportado.

### Futuros con apalancamiento

El **apalancamiento** permite a un trader controlar una posición nocional mayor con un depósito de margen menor. Las pérdidas no siempre se limitan al margen inicial: las liquidaciones, los movimientos bruscos, las comisiones y las reglas de la plataforma pueden generar pérdidas adicionales.<sup>[[3]](#references)</sup>

Por ejemplo, $100 de margen con un apalancamiento de 50x controlan una posición de $5,000. Sin tener en cuenta las comisiones, la financiación ni los mecanismos de liquidación, un movimiento favorable del 1% genera una ganancia de $50 (el 50% del margen inicial), mientras que un movimiento desfavorable del 1% genera una pérdida de $50. Un movimiento desfavorable del 2% equivale a $100, aunque normalmente la plataforma liquidará la posición antes de que se agote todo el margen.

El apalancamiento amplifica tanto las ganancias como las pérdidas y hace posible la liquidación tras un movimiento desfavorable relativamente pequeño.

## Diferencias entre futuros y opciones

El comprador de una opción recibe el derecho, pero no la obligación, de ejercerla conforme a las condiciones del contrato. El emisor de la opción tiene la obligación correspondiente si el comprador la ejerce. El comprador paga al emisor una prima por ese derecho.<sup>[[4]](#references)</sup>

### 1. **Obligación frente a derecho:**

* **Futuros:** Al comprar o vender un contrato de futuros, celebras un **acuerdo vinculante** para comprar o vender un activo a un precio específico en una fecha futura. Tanto el comprador como el vendedor están **obligados** a cumplir el contrato al vencimiento (a menos que se cierre antes).
* **Opciones:** Con las opciones, tienes el **derecho, pero no la obligación**, de comprar (en el caso de una **opción call**) o vender (en el caso de una **opción put**) un activo a un precio específico antes de una fecha de vencimiento determinada o en esa fecha. El **comprador** tiene la opción de ejecutar la operación, mientras que el **vendedor** está obligado a cumplirla si el comprador decide ejercer la opción.

### 2. **Riesgo:**

* **Futuros:** Ambas partes pueden sufrir pérdidas considerables. Que la pérdida sea matemáticamente ilimitada depende de la posición y del activo subyacente: una posición corta puede tener una pérdida teórica ilimitada, mientras que una posición larga no puede perder más que el valor nocional si el activo subyacente no puede caer por debajo de cero.
* **Opciones:** Un comprador que no emite otra opción generalmente arriesga la prima pagada. Quien emite una opción call descubierta puede afrontar pérdidas teóricamente ilimitadas; otras estrategias de emisión de opciones tienen perfiles de riesgo limitados o ilimitados diferentes.

### 3. **Costo:**

* **Futuros:** No hay un costo inicial aparte del margen requerido para mantener la posición, ya que tanto el comprador como el vendedor están obligados a completar la operación.
* **Opciones:** El comprador debe pagar por adelantado una **prima de opción** por el derecho a ejercerla. Esta prima es, en esencia, el costo de la opción.

### 4. **Potencial de ganancias:**

* **Futuros:** Las ganancias o pérdidas se basan en la diferencia entre el precio de mercado al vencimiento y el precio acordado en el contrato.
* **Opciones:** El comprador obtiene ganancias cuando el mercado se mueve a su favor más allá del precio de ejercicio por un importe superior a la prima pagada. El vendedor obtiene ganancias al quedarse con la prima si no se ejerce la opción.

## References

- [1] [CFTC - El propósito económico de los mercados de futuros](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Conceptos básicos del mercado de futuros](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Comprender los riesgos del trading de monedas virtuales](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [Glosario de la CFTC - Opción, prima y ejercicio](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}
