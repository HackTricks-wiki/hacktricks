# Términos de inversión

{{#include ../banners/hacktricks-training.md}}

## Spot

Esta es la forma más básica de hacer trading. Puedes **indicar la cantidad del activo y el precio** al que quieres comprarlo o venderlo, y cuando se alcance ese precio, se realiza la operación.

Normalmente también puedes usar el **precio actual del mercado** para realizar la transacción lo más rápido posible al precio vigente.

**Stop Loss - Limit**: También puedes indicar la cantidad y el precio de los activos que quieres comprar o vender, además de indicar un precio inferior para comprar o vender en caso de que se alcance (para detener las pérdidas).

## Futuros

Un futuro es un contrato mediante el cual 2 partes llegan a un acuerdo para **adquirir algo en el futuro a un precio fijo**. Por ejemplo, vender 1 bitcoin dentro de 6 meses por 70.000$.

Obviamente, si después de 6 meses el valor del bitcoin es de 80.000$, la parte vendedora pierde dinero y la parte compradora lo gana. Si después de 6 meses el valor del bitcoin es de 60.000$, ocurre lo contrario.

Sin embargo, esto resulta interesante, por ejemplo, para empresas que generan un producto y necesitan tener la seguridad de que podrán venderlo a un precio que les permita cubrir los costes. También para empresas que quieren garantizar precios fijos en el futuro para algo, aunque sean más altos.

Aunque en los exchanges normalmente se utiliza para intentar obtener beneficios.

* Ten en cuenta que una "posición Long" significa que alguien está apostando a que el precio va a aumentar
* Mientras que una "posición short" significa que alguien está apostando a que el precio va a bajar

### Cobertura con futuros <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Si un gestor de fondos teme que algunas acciones vayan a bajar, podría abrir una posición short sobre algunos activos, como bitcoins o contratos de futuros del S\&P 500. Esto sería similar a comprar o poseer algunos activos y crear un contrato para venderlos en el futuro a un precio mayor.

En caso de que el precio baje, el gestor de fondos obtendrá beneficios porque venderá los activos a un precio mayor. Si el precio de los activos sube, el gestor no obtendrá ese beneficio, pero conservará sus activos.

### Futuros perpetuos

**Estos son "futuros" que duran indefinidamente** (sin una fecha de finalización del contrato). Es muy común encontrarlos, por ejemplo, en exchanges de criptomonedas, donde puedes entrar y salir de futuros en función del precio de las criptomonedas.

Ten en cuenta que, en estos casos, las ganancias y las pérdidas pueden producirse en tiempo real: si el precio aumenta un 1%, ganas un 1%; si el precio disminuye un 1%, lo pierdes.

### Futuros con apalancamiento

El **apalancamiento** te permite controlar una posición mayor en el mercado con una cantidad menor de dinero. Básicamente, te permite "apostar" mucho más dinero del que tienes, arriesgando únicamente el dinero que realmente posees.

Por ejemplo, si abres una posición de futuros en BTC/USDT con 100$ y un apalancamiento de 50x, esto significa que, si el precio aumenta un 1%, ganarías 1x50 = el 50% de tu inversión inicial (50$). Y, por tanto, tendrías 150$.\
Sin embargo, si el precio disminuye un 1%, perderías el 50% de tus fondos (59$ en este caso). Y si el precio disminuye un 2%, perderías toda tu apuesta (2x50 = 100%).

Por tanto, el apalancamiento permite controlar la cantidad de dinero que apuestas, al tiempo que aumenta las ganancias y las pérdidas.

## Diferencias entre futuros y opciones

La principal diferencia entre futuros y opciones es que el contrato es opcional para el comprador: puede decidir ejecutarlo o no (normalmente solo lo hará si obtiene un beneficio). El vendedor debe vender si el comprador quiere utilizar la opción.\
Sin embargo, el comprador pagará una comisión al vendedor por abrir la opción (por lo que el vendedor, que aparentemente asume más riesgo, empieza a obtener algo de dinero).

### 1. **Obligación frente a derecho:**

* **Futuros:** Cuando compras o vendes un contrato de futuros, estás entrando en un **acuerdo vinculante** para comprar o vender un activo a un precio específico en una fecha futura. Tanto el comprador como el vendedor están **obligados** a cumplir el contrato al vencimiento (a menos que el contrato se cierre antes).
* **Opciones:** Con las opciones, tienes el **derecho, pero no la obligación**, de comprar (en el caso de una **opción call**) o vender (en el caso de una **opción put**) un activo a un precio específico antes de una fecha de vencimiento determinada o en ella. El **comprador** tiene la opción de ejecutar el contrato, mientras que el **vendedor** está obligado a realizar la operación si el comprador decide ejercer la opción.

### 2. **Riesgo:**

* **Futuros:** Tanto el comprador como el vendedor asumen un **riesgo ilimitado** porque están obligados a completar el contrato. El riesgo es la diferencia entre el precio acordado y el precio de mercado en la fecha de vencimiento.
* **Opciones:** El riesgo del comprador está limitado a la **prima** pagada para adquirir la opción. Si el mercado no se mueve a favor del titular de la opción, este puede simplemente dejar que la opción expire. Sin embargo, el **vendedor** (emisor) de la opción tiene un riesgo ilimitado si el mercado se mueve significativamente en su contra.

### 3. **Coste:**

* **Futuros:** No hay ningún coste inicial aparte del margen necesario para mantener la posición, ya que tanto el comprador como el vendedor están obligados a completar la operación.
* **Opciones:** El comprador debe pagar por adelantado una **prima de opción** por el derecho a ejercer la opción. Esta prima es, esencialmente, el coste de la opción.

### 4. **Potencial de beneficios:**

* **Futuros:** El beneficio o la pérdida se basa en la diferencia entre el precio de mercado al vencimiento y el precio acordado en el contrato.
* **Opciones:** El comprador obtiene beneficios cuando el mercado se mueve favorablemente más allá del precio de ejercicio por un importe superior a la prima pagada. El vendedor obtiene beneficios al conservar la prima si la opción no se ejerce.

{{#include ../banners/hacktricks-training.md}}
