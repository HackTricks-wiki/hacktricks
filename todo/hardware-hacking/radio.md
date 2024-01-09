# Radio

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) es un analizador de señales digitales gratuito para GNU/Linux y macOS, diseñado para extraer información de señales de radio desconocidas. Soporta una variedad de dispositivos SDR a través de SoapySDR, y permite la demodulación ajustable de señales FSK, PSK y ASK, decodificar video analógico, analizar señales intermitentes y escuchar canales de voz analógicos (todo en tiempo real).

### Configuración Básica

Después de instalar hay algunas cosas que podrías considerar configurar.\
En ajustes (el segundo botón de la pestaña) puedes seleccionar el **dispositivo SDR** o **seleccionar un archivo** para leer y qué frecuencia sintonizar y la tasa de muestreo (recomendado hasta 2.56Msps si tu PC lo soporta)\\

![](<../../.gitbook/assets/image (655) (1).png>)

En el comportamiento de la GUI se recomienda habilitar algunas cosas si tu PC lo soporta:

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
Si te das cuenta de que tu PC no está capturando cosas, intenta desactivar OpenGL y reducir la tasa de muestreo.
{% endhint %}

### Usos

* Solo para **capturar algún tiempo de una señal y analizarla** mantén presionado el botón "Push to capture" tanto tiempo como necesites.

![](<../../.gitbook/assets/image (631).png>)

* El **Tuner** de SigDigger ayuda a **capturar mejores señales** (pero también puede degradarlas). Idealmente comienza con 0 y sigue **aumentándolo hasta** que encuentres que el **ruido** introducido es **mayor** que la **mejora de la señal** que necesitas).

![](<../../.gitbook/assets/image (658).png>)

### Sincronizar con canal de radio

Con [**SigDigger**](https://github.com/BatchDrake/SigDigger) sincroniza con el canal que quieras escuchar, configura la opción "Vista previa de audio de banda base", configura el ancho de banda para obtener toda la información enviada y luego ajusta el Tuner al nivel antes de que el ruido realmente comience a aumentar:

![](<../../.gitbook/assets/image (389).png>)

## Trucos Interesantes

* Cuando un dispositivo está enviando ráfagas de información, generalmente **la primera parte va a ser un preámbulo** así que **no te preocupes** si **no encuentras información** allí **o si hay algunos errores**.
* En marcos de información generalmente deberías **encontrar diferentes marcos bien alineados entre ellos**:

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **Después de recuperar los bits es posible que necesites procesarlos de alguna manera**. Por ejemplo, en la codificación Manchester un subida+bajada será un 1 o 0 y una bajada+subida será el otro. Así que pares de 1s y 0s (subidas y bajadas) serán un 1 o un 0 real.
* Incluso si una señal está usando codificación Manchester (es imposible encontrar más de dos 0s o 1s seguidos), podrías **encontrar varios 1s o 0s juntos en el preámbulo**.

### Descubriendo el tipo de modulación con IQ

Hay 3 maneras de almacenar información en señales: Modulando la **amplitud**, **frecuencia** o **fase**.\
Si estás revisando una señal hay diferentes maneras de intentar averiguar qué se está utilizando para almacenar información (encuentra más maneras abajo) pero una buena es revisar el gráfico IQ.

![](<../../.gitbook/assets/image (630).png>)

* **Detectando AM**: Si en el gráfico IQ aparecen por ejemplo **2 círculos** (probablemente uno en 0 y otro en una amplitud diferente), podría significar que esta es una señal AM. Esto se debe a que en el gráfico IQ la distancia entre el 0 y el círculo es la amplitud de la señal, por lo que es fácil visualizar diferentes amplitudes utilizadas.
* **Detectando PM**: Como en la imagen anterior, si encuentras pequeños círculos no relacionados entre sí probablemente significa que se utiliza una modulación de fase. Esto se debe a que en el gráfico IQ, el ángulo entre el punto y el 0,0 es la fase de la señal, lo que significa que se utilizan 4 fases diferentes.
* Ten en cuenta que si la información está oculta en el hecho de que una fase cambia y no en la fase en sí, no verás diferentes fases claramente diferenciadas.
* **Detectando FM**: IQ no tiene un campo para identificar frecuencias (la distancia al centro es amplitud y el ángulo es fase).\
Por lo tanto, para identificar FM, deberías **ver básicamente un círculo** en este gráfico.\
Además, una frecuencia diferente está "representada" en el gráfico IQ por una **aceleración de velocidad a través del círculo** (así que en SysDigger seleccionando la señal el gráfico IQ se llena, si encuentras una aceleración o cambio de dirección en el círculo creado podría significar que esto es FM):

## Ejemplo AM

{% file src="../../.gitbook/assets/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Descubriendo AM

#### Revisando el sobre

Revisando la información AM con [**SigDigger**](https://github.com/BatchDrake/SigDigger) y simplemente mirando el **sobre** puedes ver diferentes niveles claros de amplitud. La señal utilizada está enviando pulsos con información en AM, así es como se ve un pulso:

![](<../../.gitbook/assets/image (636).png>)

Y así es como parte del símbolo se ve con la forma de onda:

![](<../../.gitbook/assets/image (650) (1).png>)

#### Revisando el Histograma

Puedes **seleccionar toda la señal** donde se encuentra la información, seleccionar el modo **Amplitud** y **Selección** y hacer clic en **Histograma**. Puedes observar que solo se encuentran 2 niveles claros

![](<../../.gitbook/assets/image (647) (1) (1).png>)

Por ejemplo, si seleccionas Frecuencia en lugar de Amplitud en esta señal AM encontrarás solo 1 frecuencia (no hay manera de que la información modulada en frecuencia esté usando solo 1 frecuencia).

![](<../../.gitbook/assets/image (637) (1) (1).png>)

Si encuentras muchas frecuencias potencialmente esto no será una FM, probablemente la frecuencia de la señal fue modificada debido al canal.

#### Con IQ

En este ejemplo puedes ver cómo hay un **gran círculo** pero también **muchos puntos en el centro**.

![](<../../.gitbook/assets/image (640).png>)

### Obtener Tasa de Símbolos

#### Con un símbolo

Selecciona el símbolo más pequeño que puedas encontrar (para estar seguro de que es solo 1) y revisa la "Frecuencia de selección". En este caso sería 1.013kHz (así que 1kHz).

![](<../../.gitbook/assets/image (638) (1).png>)

#### Con un grupo de símbolos

También puedes indicar el número de símbolos que vas a seleccionar y SigDigger calculará la frecuencia de 1 símbolo (cuantos más símbolos seleccionados probablemente mejor). En este escenario seleccioné 10 símbolos y la "Frecuencia de selección" es 1.004 Khz:

![](<../../.gitbook/assets/image (635).png>)

### Obtener Bits

Habiendo encontrado que esta es una señal **modulada en AM** y la **tasa de símbolos** (y sabiendo que en este caso algo hacia arriba significa 1 y algo hacia abajo significa 0), es muy fácil **obtener los bits** codificados en la señal. Entonces, selecciona la señal con información y configura el muestreo y la decisión y presiona muestrear (verifica que **Amplitud** esté seleccionado, la **Tasa de Símbolos** descubierta esté configurada y la **recuperación de reloj de Gadner** esté seleccionada):

![](<../../.gitbook/assets/image (642) (1).png>)

* **Sincronizar con intervalos de selección** significa que si previamente seleccionaste intervalos para encontrar la tasa de símbolos, esa tasa de símbolos se usará.
* **Manual** significa que se va a usar la tasa de símbolos indicada
* En **Selección de intervalo fijo** indicas el número de intervalos que se deben seleccionar y calcula la tasa de símbolos a partir de ello
* **Recuperación de reloj de Gadner** suele ser la mejor opción, pero aún necesitas indicar alguna tasa de símbolos aproximada.

Al presionar muestrear aparece esto:

![](<../../.gitbook/assets/image (659).png>)

Ahora, para hacer que SigDigger entienda **dónde está el rango** del nivel que lleva información necesitas hacer clic en el **nivel más bajo** y mantenerlo presionado hasta el nivel más alto:

![](<../../.gitbook/assets/image (662) (1) (1) (1).png>)

Si hubiera habido por ejemplo **4 niveles diferentes de amplitud**, deberías haber necesitado configurar los **Bits por símbolo a 2** y seleccionar desde el más pequeño hasta el más grande.

Finalmente **aumentando** el **Zoom** y **cambiando el Tamaño de Fila** puedes ver los bits (y puedes seleccionar todo y copiar para obtener todos los bits):

![](<../../.gitbook/assets/image (649) (1).png>)

Si la señal tiene más de 1 bit por símbolo (por ejemplo 2), SigDigger **no tiene forma de saber qué símbolo es** 00, 01, 10, 11, por lo que usará diferentes **escalas de grises** para representar cada uno (y si copias los bits usará **números del 0 al 3**, necesitarás tratarlos).

Además, usa **codificaciones** como **Manchester**, y **subida+bajada** puede ser **1 o 0** y una bajada+subida puede ser un 1 o 0. En esos casos necesitas **tratar los subidas (1) y bajadas (0) obtenidos** para sustituir los pares de 01 o 10 como 0s o 1s.

## Ejemplo FM

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Descubriendo FM

#### Revisando las frecuencias y la forma de onda

Ejemplo de señal enviando información modulada en FM:

![](<../../.gitbook/assets/image (661) (1).png>)

En la imagen anterior puedes observar bastante bien que **se utilizan 2 frecuencias** pero si **observas** la **forma de onda** podrías **no ser capaz de identificar correctamente las 2 frecuencias diferentes**:

![](<../../.gitbook/assets/image (653).png>)

Esto se debe a que capturé la señal en ambas frecuencias, por lo tanto, una es aproximadamente la otra en negativo:

![](<../../.gitbook/assets/image (656).png>)

Si la frecuencia sincronizada está **más cerca de una frecuencia que de la otra** puedes ver fácilmente las 2 frecuencias diferentes:

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### Revisando el histograma

Revisando el histograma de frecuencias de la señal con información puedes ver fácilmente 2 señales diferentes:

![](<../../.gitbook/assets/image (657).png>)

En este caso si revisas el **histograma de Amplitud** encontrarás **solo una amplitud**, por lo que **no puede ser AM** (si encuentras muchas amplitudes podría ser porque la señal ha estado perdiendo potencia a lo largo del canal):

![](<../../.gitbook/assets/image (646).png>)

Y este sería el histograma de fase (que deja muy claro que la señal no está modulada en fase):

![](<../../.gitbook/assets/image (201) (2).png>)

#### Con IQ

IQ no tiene un campo para identificar frecuencias (la distancia al centro es amplitud y el ángulo es fase).\
Por lo tanto, para identificar FM, deberías **ver básicamente un círculo** en este gráfico.\
Además, una frecuencia diferente está "representada" en el gráfico IQ por una **aceleración de velocidad a través del círculo** (así que en SysDigger seleccionando la señal el gráfico IQ se llena, si encuentras una aceleración o cambio de dirección en el círculo creado podría significar que esto es FM):

![](<../../.gitbook/assets/image (643) (1).png>)

### Obtener Tasa de Símbolos

Puedes usar la **misma técnica que la utilizada en el ejemplo AM** para obtener la tasa de símbolos una vez que hayas encontrado las frecuencias que llevan símbolos.

### Obtener Bits

Puedes usar la **misma técnica que la utilizada en el ejemplo AM** para obtener los bits una vez que hayas **encontrado que la señal está modulada en frecuencia** y la **tasa de símbolos**.

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
