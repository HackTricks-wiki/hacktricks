# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)es un analizador de señales digitales gratuito para GNU/Linux y macOS, diseñado para extraer información de señales de radio desconocidas. Soporta una variedad de dispositivos SDR a través de SoapySDR, y permite la demodulación ajustable de señales FSK, PSK y ASK, decodificar video analógico, analizar señales intermitentes y escuchar canales de voz analógicos (todo en tiempo real).

### Configuración básica

Después de instalar, hay algunas cosas que podrías considerar configurar.\
En la configuración (el segundo botón de pestaña) puedes seleccionar el **dispositivo SDR** o **seleccionar un archivo** para leer y qué frecuencia sintonizar y la tasa de muestreo (se recomienda hasta 2.56Msps si tu PC lo soporta)\\

![](<../../images/image (245).png>)

En el comportamiento de la GUI, se recomienda habilitar algunas cosas si tu PC lo soporta:

![](<../../images/image (472).png>)

> [!NOTE]
> Si te das cuenta de que tu PC no está capturando cosas, intenta deshabilitar OpenGL y reducir la tasa de muestreo.

### Usos

- Solo para **capturar algún tiempo de una señal y analizarla**, mantén presionado el botón "Push to capture" tanto tiempo como necesites.

![](<../../images/image (960).png>)

- El **sintonizador** de SigDigger ayuda a **capturar mejores señales** (pero también puede degradarlas). Idealmente comienza con 0 y sigue **aumentándolo hasta** que encuentres que el **ruido** introducido es **mayor** que la **mejora de la señal** que necesitas).

![](<../../images/image (1099).png>)

### Sincronizar con el canal de radio

Con [**SigDigger** ](https://github.com/BatchDrake/SigDigger)sincroniza con el canal que deseas escuchar, configura la opción "Baseband audio preview", configura el ancho de banda para obtener toda la información que se envía y luego ajusta el sintonizador al nivel antes de que el ruido comience a aumentar realmente:

![](<../../images/image (585).png>)

## Trucos interesantes

- Cuando un dispositivo está enviando ráfagas de información, generalmente la **primera parte será un preámbulo**, así que **no** necesitas **preocuparte** si **no encuentras información** allí **o si hay algunos errores**.
- En los tramos de información, generalmente deberías **encontrar diferentes tramos bien alineados entre sí**:

![](<../../images/image (1076).png>)

![](<../../images/image (597).png>)

- **Después de recuperar los bits, es posible que necesites procesarlos de alguna manera**. Por ejemplo, en la codificación Manchester, un up+down será un 1 o 0 y un down+up será el otro. Así que pares de 1s y 0s (ups y downs) serán un 1 real o un 0 real.
- Incluso si una señal está usando codificación Manchester (es imposible encontrar más de dos 0s o 1s en fila), ¡podrías **encontrar varios 1s o 0s juntos en el preámbulo**!

### Descubriendo el tipo de modulación con IQ

Hay 3 formas de almacenar información en señales: modulando la **amplitud**, **frecuencia** o **fase**.\
Si estás revisando una señal, hay diferentes formas de intentar averiguar qué se está utilizando para almacenar información (encuentra más formas a continuación), pero una buena es revisar el gráfico IQ.

![](<../../images/image (788).png>)

- **Detectando AM**: Si en el gráfico IQ aparecen, por ejemplo, **2 círculos** (probablemente uno en 0 y otro en una amplitud diferente), podría significar que esta es una señal AM. Esto se debe a que en el gráfico IQ la distancia entre el 0 y el círculo es la amplitud de la señal, por lo que es fácil visualizar diferentes amplitudes siendo utilizadas.
- **Detectando PM**: Al igual que en la imagen anterior, si encuentras pequeños círculos no relacionados entre sí, probablemente significa que se está utilizando una modulación de fase. Esto se debe a que en el gráfico IQ, el ángulo entre el punto y el 0,0 es la fase de la señal, lo que significa que se están utilizando 4 fases diferentes.
- Ten en cuenta que si la información está oculta en el hecho de que se cambia una fase y no en la fase misma, no verás diferentes fases claramente diferenciadas.
- **Detectando FM**: IQ no tiene un campo para identificar frecuencias (la distancia al centro es amplitud y el ángulo es fase).\
Por lo tanto, para identificar FM, deberías **ver básicamente un círculo** en este gráfico.\
Además, una frecuencia diferente es "representada" por el gráfico IQ mediante una **aceleración de velocidad a través del círculo** (así que en SysDigger, al seleccionar la señal, el gráfico IQ se llena; si encuentras una aceleración o cambio de dirección en el círculo creado, podría significar que esto es FM):

## Ejemplo de AM

{% file src="../../images/sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw" %}

### Descubriendo AM

#### Revisando la envoltura

Revisando la información AM con [**SigDigger** ](https://github.com/BatchDrake/SigDigger)y solo mirando la **envoltura**, puedes ver diferentes niveles de amplitud claros. La señal utilizada está enviando pulsos con información en AM, así es como se ve un pulso:

![](<../../images/image (590).png>)

Y así es como se ve parte del símbolo con la forma de onda:

![](<../../images/image (734).png>)

#### Revisando el histograma

Puedes **seleccionar toda la señal** donde se encuentra la información, seleccionar el modo **Amplitud** y **Selección** y hacer clic en **Histograma**. Puedes observar que solo se encuentran 2 niveles claros.

![](<../../images/image (264).png>)

Por ejemplo, si seleccionas Frecuencia en lugar de Amplitud en esta señal AM, solo encuentras 1 frecuencia (no hay forma de que la información modulada en frecuencia esté usando solo 1 frecuencia).

![](<../../images/image (732).png>)

Si encuentras muchas frecuencias, potencialmente esto no será un FM; probablemente la frecuencia de la señal solo se modificó debido al canal.

#### Con IQ

En este ejemplo puedes ver cómo hay un **gran círculo** pero también **muchos puntos en el centro.**

![](<../../images/image (222).png>)

### Obtener la tasa de símbolos

#### Con un símbolo

Selecciona el símbolo más pequeño que puedas encontrar (así te aseguras de que sea solo 1) y revisa la "Frecuencia de selección". En este caso sería 1.013kHz (así que 1kHz).

![](<../../images/image (78).png>)

#### Con un grupo de símbolos

También puedes indicar el número de símbolos que vas a seleccionar y SigDigger calculará la frecuencia de 1 símbolo (cuantos más símbolos seleccionados, mejor probablemente). En este escenario seleccioné 10 símbolos y la "Frecuencia de selección" es 1.004 Khz:

![](<../../images/image (1008).png>)

### Obtener bits

Habiendo encontrado que esta es una señal **modulada en AM** y la **tasa de símbolos** (y sabiendo que en este caso algo up significa 1 y algo down significa 0), es muy fácil **obtener los bits** codificados en la señal. Así que, selecciona la señal con información y configura el muestreo y la decisión y presiona muestrear (verifica que **Amplitud** esté seleccionada, que la **Tasa de símbolos** descubierta esté configurada y que la **recuperación de reloj de Gardner** esté seleccionada):

![](<../../images/image (965).png>)

- **Sincronizar a intervalos de selección** significa que si previamente seleccionaste intervalos para encontrar la tasa de símbolos, esa tasa de símbolos se utilizará.
- **Manual** significa que se utilizará la tasa de símbolos indicada.
- En **Selección de intervalo fijo** indicas el número de intervalos que deben seleccionarse y calcula la tasa de símbolos a partir de ello.
- **Recuperación de reloj de Gardner** suele ser la mejor opción, pero aún necesitas indicar alguna tasa de símbolos aproximada.

Al presionar muestrear, esto aparece:

![](<../../images/image (644).png>)

Ahora, para hacer que SigDigger entienda **dónde está el rango** del nivel que lleva información, necesitas hacer clic en el **nivel más bajo** y mantener presionado hasta el nivel más alto:

![](<../../images/image (439).png>)

Si hubiera habido, por ejemplo, **4 niveles diferentes de amplitud**, deberías haber configurado los **Bits por símbolo a 2** y seleccionar desde el más pequeño hasta el más grande.

Finalmente, **aumentando** el **Zoom** y **cambiando el tamaño de fila**, puedes ver los bits (y puedes seleccionar todo y copiar para obtener todos los bits):

![](<../../images/image (276).png>)

Si la señal tiene más de 1 bit por símbolo (por ejemplo, 2), SigDigger **no tiene forma de saber qué símbolo es** 00, 01, 10, 11, así que usará diferentes **escalas de grises** para representar cada uno (y si copias los bits, usará **números del 0 al 3**, necesitarás tratarlos).

Además, usa **codificaciones** como **Manchester**, y **up+down** puede ser **1 o 0** y un down+up puede ser un 1 o 0. En esos casos, necesitas **tratar los ups (1) y downs (0) obtenidos** para sustituir los pares de 01 o 10 como 0s o 1s.

## Ejemplo de FM

{% file src="../../images/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Descubriendo FM

#### Revisando las frecuencias y la forma de onda

Ejemplo de señal enviando información modulada en FM:

![](<../../images/image (725).png>)

En la imagen anterior puedes observar bastante bien que **se utilizan 2 frecuencias**, pero si **observas** la **forma de onda**, es posible que **no puedas identificar correctamente las 2 frecuencias diferentes**:

![](<../../images/image (717).png>)

Esto se debe a que capturé la señal en ambas frecuencias, por lo tanto, una es aproximadamente la otra en negativo:

![](<../../images/image (942).png>)

Si la frecuencia sincronizada está **más cerca de una frecuencia que de la otra**, puedes ver fácilmente las 2 frecuencias diferentes:

![](<../../images/image (422).png>)

![](<../../images/image (488).png>)

#### Revisando el histograma

Revisando el histograma de frecuencia de la señal con información, puedes ver fácilmente 2 señales diferentes:

![](<../../images/image (871).png>)

En este caso, si revisas el **histograma de Amplitud**, encontrarás **solo una amplitud**, así que **no puede ser AM** (si encuentras muchas amplitudes, podría ser porque la señal ha estado perdiendo potencia a lo largo del canal):

![](<../../images/image (817).png>)

Y este sería el histograma de fase (que deja muy claro que la señal no está modulada en fase):

![](<../../images/image (996).png>)

#### Con IQ

IQ no tiene un campo para identificar frecuencias (la distancia al centro es amplitud y el ángulo es fase).\
Por lo tanto, para identificar FM, deberías **ver básicamente un círculo** en este gráfico.\
Además, una frecuencia diferente es "representada" por el gráfico IQ mediante una **aceleración de velocidad a través del círculo** (así que en SysDigger, al seleccionar la señal, el gráfico IQ se llena; si encuentras una aceleración o cambio de dirección en el círculo creado, podría significar que esto es FM):

![](<../../images/image (81).png>)

### Obtener la tasa de símbolos

Puedes usar la **misma técnica que la utilizada en el ejemplo de AM** para obtener la tasa de símbolos una vez que hayas encontrado las frecuencias que llevan símbolos.

### Obtener bits

Puedes usar la **misma técnica que la utilizada en el ejemplo de AM** para obtener los bits una vez que hayas **encontrado que la señal está modulada en frecuencia** y la **tasa de símbolos**.

{{#include ../../banners/hacktricks-training.md}}
