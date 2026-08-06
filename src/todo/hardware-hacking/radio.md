# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)es un analizador de señales digitales gratuito para GNU/Linux y macOS, diseñado para extraer información de señales de radio desconocidas. Es compatible con diversos dispositivos SDR mediante SoapySDR y permite demodular señales FSK, PSK y ASK de forma ajustable, decodificar vídeo analógico, analizar señales con ráfagas y escuchar canales de voz analógica (todo en tiempo real).<sup>[[1]](#references)</sup>

### Configuración básica

Después de instalarlo, hay algunos aspectos que puedes considerar configurar.\
En los ajustes (el segundo botón de pestaña) puedes seleccionar el **dispositivo SDR** o **seleccionar un archivo** que leer, así como la frecuencia que sintonizar y la tasa de muestreo (se recomienda hasta 2.56Msps si tu PC lo admite).

![Ajustes de SigDigger mostrando las opciones de dispositivo SDR, archivo de entrada, frecuencia y tasa de muestreo](<../../images/image (245).png>)

En el comportamiento de la GUI se recomienda activar algunas opciones si tu PC las admite:

![SigDigger - Configuración básica: en el comportamiento de la GUI se recomienda activar algunas opciones si tu PC las admite](<../../images/image (472).png>)

> [!TIP]
> Si notas que tu PC no captura información, prueba a desactivar OpenGL y reducir la tasa de muestreo.

### Usos

- Para **capturar durante un tiempo una señal y analizarla**, mantén pulsado el botón "Push to capture" durante el tiempo que necesites.

![Configuración básica - Usos: para capturar durante un tiempo una señal y analizarla, mantén pulsado el botón "Push to capture" durante el tiempo que necesites](<../../images/image (960).png>)

- El **Tuner** de SigDigger ayuda a **capturar mejores señales** (aunque también puede degradarlas). Lo ideal es empezar en 0 y **seguir aumentándolo hasta** que encuentres que el **ruido** introducido es **mayor** que la **mejora de la señal** que necesitas.

![Control Tuner de SigDigger ajustado para mejorar la señal de radio capturada](<../../images/image (1099).png>)

### Sincronizar con un canal de radio

Con [**SigDigger** ](https://github.com/BatchDrake/SigDigger), sincronízate con el canal que quieres escuchar, configura la opción "Baseband audio preview", configura el ancho de banda para obtener toda la información que se está enviando y, después, ajusta el Tuner al nivel anterior a que el ruido empiece a aumentar realmente:<sup>[[1]](#references)</sup>

![Canal de radio sincronizado en SigDigger con la previsualización de audio de banda base y el ancho de banda configurados](<../../images/image (585).png>)

## Trucos interesantes

- Cuando un dispositivo envía ráfagas de información, normalmente la **primera parte será un preámbulo**, así que **no necesitas preocuparte** si **no encuentras información** en ella **o si contiene algunos errores**.
- En las tramas de información normalmente deberías **encontrar diferentes tramas bien alineadas entre sí**:

![Sincronizar con un canal de radio - Trucos interesantes: en las tramas de información normalmente deberías encontrar diferentes tramas bien alineadas entre sí](<../../images/image (1076).png>)

![Sincronizar con un canal de radio - Trucos interesantes: en las tramas de información normalmente deberías encontrar diferentes tramas bien alineadas entre sí](<../../images/image (597).png>)

- **Después de recuperar los bits, puede que necesites procesarlos de alguna manera**. Por ejemplo, en la codificación Manchester, una subida+bajada será un 1 o un 0, y una bajada+subida será el otro valor. Por tanto, los pares de 1 y 0 (subidas y bajadas) serán un 1 real o un 0 real.
- Aunque una señal utilice codificación Manchester (es imposible encontrar más de dos 0 o 1 seguidos), ¡puedes **encontrar varios 1 o 0 juntos en el preámbulo**!

### Descubrir el tipo de modulación con IQ

Hay 3 formas de almacenar información en las señales: modular la **amplitud**, la **frecuencia** o la **fase**.\
Si estás comprobando una señal, hay diferentes formas de intentar averiguar cuál se utiliza para almacenar la información (consulta más formas abajo), pero una buena opción es comprobar el gráfico IQ.

![Gráfico IQ de SigDigger utilizado para identificar si una señal usa modulación de amplitud, frecuencia o fase](<../../images/image (788).png>)

- **Detectar AM**: Si en el gráfico IQ aparecen, por ejemplo, **2 círculos** (probablemente uno en 0 y otro con una amplitud diferente), podría significar que se trata de una señal AM. Esto se debe a que, en el gráfico IQ, la distancia entre el 0 y el círculo representa la amplitud de la señal, por lo que es fácil visualizar las diferentes amplitudes utilizadas.
- **Detectar PM**: Como en la imagen anterior, si encuentras círculos pequeños no relacionados entre sí, probablemente significa que se utiliza modulación de fase. Esto se debe a que, en el gráfico IQ, el ángulo entre el punto y el 0,0 representa la fase de la señal, lo que significa que se utilizan 4 fases diferentes.
- Ten en cuenta que, si la información está oculta en el hecho de que una fase cambia y no en la fase en sí, no verás las diferentes fases claramente diferenciadas.
- **Detectar FM**: IQ no tiene un campo para identificar frecuencias (la distancia al centro es la amplitud y el ángulo es la fase).\
Por tanto, para identificar FM, básicamente deberías **ver solo un círculo** en este gráfico.\
Además, una frecuencia diferente se "representa" en el gráfico IQ mediante una **aceleración de la velocidad a través del círculo** (así, al seleccionar la señal en SysDigger se rellena el gráfico IQ; si encuentras una aceleración o un cambio de dirección en el círculo creado, podría significar que se trata de FM):

## Ejemplo de AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Descubrir AM

#### Comprobar la envolvente

Al comprobar información AM con [**SigDigger** ](https://github.com/BatchDrake/SigDigger) y observar únicamente la **envolvente**, puedes ver diferentes niveles de amplitud claramente definidos. La señal utilizada envía pulsos con información en AM; así es como se ve un pulso:<sup>[[1]](#references)</sup>

![Envolvente de una señal AM en SigDigger con niveles claros de amplitud de los pulsos](<../../images/image (590).png>)

Y así es como se ve parte del símbolo con la forma de onda:

![Descubrir AM - Comprobar la envolvente: así es como se ve parte del símbolo con la forma de onda](<../../images/image (734).png>)

#### Comprobar el histograma

Puedes **seleccionar toda la señal** donde se encuentra la información, seleccionar el modo **Amplitude** y **Selection**, y hacer clic en **Histogram**. Puedes observar que solo se encuentran 2 niveles claros.

![Histograma de amplitud de SigDigger mostrando dos niveles claros para la señal AM seleccionada](<../../images/image (264).png>)

Por ejemplo, si seleccionas Frequency en lugar de Amplitude en esta señal AM, solo encontrarás 1 frecuencia (no tendría sentido que la información modulada en frecuencia utilizara una sola frecuencia).

![Histograma de frecuencia de SigDigger para la señal AM mostrando una frecuencia](<../../images/image (732).png>)

Si encuentras muchas frecuencias, probablemente no se trate de FM; seguramente la frecuencia de la señal simplemente se modificó debido al canal.

#### Con IQ

En este ejemplo puedes ver que hay un **círculo grande**, pero también **muchos puntos en el centro**.

![Comprobar el histograma - Con IQ: en este ejemplo puedes ver que hay un círculo grande, pero también muchos puntos en el centro](<../../images/image (222).png>)

### Obtener la tasa de símbolos

#### Con un símbolo

Selecciona el símbolo más pequeño que puedas encontrar (para asegurarte de que solo es 1) y comprueba "Selection freq". En este caso sería 1.013kHz (es decir, 1kHz).

![Obtener la tasa de símbolos - Con un símbolo: selecciona el símbolo más pequeño que puedas encontrar (para asegurarte de que solo es 1) y comprueba "Selection freq". En este caso sería 1.013kHz (es decir, 1kHz)](<../../images/image (78).png>)

#### Con un grupo de símbolos

También puedes indicar el número de símbolos que vas a seleccionar y SigDigger calculará la frecuencia de 1 símbolo (probablemente, cuantos más símbolos selecciones, mejor). En este escenario seleccioné 10 símbolos y "Selection freq" es 1.004 Khz:

![Cálculo de la tasa de símbolos en SigDigger utilizando un grupo seleccionado de diez símbolos](<../../images/image (1008).png>)

### Obtener los bits

Una vez descubierto que se trata de una señal **modulada en AM** y la **tasa de símbolos** (y sabiendo que, en este caso, algo que sube significa 1 y algo que baja significa 0), es muy fácil **obtener los bits** codificados en la señal. Selecciona la señal con información, configura el muestreo y la decisión, y pulsa sample (comprueba que **Amplitude** esté seleccionado, que la **tasa de símbolos** descubierta esté configurada y que **Gadner clock recovery** esté seleccionado):

![Panel Get Bits de SigDigger configurado para el muestreo AM, la tasa de símbolos y la recuperación de reloj Gardner](<../../images/image (965).png>)

- **Sync to selection intervals** significa que, si previamente seleccionaste intervalos para encontrar la tasa de símbolos, se utilizará esa tasa.
- **Manual** significa que se utilizará la tasa de símbolos indicada.
- En **Fixed interval selection** indicas el número de intervalos que deben seleccionarse y se calcula la tasa de símbolos a partir de ellos.
- **Gadner clock recovery** suele ser la mejor opción, pero aun así necesitas indicar una tasa de símbolos aproximada.

Al pulsar sample aparece lo siguiente:

![Con un grupo de símbolos - Obtener los bits: esto aparece al pulsar sample](<../../images/image (644).png>)

Ahora, para que SigDigger entienda **dónde está el rango** del nivel que contiene la información, debes hacer clic en el **nivel inferior** y mantener el clic hasta llegar al nivel más alto:

![Selección del rango de niveles de SigDigger desde el nivel de amplitud inferior hasta el superior](<../../images/image (439).png>)

Si, por ejemplo, hubiera habido **4 niveles de amplitud diferentes**, deberías haber configurado **Bits per symbol en 2** y seleccionado desde el nivel más pequeño hasta el más grande.

Por último, **aumentando** el **Zoom** y **cambiando el Row size**, puedes ver los bits (y puedes seleccionarlos todos y copiarlos para obtener todos los bits):

![Con un grupo de símbolos - Obtener los bits: por último, aumentando el Zoom y cambiando el Row size puedes ver los bits (y puedes seleccionarlos todos y copiarlos para obtenerlos)](<../../images/image (276).png>)

Si la señal tiene más de 1 bit por símbolo (por ejemplo, 2), SigDigger **no tiene forma de saber qué símbolo es** 00, 01, 10 o 11, por lo que utilizará diferentes **escalas de grises** para representar cada uno (y, si copias los bits, utilizará **números del 0 al 3**, que tendrás que procesar).

Además, utiliza **codificaciones** como **Manchester**: una subida+bajada puede ser **1 o 0**, y una bajada+subida puede ser 1 o 0. En esos casos debes **procesar las subidas (1) y bajadas (0)** obtenidas para sustituir los pares 01 o 10 por 0 o 1.

## Ejemplo de FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Descubrir FM

#### Comprobar las frecuencias y la forma de onda

Ejemplo de una señal que envía información modulada en FM:

![Descubrir FM - Comprobar las frecuencias y la forma de onda: ejemplo de una señal que envía información modulada en FM](<../../images/image (725).png>)

En la imagen anterior puedes observar bastante bien que se utilizan **2 frecuencias**, pero si **observas** la **forma de onda**, puede que n**o seas capaz de identificar correctamente las 2 frecuencias diferentes**:

![Forma de onda FM de SigDigger donde las dos frecuencias son difíciles de distinguir directamente](<../../images/image (717).png>)

Esto se debe a que capturé la señal en ambas frecuencias, por lo que una es aproximadamente la otra en negativo:

![Captura FM de SigDigger mostrando las dos frecuencias como aproximadamente negativas entre sí](<../../images/image (942).png>)

Si la frecuencia sincronizada está **más cerca de una frecuencia que de la otra**, puedes ver fácilmente las 2 frecuencias diferentes:

![Descubrir FM - Comprobar las frecuencias y la forma de onda: si la frecuencia sincronizada está más cerca de una frecuencia que de la otra, puedes ver fácilmente las 2 frecuencias diferentes](<../../images/image (422).png>)

![Descubrir FM - Comprobar las frecuencias y la forma de onda: si la frecuencia sincronizada está más cerca de una frecuencia que de la otra, puedes ver fácilmente las 2 frecuencias diferentes](<../../images/image (488).png>)

#### Comprobar el histograma

Al comprobar el histograma de frecuencia de la señal con información, puedes ver fácilmente 2 señales diferentes:

![Comprobar las frecuencias y la forma de onda - Comprobar el histograma: al comprobar el histograma de frecuencia de la señal con información puedes ver fácilmente 2 señales diferentes](<../../images/image (871).png>)

En este caso, si compruebas el **histograma de amplitud**, encontrarás **una sola amplitud**, por lo que **no puede ser AM** (si encuentras muchas amplitudes, podría deberse a que la señal ha perdido potencia a lo largo del canal):

![Histograma de amplitud de SigDigger para una señal FM mostrando un único nivel de amplitud](<../../images/image (817).png>)

Y este sería el histograma de fase (que deja muy claro que la señal no está modulada en fase):

![Comprobar las frecuencias y la forma de onda - Comprobar el histograma: este sería el histograma de fase, que deja muy claro que la señal no está modulada en fase](<../../images/image (996).png>)

#### Con IQ

IQ no tiene un campo para identificar frecuencias (la distancia al centro es la amplitud y el ángulo es la fase).\
Por tanto, para identificar FM, básicamente deberías **ver solo un círculo** en este gráfico.\
Además, una frecuencia diferente se "representa" en el gráfico IQ mediante una **aceleración de la velocidad a través del círculo** (así, al seleccionar la señal en SysDigger se rellena el gráfico IQ; si encuentras una aceleración o un cambio de dirección en el círculo creado, podría significar que se trata de FM):

![Gráfico IQ de SigDigger donde FM aparece como cambios de aceleración alrededor del círculo](<../../images/image (81).png>)

### Obtener la tasa de símbolos

Puedes utilizar la **misma técnica que en el ejemplo de AM** para obtener la tasa de símbolos una vez que hayas encontrado las frecuencias que transportan los símbolos.

### Obtener los bits

Puedes utilizar la **misma técnica que en el ejemplo de AM** para obtener los bits una vez que hayas **determinado que la señal está modulada en frecuencia** y hayas obtenido la **tasa de símbolos**.

## Referencias

- [1] [SigDigger - Free digital signal analyzer for GNU/Linux and macOS](https://github.com/BatchDrake/SigDigger)

{{#include ../../banners/hacktricks-training.md}}
