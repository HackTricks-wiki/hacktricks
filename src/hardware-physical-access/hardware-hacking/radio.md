# Radio

{{#include ../../banners/hacktricks-training.md}}

Para trabajos específicos de cada protocolo después de identificar la señal, consulta las pruebas de [RFID/NFC, sub-GHz, infrarrojos, BLE y LoRaWAN](../radio-hacking/README.md).

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) es un analizador gratuito de señales digitales para GNU/Linux y macOS, diseñado para extraer información de señales de radio desconocidas. Es compatible con dispositivos SDR mediante SoapySDR y proporciona herramientas de demodulación y análisis en tiempo real para FSK, PSK, ASK, video analógico, señales en ráfagas y canales de voz analógicos.<sup>[[1]](#references)</sup>

### Configuración básica

Después de instalarlo, hay algunas opciones que puedes configurar.\
En los ajustes (el botón de la segunda pestaña), selecciona un **dispositivo SDR** o un archivo de entrada, la frecuencia que quieres sintonizar y la frecuencia de muestreo. Una velocidad de hasta 2.56 Msps puede ser práctica si el equipo lo permite.

![Ajustes de SigDigger con las opciones de dispositivo SDR, archivo de entrada, frecuencia y frecuencia de muestreo](<../../images/image (245).png>)

En el comportamiento de la GUI, se recomienda habilitar algunas opciones si tu PC las admite:

![SigDigger - Configuración básica: En el comportamiento de la GUI, se recomienda habilitar algunas opciones si tu PC las admite](<../../images/image (472).png>)

> [!TIP]
> Si ves que tu PC no captura la señal, prueba a deshabilitar OpenGL y reducir la frecuencia de muestreo.

### Usos

- Para **capturar un intervalo de una señal y analizarlo**, mantén pulsado el botón "Push to capture" durante el tiempo que necesites.

![Configuración básica - Usos: Para capturar un intervalo de una señal y analizarlo, mantén pulsado el botón "Push to capture" durante el tiempo que necesites](<../../images/image (960).png>)

- El **Tuner** de SigDigger ayuda a **capturar mejor las señales** (aunque también puede degradarlas). Lo ideal es empezar en 0 e **ir aumentándolo hasta** que el **ruido** introducido sea **mayor** que la **mejora de la señal** que necesitas.

![Control del Tuner de SigDigger ajustado para mejorar la señal de radio capturada](<../../images/image (1099).png>)

### Sincronizarse con un canal de radio

Con [**SigDigger** ](https://github.com/BatchDrake/SigDigger), sincronízate con el canal que quieres escuchar, configura la opción "Baseband audio preview", establece el ancho de banda para obtener toda la información transmitida y ajusta el Tuner al nivel anterior al momento en que el ruido empiece a aumentar considerablemente:<sup>[[1]](#references)</sup>

![Canal de radio sincronizado en SigDigger con la vista previa de audio en banda base y el ancho de banda configurados](<../../images/image (585).png>)

## Trucos interesantes

- Cuando un dispositivo transmite ráfagas de información, normalmente la **primera parte será un preámbulo**, así que **no** tienes que **preocuparte** si **no encuentras información** ahí **o si hay algunos errores**.
- En las tramas de información, normalmente deberías **encontrar distintas tramas bien alineadas entre sí**:

![Sincronizarse con un canal de radio - Trucos interesantes: En las tramas de información, normalmente deberías encontrar distintas tramas bien alineadas entre sí](<../../images/image (1076).png>)

![Sincronizarse con un canal de radio - Trucos interesantes: En las tramas de información, normalmente deberías encontrar distintas tramas bien alineadas entre sí](<../../images/image (597).png>)

- **Después de recuperar las transiciones de nivel, quizá tengas que decodificarlas.** En la codificación Manchester, una dirección de transición representa `0` y la dirección opuesta representa `1`; la polaridad exacta depende de la convención utilizada.
- Un preámbulo puede contener una secuencia del mismo nivel muestreado aunque la carga útil use codificación Manchester, así que identifica el límite de la trama antes de decodificarla.

### Identificar el tipo de modulación con IQ

Hay 3 formas de almacenar información en señales: modular la **amplitud**, la **frecuencia** o la **fase**.\
Si estás analizando una señal, hay distintas formas de intentar averiguar qué se utiliza para almacenar la información (encuentra más formas abajo), pero una buena opción es comprobar el gráfico IQ.

![Gráfico IQ de SigDigger utilizado para identificar si una señal usa modulación de amplitud, frecuencia o fase](<../../images/image (788).png>)

- **Detectar AM**: Si en el gráfico IQ aparecen, por ejemplo, **2 círculos** (probablemente uno en 0 y otro con una amplitud distinta), podría significar que se trata de una señal AM. Esto se debe a que, en el gráfico IQ, la distancia entre el 0 y el círculo representa la amplitud de la señal, por lo que resulta fácil visualizar las distintas amplitudes utilizadas.
- **Detectar PM**: Como en la imagen anterior, si encuentras círculos pequeños que no guardan relación entre sí, probablemente se esté utilizando modulación de fase. Esto se debe a que, en el gráfico IQ, el ángulo entre el punto y el 0,0 representa la fase de la señal, lo que significa que se utilizan 4 fases distintas.
  - Ten en cuenta que, si la información está codificada en el cambio de fase y no en la fase en sí, no verás fases distintas claramente diferenciadas.
- **Detectar FM**: IQ no tiene un campo para identificar frecuencias (la distancia al centro representa la amplitud y el ángulo, la fase).\
  Por lo tanto, para identificar FM, básicamente deberías **ver solo un círculo** en este gráfico.\
  Además, un desplazamiento de frecuencia cambia la velocidad de rotación alrededor del círculo IQ. Por tanto, en SigDigger, un cambio en la velocidad o la dirección de rotación puede indicar FM.

## Ejemplo de AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Identificar AM

#### Comprobar la envolvente

Al inspeccionar datos AM con [**SigDigger**](https://github.com/BatchDrake/SigDigger), la **envolvente** de la señal puede revelar niveles de amplitud distintos. La señal de ejemplo transmite información en pulsos modulados en amplitud; este es el aspecto de un pulso:<sup>[[1]](#references)</sup>

![Envolvente de la señal AM en SigDigger con niveles de amplitud de pulso claramente definidos](<../../images/image (590).png>)

Y así se ve parte del símbolo en la forma de onda:

![Identificar AM - Comprobar la envolvente: Así se ve parte del símbolo en la forma de onda](<../../images/image (734).png>)

#### Comprobar el histograma

Puedes **seleccionar toda la señal** donde se encuentra la información, seleccionar el modo **Amplitude** y **Selection**, y hacer clic en **Histogram**. Puedes observar que solo aparecen 2 niveles claramente definidos.

![Histograma de amplitud de SigDigger que muestra dos niveles claramente definidos para la señal AM seleccionada](<../../images/image (264).png>)

Por ejemplo, si seleccionas Frequency en lugar de Amplitude en esta señal AM, encontrarás una sola frecuencia (no tendría sentido que la información modulada en frecuencia utilizara una sola frecuencia).

![Histograma de frecuencia de SigDigger para la señal AM que muestra una sola frecuencia](<../../images/image (732).png>)

Si encuentras muchas frecuencias, es posible que no se trate de FM; probablemente, la frecuencia de la señal simplemente haya cambiado debido al canal.

#### Con IQ

En este ejemplo puedes ver que hay un **círculo grande**, pero también **muchos puntos en el centro**.

![Comprobar el histograma - Con IQ: En este ejemplo puedes ver que hay un círculo grande, pero también muchos puntos en el centro](<../../images/image (222).png>)

### Obtener la tasa de símbolos

#### Con un símbolo

Selecciona el intervalo más pequeño que contenga claramente un símbolo y comprueba **Selection freq**. En este ejemplo es 1.013 kHz, aproximadamente 1 kHz.

![Obtener la tasa de símbolos - Con un símbolo: Selecciona el intervalo más pequeño que puedas encontrar (para asegurarte de que contiene solo uno) y comprueba "Selection freq". En este caso sería 1.013 kHz (es decir, 1 kHz).](<../../images/image (78).png>)

#### Con un grupo de símbolos

También puedes indicar el número de símbolos que vas a seleccionar y SigDigger calculará la frecuencia de un símbolo (probablemente, cuantos más símbolos selecciones, mejor). En este caso seleccioné 10 símbolos y "Selection freq" es 1.004 Khz:

![Cálculo de la tasa de símbolos en SigDigger usando un grupo seleccionado de diez símbolos](<../../images/image (1008).png>)

### Obtener bits

Después de identificar AM y estimar la **tasa de símbolos**, selecciona la región de la señal, configura el muestreo de amplitud y los niveles de decisión, elige **Gardner clock recovery** y pulsa **Sample**:

![Panel Get Bits de SigDigger configurado para el muestreo AM, la tasa de símbolos y Gardner clock recovery](<../../images/image (965).png>)

- **Sync to selection intervals** significa que se utilizará la tasa de símbolos obtenida si antes seleccionaste intervalos para calcularla.
- **Manual** significa que se utilizará la tasa de símbolos indicada.
- En **Fixed interval selection**, indicas el número de intervalos que se deben seleccionar y se calcula la tasa de símbolos a partir de ellos.
- **Gardner clock recovery** es una opción predeterminada útil, pero también necesita una tasa de símbolos aproximada.

Al pulsar Sample, aparece esto:

![Con un grupo de símbolos - Obtener bits: Esto aparece al pulsar Sample](<../../images/image (644).png>)

Ahora, para que SigDigger reconozca **el rango que contiene el nivel con información**, tienes que hacer clic en el **nivel inferior** y mantener pulsado hasta llegar al nivel más alto:

![Selección del rango de niveles en SigDigger desde el nivel de amplitud inferior hasta el superior](<../../images/image (439).png>)

Si, por ejemplo, hubiera **4 niveles de amplitud distintos**, tendrías que configurar **Bits per symbol** en 2 y seleccionar desde el nivel más bajo hasta el más alto.

Por último, **aumentando** el **Zoom** y **cambiando el Row size** puedes ver los bits (y puedes seleccionarlos todos y copiarlos para obtenerlos todos):

![Con un grupo de símbolos - Obtener bits: Por último, aumenta el Zoom y cambia el Row size para ver los bits (puedes seleccionarlos todos y copiarlos para obtenerlos todos)](<../../images/image (276).png>)

Si la señal tiene más de 1 bit por símbolo (por ejemplo, 2), SigDigger **no puede saber qué símbolo corresponde a** 00, 01, 10 o 11, así que utilizará distintas **escalas de grises** para representar cada uno (y al copiar los bits, utilizará **números del 0 al 3**, que tendrás que procesar).

Para codificaciones de línea como **Manchester**, convierte cada par de transiciones válido (`01` o `10`) en un bit de datos según la convención utilizada por el protocolo.

## Ejemplo de FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Identificar FM

#### Comprobar las frecuencias y la forma de onda

Ejemplo de señal que transmite información modulada en FM:

![Identificar FM - Comprobar las frecuencias y la forma de onda: Ejemplo de señal que transmite información modulada en FM](<../../images/image (725).png>)

El espectro muestra claramente **dos frecuencias**, aunque puede ser difícil distinguirlas en la forma de onda en el dominio temporal:

![Forma de onda FM de SigDigger en la que es difícil distinguir directamente las dos frecuencias](<../../images/image (717).png>)

Esto ocurre porque la captura está centrada entre ambas frecuencias, por lo que sus desplazamientos de frecuencia son aproximadamente opuestos:

![Captura FM de SigDigger que muestra las dos frecuencias como valores aproximadamente opuestos](<../../images/image (942).png>)

Si la frecuencia sincronizada está **más cerca de una frecuencia que de la otra**, puedes ver fácilmente las 2 frecuencias distintas:

![Identificar FM - Comprobar las frecuencias y la forma de onda: Si la frecuencia sincronizada está más cerca de una frecuencia que de la otra, puedes ver fácilmente las 2 frecuencias distintas](<../../images/image (422).png>)

![Identificar FM - Comprobar las frecuencias y la forma de onda: Si la frecuencia sincronizada está más cerca de una frecuencia que de la otra, puedes ver fácilmente las 2 frecuencias distintas](<../../images/image (488).png>)

#### Comprobar el histograma

Al comprobar el histograma de frecuencia de la señal con información, puedes ver fácilmente 2 señales distintas:

![Comprobar las frecuencias y la forma de onda - Comprobar el histograma: Al comprobar el histograma de frecuencia de la señal con información, puedes ver fácilmente 2 señales distintas](<../../images/image (871).png>)

En este caso, si compruebas el **histograma de amplitud**, encontrarás **una sola amplitud**, por lo que **no puede ser AM** (si encuentras muchas amplitudes, podría deberse a que la señal ha perdido potencia a través del canal):

![Histograma de amplitud de SigDigger para una señal FM que muestra un único nivel de amplitud](<../../images/image (817).png>)

Y este sería el histograma de fase (que deja muy claro que la señal no está modulada en fase):

![Comprobar las frecuencias y la forma de onda - Comprobar el histograma: Este sería el histograma de fase, que deja muy claro que la señal no está modulada en fase](<../../images/image (996).png>)

#### Con IQ

IQ no tiene un campo para identificar frecuencias (la distancia al centro representa la amplitud y el ángulo, la fase).\
Por lo tanto, para identificar FM, básicamente deberías **ver solo un círculo** en este gráfico.\
Además, un desplazamiento de frecuencia cambia la velocidad de rotación alrededor del círculo IQ. Por tanto, en SigDigger, un cambio en la velocidad o la dirección de rotación puede indicar FM:

![Gráfico IQ de SigDigger en el que FM aparece como cambios de velocidad alrededor del círculo](<../../images/image (81).png>)

### Obtener la tasa de símbolos

Puedes utilizar **la misma técnica que en el ejemplo de AM** para obtener la tasa de símbolos una vez que hayas encontrado las frecuencias que transportan los símbolos.

### Obtener bits

Puedes utilizar **la misma técnica que en el ejemplo de AM** para obtener los bits una vez que hayas **determinado que la señal está modulada en frecuencia** y hayas obtenido la **tasa de símbolos**.

## References

- [1] [SigDigger - Analizador gratuito de señales digitales para GNU/Linux y macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
