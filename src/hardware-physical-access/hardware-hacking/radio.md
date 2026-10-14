# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

[**SigDigger**](https://github.com/BatchDrake/SigDigger) es un analizador de señales digitales gratuito para GNU/Linux y macOS, diseñado para extraer información de señales de radio desconocidas. Es compatible con dispositivos SDR mediante SoapySDR y ofrece herramientas de demodulación y análisis en tiempo real para FSK, PSK, ASK, vídeo analógico, señales en ráfagas y canales de voz analógicos.<sup>[[1]](#references)</sup>

### Configuración básica

Después de instalarlo, hay algunos ajustes que puedes considerar.\
En los ajustes (el botón de la segunda pestaña), selecciona un **dispositivo SDR** o un archivo de entrada, la frecuencia que quieres sintonizar y la frecuencia de muestreo. Una frecuencia de hasta 2.56 Msps puede resultar práctica si el equipo host la admite.

![Ajustes de SigDigger con las opciones de dispositivo SDR, archivo de entrada, frecuencia y frecuencia de muestreo](<../../images/image (245).png>)

En el comportamiento de la GUI, se recomienda habilitar algunas opciones si tu PC las admite:

![SigDigger - Configuración básica: En el comportamiento de la GUI, se recomienda habilitar algunas opciones si tu PC las admite](<../../images/image (472).png>)

> [!TIP]
> Si ves que tu PC no está capturando la señal, prueba a deshabilitar OpenGL y reducir la frecuencia de muestreo.

### Usos

- Para **capturar parte de una señal y analizarla**, mantén pulsado el botón "Push to capture" durante el tiempo que necesites.

![Configuración básica - Usos: Para capturar parte de una señal y analizarla, mantén pulsado el botón "Push to capture" durante el tiempo que necesites](<../../images/image (960).png>)

- El **Tuner** de SigDigger ayuda a **capturar señales de mejor calidad** (pero también puede degradarlas). Lo ideal es empezar en 0 e ir **aumentándolo hasta que** el **ruido** que introduce sea **mayor** que la **mejora de la señal** que necesitas).

![Control Tuner de SigDigger ajustado para mejorar la señal de radio capturada](<../../images/image (1099).png>)

### Sincronización con un canal de radio

Con [**SigDigger** ](https://github.com/BatchDrake/SigDigger), sincronízate con el canal que quieras escuchar, configura la opción "Baseband audio preview", ajusta el ancho de banda para recibir toda la información transmitida y, después, establece el Tuner en el nivel anterior al punto en que el ruido empieza a aumentar considerablemente:<sup>[[1]](#references)</sup>

![Canal de radio sincronizado en SigDigger con la vista previa de audio de banda base y el ancho de banda configurados](<../../images/image (585).png>)

## Trucos interesantes

- Cuando un dispositivo transmite información en ráfagas, normalmente **la primera parte será un preámbulo**, así que **no** tienes que **preocuparte** si **no encuentras información** en esa parte **o si contiene algunos errores**.
- En las tramas de información, normalmente deberías **encontrar distintas tramas bien alineadas entre sí**:

![Sincronización con un canal de radio - Trucos interesantes: En las tramas de información, normalmente deberías encontrar distintas tramas bien alineadas entre sí](<../../images/image (1076).png>)

![Sincronización con un canal de radio - Trucos interesantes: En las tramas de información, normalmente deberías encontrar distintas tramas bien alineadas entre sí](<../../images/image (597).png>)

- **Después de recuperar las transiciones de nivel, puede que tengas que decodificarlas.** En la codificación Manchester, una dirección de transición representa `0` y la dirección opuesta representa `1`; la polaridad exacta depende de la convención utilizada.
- Un preámbulo puede contener una secuencia del mismo nivel muestreado aunque la carga útil use codificación Manchester, así que identifica el límite de la trama antes de decodificarla.

### Identificar el tipo de modulación con IQ

Hay 3 formas de almacenar información en señales: modulando la **amplitud**, la **frecuencia** o la **fase**.\
Si estás analizando una señal, hay distintas formas de intentar averiguar qué método se utiliza para almacenar información (más abajo se describen otras), pero una buena opción es revisar el gráfico IQ.

![Gráfico IQ de SigDigger utilizado para identificar si una señal usa modulación de amplitud, frecuencia o fase](<../../images/image (788).png>)

- **Detección de AM**: Si en el gráfico IQ aparecen, por ejemplo, **2 círculos** (probablemente uno en 0 y otro con una amplitud diferente), podría significar que se trata de una señal AM. Esto se debe a que, en el gráfico IQ, la distancia entre el 0 y el círculo representa la amplitud de la señal, por lo que es fácil visualizar las distintas amplitudes utilizadas.
- **Detección de PM**: Como en la imagen anterior, si encuentras círculos pequeños que no están relacionados entre sí, probablemente se utilice modulación de fase. Esto se debe a que, en el gráfico IQ, el ángulo entre el punto y el origen (0,0) representa la fase de la señal, lo que significa que se utilizan 4 fases diferentes.
  - Ten en cuenta que, si la información depende de que la fase cambie y no de la fase en sí, no verás las distintas fases claramente diferenciadas.
- **Detección de FM**: IQ no tiene un campo para identificar frecuencias (la distancia al centro representa la amplitud y el ángulo, la fase).\
  Por lo tanto, para identificar FM, en este gráfico básicamente solo deberías ver un círculo.\
  Además, un desplazamiento de frecuencia cambia la velocidad de rotación alrededor del círculo IQ. Por tanto, en SigDigger, un cambio en la velocidad o la dirección de rotación puede indicar FM.

## Ejemplo de AM

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Identificar AM

#### Revisar la envolvente

Al inspeccionar datos AM con [**SigDigger**](https://github.com/BatchDrake/SigDigger), la **envolvente** de la señal puede revelar distintos niveles de amplitud. La señal de ejemplo transmite información mediante pulsos modulados en amplitud; un pulso tiene este aspecto:<sup>[[1]](#references)</sup>

![Envolvente de una señal AM en SigDigger con niveles de amplitud de pulso claramente diferenciados](<../../images/image (590).png>)

Este es el aspecto de una parte del símbolo en la forma de onda:

![Identificar AM - Revisar la envolvente: Este es el aspecto de una parte del símbolo en la forma de onda](<../../images/image (734).png>)

#### Revisar el histograma

Puedes **seleccionar toda la señal** donde se encuentra la información, elegir el modo **Amplitude** y **Selection**, y hacer clic en **Histogram**. Observarás que solo aparecen 2 niveles claramente diferenciados.

![Histograma de amplitud de SigDigger que muestra dos niveles claramente diferenciados en la señal AM seleccionada](<../../images/image (264).png>)

Por ejemplo, si seleccionas Frequency en lugar de Amplitude para esta señal AM, solo encontrarás 1 frecuencia (no es posible que la información modulada en frecuencia use una sola frecuencia).

![Histograma de frecuencia de SigDigger para la señal AM que muestra una sola frecuencia](<../../images/image (732).png>)

Si encuentras muchas frecuencias, es posible que no se trate de FM; probablemente la frecuencia de la señal solo haya cambiado debido al canal.

#### Con IQ

En este ejemplo puedes ver que hay un **círculo grande**, pero también **muchos puntos en el centro**.

![Revisar el histograma - Con IQ: En este ejemplo puedes ver que hay un círculo grande, pero también muchos puntos en el centro](<../../images/image (222).png>)

### Obtener la tasa de símbolos

#### Con un símbolo

Selecciona el intervalo más pequeño que contenga claramente un símbolo y revisa **Selection freq**. En este ejemplo es 1.013 kHz, aproximadamente 1 kHz.

![Obtener la tasa de símbolos - Con un símbolo: Selecciona el intervalo más pequeño que encuentres (para asegurarte de que contiene solo uno) y revisa "Selection freq". En este caso sería 1.013 kHz (es decir, 1 kHz).](<../../images/image (78).png>)

#### Con un grupo de símbolos

También puedes indicar cuántos símbolos vas a seleccionar y SigDigger calculará la frecuencia de 1 símbolo (probablemente, cuantos más símbolos selecciones, mejor). En este caso seleccioné 10 símbolos y "Selection freq" es 1.004 kHz:

![Cálculo de la tasa de símbolos en SigDigger mediante un grupo seleccionado de diez símbolos](<../../images/image (1008).png>)

### Obtener bits

Después de identificar AM y estimar la **tasa de símbolos**, selecciona la región de la señal, configura el muestreo de amplitud y los niveles de decisión, elige **Gardner clock recovery** y pulsa **Sample**:

![Panel Get Bits de SigDigger configurado para el muestreo AM, la tasa de símbolos y Gardner clock recovery](<../../images/image (965).png>)

- **Sync to selection intervals** significa que se usará la tasa de símbolos calculada anteriormente al seleccionar intervalos.
- **Manual** significa que se usará la tasa de símbolos indicada.
- En **Fixed interval selection** indicas el número de intervalos que se deben seleccionar y SigDigger calcula la tasa de símbolos a partir de ellos.
- **Gardner clock recovery** es una opción predeterminada útil, pero sigue necesitando una tasa de símbolos aproximada.

Al pulsar Sample, aparecerá esto:

![Con un grupo de símbolos - Obtener bits: Esto aparece al pulsar Sample](<../../images/image (644).png>)

Ahora, para que SigDigger entienda **dónde está el rango** del nivel que contiene la información, haz clic en el **nivel más bajo** y mantén pulsado hasta llegar al nivel más alto:

![Selección del rango de niveles en SigDigger desde el nivel de amplitud más bajo hasta el más alto](<../../images/image (439).png>)

Si, por ejemplo, hubiera **4 niveles de amplitud diferentes**, tendrías que configurar **Bits per symbol** en 2 y seleccionar desde el nivel más bajo hasta el más alto.

Por último, al **aumentar** el **Zoom** y **cambiar Row size**, podrás ver los bits (y puedes seleccionarlos todos y copiarlos para obtenerlos):

![Con un grupo de símbolos - Obtener bits: Por último, al aumentar el Zoom y cambiar Row size, podrás ver los bits (y puedes seleccionarlos todos y copiarlos para obtenerlos)](<../../images/image (276).png>)

Si la señal tiene más de 1 bit por símbolo (por ejemplo, 2), SigDigger **no puede saber qué símbolo es** 00, 01, 10 o 11, así que usará distintas **escalas de grises** para representar cada uno (y, si copias los bits, usará **números del 0 al 3**, que tendrás que procesar).

Para codificaciones de línea como **Manchester**, convierte cada par de transiciones válido (`01` o `10`) en un bit de datos según la convención utilizada por el protocolo.

## Ejemplo de FM

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Identificar FM

#### Revisar las frecuencias y la forma de onda

Ejemplo de una señal que transmite información modulada en FM:

![Identificar FM - Revisar las frecuencias y la forma de onda: Ejemplo de una señal que transmite información modulada en FM](<../../images/image (725).png>)

El espectro muestra claramente **dos frecuencias**, aunque puede ser difícil distinguirlas en la forma de onda en el dominio del tiempo:

![Forma de onda FM en SigDigger donde es difícil distinguir directamente las dos frecuencias](<../../images/image (717).png>)

Esto ocurre porque la captura está centrada entre ambas frecuencias, por lo que sus desplazamientos de frecuencia son aproximadamente opuestos:

![Captura FM en SigDigger que muestra las dos frecuencias como valores aproximadamente opuestos](<../../images/image (942).png>)

Si la frecuencia de sincronización está **más cerca de una frecuencia que de la otra**, podrás ver fácilmente las 2 frecuencias diferentes:

![Identificar FM - Revisar las frecuencias y la forma de onda: Si la frecuencia de sincronización está más cerca de una frecuencia que de la otra, podrás ver fácilmente las 2 frecuencias diferentes](<../../images/image (422).png>)

![Identificar FM - Revisar las frecuencias y la forma de onda: Si la frecuencia de sincronización está más cerca de una frecuencia que de la otra, podrás ver fácilmente las 2 frecuencias diferentes](<../../images/image (488).png>)

#### Revisar el histograma

Al revisar el histograma de frecuencia de la señal con información, puedes ver fácilmente 2 señales diferentes:

![Revisar las frecuencias y la forma de onda - Revisar el histograma: Al revisar el histograma de frecuencia de la señal con información, puedes ver fácilmente 2 señales diferentes](<../../images/image (871).png>)

En este caso, si revisas el **histograma de amplitud**, solo encontrarás **una amplitud**, así que **no puede ser AM** (si encuentras muchas amplitudes, quizá se deba a que la señal ha perdido potencia a lo largo del canal):

![Histograma de amplitud de SigDigger para una señal FM que muestra un único nivel de amplitud](<../../images/image (817).png>)

Este sería el histograma de fase (que deja muy claro que la señal no está modulada en fase):

![Revisar las frecuencias y la forma de onda - Revisar el histograma: Este sería el histograma de fase, que deja muy claro que la señal no está modulada en fase](<../../images/image (996).png>)

#### Con IQ

IQ no tiene un campo para identificar frecuencias (la distancia al centro representa la amplitud y el ángulo, la fase).\
Por lo tanto, para identificar FM, en este gráfico básicamente solo deberías ver un círculo.\
Además, un desplazamiento de frecuencia cambia la velocidad de rotación alrededor del círculo IQ. Por tanto, en SigDigger, un cambio en la velocidad o la dirección de rotación puede indicar FM:

![Gráfico IQ de SigDigger donde FM aparece como cambios en la velocidad de rotación alrededor del círculo](<../../images/image (81).png>)

### Obtener la tasa de símbolos

Puedes usar **la misma técnica que en el ejemplo de AM** para obtener la tasa de símbolos una vez que hayas encontrado las frecuencias que contienen los símbolos.

### Obtener bits

Puedes usar **la misma técnica que en el ejemplo de AM** para obtener los bits una vez que hayas **identificado que la señal está modulada en frecuencia** y hayas encontrado la **tasa de símbolos**.

## References

- [1] [SigDigger: analizador de señales digitales gratuito para GNU/Linux y macOS](https://github.com/BatchDrake/SigDigger)
{{#include ../../banners/hacktricks-training.md}}
