# Radio

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## SigDigger

[**SigDigger** ](https://github.com/BatchDrake/SigDigger)es un analizador de señales digitales gratuito para GNU/Linux y macOS, diseñado para extraer información de señales de radio desconocidas. Admite una variedad de dispositivos SDR a través de SoapySDR, y permite la demodulación ajustable de señales FSK, PSK y ASK, decodificar video analógico, analizar señales intermitentes y escuchar canales de voz analógicos (todo en tiempo real).

### Configuración básica

Después de instalar, hay algunas cosas que podrías considerar configurar.\
En la configuración (el segundo botón de la pestaña) puedes seleccionar el **dispositivo SDR** o **seleccionar un archivo** para leer y en qué frecuencia sintonizar y la tasa de muestreo (recomendado hasta 2,56Msps si tu PC lo soporta).

![](<../../.gitbook/assets/image (655) (1).png>)

En el comportamiento de la GUI, se recomienda habilitar algunas cosas si tu PC lo soporta:

![](<../../.gitbook/assets/image (465) (2).png>)

{% hint style="info" %}
Si te das cuenta de que tu PC no está capturando cosas, intenta desactivar OpenGL y reducir la tasa de muestreo.
{% endhint %}

### Usos

* Solo para **capturar algún tiempo de una señal y analizarla**, mantén presionado el botón "Push to capture" todo el tiempo que necesites.

![](<../../.gitbook/assets/image (631).png>)

* El **Sintonizador** de SigDigger ayuda a **capturar mejores señales** (pero también puede degradarlas). Idealmente, comienza con 0 y sigue **aumentándolo hasta** que encuentres que el **ruido** introducido es **mayor** que la **mejora de la señal** que necesitas.

![](<../../.gitbook/assets/image (658).png>)

### Sincronización con el canal de radio

Con [**SigDigger** ](https://github.com/BatchDrake/SigDigger)sincroniza con el canal que deseas escuchar, configura la opción "Baseband audio preview", configura el ancho de banda para obtener toda la información que se envía y luego ajusta el sintonizador al nivel antes de que el ruido realmente comience a aumentar:

![](<../../.gitbook/assets/image (389).png>)

## Trucos interesantes

* Cuando un dispositivo envía ráfagas de información, por lo general la **primera parte será un preámbulo** por lo que no necesitas preocuparte si no encuentras información allí o si hay algunos errores allí.
* En los marcos de información, por lo general deberías **encontrar diferentes marcos bien alineados entre ellos**:

![](<../../.gitbook/assets/image (660) (1).png>)

![](<../../.gitbook/assets/image (652) (1) (1).png>)

* **Después de recuperar los bits, es posible que necesites procesarlos de alguna manera**. Por ejemplo, en la codificación Manchester, un arriba + abajo será un 1 o 0 y un abajo + arriba será el otro. Entonces, los pares de 1 y 0 (arriba
## Ejemplo de FM

{% file src="../../.gitbook/assets/sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw" %}

### Descubriendo FM

#### Comprobando las frecuencias y la forma de onda

Ejemplo de señal que envía información modulada en FM:

![](<../../.gitbook/assets/image (661) (1).png>)

En la imagen anterior se pueden observar **2 frecuencias que se utilizan**, pero si **observas** la **forma de onda**, es posible que **no puedas identificar correctamente las 2 frecuencias diferentes**:

![](<../../.gitbook/assets/image (653).png>)

Esto se debe a que capturé la señal en ambas frecuencias, por lo tanto, una es aproximadamente la otra en negativo:

![](<../../.gitbook/assets/image (656).png>)

Si la frecuencia sincronizada está **más cerca de una frecuencia que de la otra**, es posible ver fácilmente las 2 frecuencias diferentes:

![](<../../.gitbook/assets/image (648) (1) (1) (1).png>)

![](<../../.gitbook/assets/image (634).png>)

#### Comprobando el histograma

Comprobando el histograma de frecuencia de la señal con información, es posible ver fácilmente 2 señales diferentes:

![](<../../.gitbook/assets/image (657).png>)

En este caso, si compruebas el **histograma de amplitud**, encontrarás **sólo una amplitud**, por lo que **no puede ser AM** (si encuentras muchas amplitudes, puede ser porque la señal ha perdido potencia a lo largo del canal):

![](<../../.gitbook/assets/image (646).png>)

Y este sería el histograma de fase (lo que deja muy claro que la señal no está modulada en fase):

![](<../../.gitbook/assets/image (201) (2).png>)

#### Con IQ

IQ no tiene un campo para identificar frecuencias (la distancia al centro es la amplitud y el ángulo es la fase).\
Por lo tanto, para identificar FM, deberías **ver básicamente un círculo** en este gráfico.\
Además, una frecuencia diferente se "representa" en el gráfico IQ por una **aceleración de velocidad a través del círculo** (por lo que en SysDigger, al seleccionar la señal, se genera el gráfico IQ, si encuentras una aceleración o cambio de dirección en el círculo creado, podría significar que esto es FM):

![](<../../.gitbook/assets/image (643) (1).png>)

### Obtener la tasa de símbolos

Puedes utilizar la **misma técnica que la utilizada en el ejemplo de AM** para obtener la tasa de símbolos una vez que hayas encontrado las frecuencias que transportan los símbolos.

### Obtener bits

Puedes utilizar la **misma técnica que la utilizada en el ejemplo de AM** para obtener los bits una vez que hayas **encontrado que la señal está modulada en frecuencia** y la **tasa de símbolos**. 

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Consigue el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
