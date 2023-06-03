# Sub-GHz RF

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Puertas de garaje

Los abridores de puertas de garaje suelen operar en frecuencias en el rango de 300-190 MHz, siendo las frecuencias más comunes 300 MHz, 310 MHz, 315 MHz y 390 MHz. Este rango de frecuencia se utiliza comúnmente para los abridores de puertas de garaje porque está menos congestionado que otras bandas de frecuencia y es menos probable que experimente interferencias de otros dispositivos.

## Puertas de coche

La mayoría de los mandos a distancia de los coches funcionan en frecuencias de **315 MHz o 433 MHz**. Ambas son frecuencias de radio y se utilizan en una variedad de aplicaciones diferentes. La principal diferencia entre las dos frecuencias es que 433 MHz tiene un alcance mayor que 315 MHz. Esto significa que 433 MHz es mejor para aplicaciones que requieren un alcance mayor, como la entrada sin llave.\
En Europa se utiliza comúnmente 433,92 MHz y en EE. UU. y Japón es el 315 MHz.

## Ataque de fuerza bruta

<figure><img src="../../.gitbook/assets/image (4) (3).png" alt=""><figcaption></figcaption></figure>

Si en lugar de enviar cada código 5 veces (enviado de esta manera para asegurarse de que el receptor lo reciba) se envía solo una vez, el tiempo se reduce a 6 minutos:

<figure><img src="../../.gitbook/assets/image (1) (1) (2) (2).png" alt=""><figcaption></figcaption></figure>

y si **se elimina el período de espera de 2 ms** entre señales, se puede **reducir el tiempo a 3 minutos**.

Además, mediante el uso de la secuencia de De Bruijn (una forma de reducir el número de bits necesarios para enviar todos los números binarios potenciales para la fuerza bruta) este **tiempo se reduce a solo 8 segundos**:

<figure><img src="../../.gitbook/assets/image (5) (2) (3).png" alt=""><figcaption></figcaption></figure>

Un ejemplo de este ataque se implementó en [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)

Requerir **un preámbulo evitará la optimización de la secuencia de De Bruijn** y **los códigos rodantes evitarán este ataque** (suponiendo que el código es lo suficientemente largo como para no ser fuerza bruta).

## Ataque Sub-GHz

Para atacar estas señales con Flipper Zero, consulte:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## Protección de códigos rodantes

Los abridores automáticos de puertas de garaje suelen utilizar un control remoto in
