# Número de serie de macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Los dispositivos Apple fabricados después de 2010 generalmente tienen números de serie alfanuméricos de **12 caracteres**, con los **primeros tres dígitos que representan la ubicación de fabricación**, los siguientes **dos** que indican el **año** y la **semana** de fabricación, los siguientes **tres** dígitos proporcionan un **identificador único**, y los **últimos cuatro** dígitos representan el **número de modelo**.

Ejemplo de número de serie: **C02L13ECF8J2**

### **3 - Ubicaciones de fabricación**

| Código | Fábrica                                      |
| ------ | -------------------------------------------- |
| FC     | Fountain Colorado, EE. UU.                   |
| F      | Fremont, California, EE. UU.                 |
| XA, XB, QP, G8 | EE. UU.                                          |
| RN     | México                                       |
| CK     | Cork, Irlanda                                 |
| VM     | Foxconn, Pardubice, República Checa           |
| SG, E  | Singapur                                     |
| MB     | Malasia                                      |
| PT, CY | Corea                                        |
| EE, QT, UV | Taiwán                                       |
| FK, F1, F2 | Foxconn - Zhengzhou, China                   |
| W8     | Shanghai, China                              |
| DL, DM | Foxconn - China                              |
| DN     | Foxconn, Chengdu, China                      |
| YM, 7J | Hon Hai/Foxconn, China                       |
| 1C, 4H, WQ, F7 | China                                        |
| C0     | Tech Com - Subsidiaria de Quanta Computer, China |
| C3     | Foxxcon, Shenzhen, China                     |
| C7     | Pentragon, Changhai, China                   |
| RM     | Remanufacturado                               |

### 1 - Año de fabricación

| Código | Lanzamiento              |
| ------ | ------------------------ |
| C      | 2010/2020 (1er semestre) |
| D      | 2010/2020 (2do semestre) |
| F      | 2011/2021 (1er semestre) |
| G      | 2011/2021 (2do semestre) |
| H      | 2012/... (1er semestre)  |
| J      | 2012 (2do semestre)      |
| K      | 2013 (1er semestre)      |
| L      | 2013 (2do semestre)      |
| M      | 2014 (1er semestre)      |
| N      | 2014 (2do semestre)      |
| P      | 2015 (1er semestre)      |
| Q      | 2015 (2do semestre)      |
| R      | 2016 (1er semestre)      |
| S      | 2016 (2do semestre)      |
| T      | 2017 (1er semestre)      |
| V      | 2017 (2do semestre)      |
| W      | 2018 (1er semestre)      |
| X      | 2018 (2do semestre)      |
| Y      | 2019 (1er semestre)      |
| Z      | 2019 (2do semestre)      |

### 1 - Semana de fabricación

El quinto carácter representa la semana en que se fabricó el dispositivo. Hay 28 caracteres posibles en este lugar: **los dígitos del 1 al 9 se utilizan para representar las primeras nueve semanas**, y las **letras C a Y**, **excluyendo** las vocales A, E, I, O y U, y la letra S, representan las **semanas diez a veintisiete**. Para los dispositivos fabricados en la **segunda mitad del año, se agrega 26** al número representado por el quinto carácter del número de serie. Por ejemplo, un producto con un número de serie cuyos cuarto y quinto dígitos son "JH" fue fabricado en la semana 40 de 2012.

### 3 - Código único

Los siguientes tres dígitos son un código identificador que **sirve para diferenciar cada dispositivo Apple del mismo modelo** que se fabrica en la misma ubicación y durante la misma semana del mismo año, asegurando que cada dispositivo tenga un número de serie diferente.

### 4 - Número de serie

Los últimos cuatro dígitos del número de serie representan el **modelo del producto**.

### Referencia

{% embed url="https://beetstech.com/blog/decode-meaning-behind-apple-serial-number" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/c
