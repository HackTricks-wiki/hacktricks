# Número de Serie de macOS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Los dispositivos Apple fabricados después de 2010 generalmente tienen números de serie **alfanuméricos de 12 caracteres**, con los **primeros tres dígitos representando el lugar de fabricación**, los siguientes **dos** indicando el **año** y **semana** de fabricación, los siguientes **tres** dígitos proporcionando un **identificador único**, y los **últimos** **cuatro dígitos representando el número de modelo**.

Ejemplo de número de serie: **C02L13ECF8J2**

### **3 - Lugares de fabricación**

| Código         | Fábrica                                      |
| -------------- | -------------------------------------------- |
| FC             | Fountain Colorado, EE.UU.                    |
| F              | Fremont, California, EE.UU.                  |
| XA, XB, QP, G8 | EE.UU.                                       |
| RN             | México                                       |
| CK             | Cork, Irlanda                                |
| VM             | Foxconn, Pardubice, República Checa          |
| SG, E          | Singapur                                     |
| MB             | Malasia                                      |
| PT, CY         | Corea                                        |
| EE, QT, UV     | Taiwán                                       |
| FK, F1, F2     | Foxconn – Zhengzhou, China                   |
| W8             | Shanghai China                               |
| DL, DM         | Foxconn – China                              |
| DN             | Foxconn, Chengdu, China                      |
| YM, 7J         | Hon Hai/Foxconn, China                       |
| 1C, 4H, WQ, F7 | China                                        |
| C0             | Tech Com – Filial de Quanta Computer, China  |
| C3             | Foxxcon, Shenzhen, China                     |
| C7             | Pentragon, Changhai, China                   |
| RM             | Reacondicionado/remodelado                   |

### 1 - Año de fabricación

| Código | Lanzamiento           |
| ------ | --------------------- |
| C      | 2010/2020 (1.ª mitad) |
| D      | 2010/2020 (2.ª mitad) |
| F      | 2011/2021 (1.ª mitad) |
| G      | 2011/2021 (2.ª mitad) |
| H      | 2012/... (1.ª mitad)  |
| J      | 2012 (2.ª mitad)      |
| K      | 2013 (1.ª mitad)      |
| L      | 2013 (2.ª mitad)      |
| M      | 2014 (1.ª mitad)      |
| N      | 2014 (2.ª mitad)      |
| P      | 2015 (1.ª mitad)      |
| Q      | 2015 (2.ª mitad)      |
| R      | 2016 (1.ª mitad)      |
| S      | 2016 (2.ª mitad)      |
| T      | 2017 (1.ª mitad)      |
| V      | 2017 (2.ª mitad)      |
| W      | 2018 (1.ª mitad)      |
| X      | 2018 (2.ª mitad)      |
| Y      | 2019 (1.ª mitad)      |
| Z      | 2019 (2.ª mitad)      |

### 1 - Semana de fabricación

El quinto carácter representa la semana en la que se fabricó el dispositivo. Hay 28 caracteres posibles en este lugar: **los dígitos del 1 al 9 se utilizan para representar desde la primera hasta la novena semana**, y los **caracteres de la C a la Y**, **excluyendo** las vocales A, E, I, O y U, y la letra S, representan **desde la décima hasta la vigésimo séptima semana**. Para dispositivos fabricados en la **segunda mitad del año, se añaden 26** al número representado por el quinto carácter del número de serie. Por ejemplo, un producto con un número de serie cuyos cuarto y quinto dígitos son “JH” fue fabricado en la 40.ª semana de 2012.

### 3 - Código Único

Los siguientes tres dígitos son un código identificador que **sirve para diferenciar cada dispositivo Apple del mismo modelo** que se fabrica en el mismo lugar y durante la misma semana del mismo año, asegurando que cada dispositivo tenga un número de serie diferente.

### 4 - Número de serie

Los últimos cuatro dígitos del número de serie representan el **modelo del producto**.

### Referencia

{% embed url="https://beetstech.com/blog/decode-meaning-behind-apple-serial-number" %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
