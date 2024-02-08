# Número de Serie de macOS

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


## Información Básica

Los dispositivos de Apple posteriores a 2010 tienen números de serie que constan de **12 caracteres alfanuméricos**, donde cada segmento transmite información específica:

- **Primeros 3 Caracteres**: Indican la **ubicación de fabricación**.
- **Caracteres 4 y 5**: Denotan el **año y semana de fabricación**.
- **Caracteres 6 a 8**: Sirven como un **identificador único** para cada dispositivo.
- **Últimos 4 Caracteres**: Especifican el **número de modelo**.

Por ejemplo, el número de serie **C02L13ECF8J2** sigue esta estructura.

### **Ubicaciones de Fabricación (Primeros 3 Caracteres)**
Ciertos códigos representan fábricas específicas:
- **FC, F, XA/XB/QP/G8**: Varios lugares en EE. UU.
- **RN**: México.
- **CK**: Cork, Irlanda.
- **VM**: Foxconn, República Checa.
- **SG/E**: Singapur.
- **MB**: Malasia.
- **PT/CY**: Corea.
- **EE/QT/UV**: Taiwán.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Diferentes lugares en China.
- **C0, C3, C7**: Ciudades específicas en China.
- **RM**: Dispositivos reacondicionados.

### **Año de Fabricación (4to Carácter)**
Este carácter varía desde 'C' (representando la primera mitad de 2010) hasta 'Z' (segunda mitad de 2019), con diferentes letras que indican diferentes períodos semestrales.

### **Semana de Fabricación (5to Carácter)**
Los dígitos 1-9 corresponden a las semanas 1-9. Las letras C-Y (excluyendo vocales y 'S') representan las semanas 10-27. Para la segunda mitad del año, se agrega 26 a este número.

### **Identificador Único (Caracteres 6 a 8)**
Estos tres dígitos garantizan que cada dispositivo, incluso del mismo modelo y lote, tenga un número de serie distinto.

### **Número de Modelo (Últimos 4 Caracteres)**
Estos dígitos identifican el modelo específico del dispositivo.

### Referencia

* [https://beetstech.com/blog/decode-meaning-behind-apple-serial-number](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
