<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# CBC - Encadenamiento de Bloques de Cifrado

En el modo CBC, el **bloque cifrado anterior se utiliza como IV** para hacer XOR con el siguiente bloque:

![Cifrado CBC](https://defuse.ca/images/cbc\_encryption.png)

Para descifrar CBC se realizan las **operaciones opuestas**:

![Descifrado CBC](https://defuse.ca/images/cbc\_decryption.png)

Nótese que se necesita usar una **clave de cifrado** y un **IV**.

# Relleno de Mensajes

Como el cifrado se realiza en **bloques de tamaño fijo**, generalmente se necesita **relleno** en el **último bloque** para completar su longitud.\
Normalmente se utiliza **PKCS7**, que genera un relleno **repitiendo** el **número de bytes necesarios** para **completar** el bloque. Por ejemplo, si al último bloque le faltan 3 bytes, el relleno será `\x03\x03\x03`.

Veamos más ejemplos con **2 bloques de longitud 8 bytes**:

| byte #0 | byte #1 | byte #2 | byte #3 | byte #4 | byte #5 | byte #6 | byte #7 | byte #0  | byte #1  | byte #2  | byte #3  | byte #4  | byte #5  | byte #6  | byte #7  |
| ------- | ------- | ------- | ------- | ------- | ------- | ------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | 6        | **0x02** | **0x02** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | 4        | 5        | **0x03** | **0x03** | **0x03** |
| P       | A       | S       | S       | W       | O       | R       | D       | 1        | 2        | 3        | **0x05** | **0x05** | **0x05** | **0x05** | **0x05** |
| P       | A       | S       | S       | W       | O       | R       | D       | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** | **0x08** |

Note cómo en el último ejemplo el **último bloque estaba lleno, por lo que se generó otro solo con relleno**.

# Oracle de Relleno

Cuando una aplicación descifra datos cifrados, primero descifrará los datos; luego eliminará el relleno. Durante la limpieza del relleno, si un **relleno inválido provoca un comportamiento detectable**, tienes una **vulnerabilidad de oracle de relleno**. El comportamiento detectable puede ser un **error**, una **falta de resultados**, o una **respuesta más lenta**.

Si detectas este comportamiento, puedes **descifrar los datos cifrados** e incluso **cifrar cualquier texto en claro**.

## Cómo explotar

Podrías usar [https://github.com/AonCyberLabs/PadBuster](https://github.com/AonCyberLabs/PadBuster) para explotar este tipo de vulnerabilidad o simplemente hacer
```
sudo apt-get install padbuster
```
Para probar si la cookie de un sitio es vulnerable podrías intentar:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
**La codificación 0** significa que se utiliza **base64** (pero hay otras disponibles, consulta el menú de ayuda).

También podrías **abusar de esta vulnerabilidad para cifrar nuevos datos. Por ejemplo, imagina que el contenido de la cookie es "**_**user=MyUsername**_**", entonces podrías cambiarlo a "\_user=administrator\_" y escalar privilegios dentro de la aplicación. También podrías hacerlo usando `paduster` especificando el parámetro -plaintext**:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 8 -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA==" -plaintext "user=administrator"
```
Si el sitio es vulnerable, `padbuster` intentará automáticamente encontrar cuándo ocurre el error de relleno, pero también puedes indicar el mensaje de error utilizando el parámetro **-error**.
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "" 8 -encoding 0 -cookies "hcon=RVJDQrwUdTRWJUVUeBKkEA==" -error "Invalid padding"
```
## La teoría

En **resumen**, puedes comenzar a descifrar los datos encriptados adivinando los valores correctos que pueden usarse para crear todos los **diferentes rellenos**. Luego, el ataque del oráculo de relleno comenzará a descifrar bytes desde el final hasta el inicio adivinando cuál será el valor correcto que **crea un relleno de 1, 2, 3, etc**.

![](<../.gitbook/assets/image (629) (1) (1).png>)

Imagina que tienes un texto cifrado que ocupa **2 bloques** formados por los bytes de **E0 a E15**.\
Para **descifrar** el **último** **bloque** (**E8** a **E15**), todo el bloque pasa por el "descifrado de cifrado de bloque" generando los **bytes intermedios I0 a I15**.\
Finalmente, cada byte intermedio se **XORea** con los bytes cifrados anteriores (E0 a E7). Entonces:

* `C15 = D(E15) ^ E7 = I15 ^ E7`
* `C14 = I14 ^ E6`
* `C13 = I13 ^ E5`
* `C12 = I12 ^ E4`
* ...

Ahora, es posible **modificar `E7` hasta que `C15` sea `0x01`**, lo que también será un relleno correcto. Entonces, en este caso: `\x01 = I15 ^ E'7`

Así, encontrando E'7, es **posible calcular I15**: `I15 = 0x01 ^ E'7`

Lo que nos permite **calcular C15**: `C15 = E7 ^ I15 = E7 ^ \x01 ^ E'7`

Conociendo **C15**, ahora es posible **calcular C14**, pero esta vez forzando bruscamente el relleno `\x02\x02`.

Este BF es tan complejo como el anterior ya que es posible calcular el `E''15` cuyo valor es 0x02: `E''7 = \x02 ^ I15` por lo que solo es necesario encontrar el **`E'14`** que genera un **`C14` igual a `0x02`**.\
Luego, hacer los mismos pasos para descifrar C14: **`C14 = E6 ^ I14 = E6 ^ \x02 ^ E''6`**

**Sigue esta cadena hasta que descifres todo el texto cifrado.**

## Detección de la vulnerabilidad

Registra una cuenta e inicia sesión con ella.\
Si **inicias sesión muchas veces** y siempre obtienes la **misma cookie**, probablemente haya **algo** **incorrecto** en la aplicación. La **cookie enviada debería ser única** cada vez que inicies sesión. Si la cookie es **siempre** la **misma**, probablemente siempre será válida y **no habrá forma de invalidarla**.

Ahora, si intentas **modificar** la **cookie**, puedes ver que obtienes un **error** de la aplicación.\
Pero si fuerzas bruscamente el relleno (usando padbuster, por ejemplo) logras obtener otra cookie válida para un usuario diferente. Este escenario es altamente probablemente vulnerable a padbuster.

# Referencias

* [https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation](https://en.wikipedia.org/wiki/Block\_cipher\_mode\_of\_operation)


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
