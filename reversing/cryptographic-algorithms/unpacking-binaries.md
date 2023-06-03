# Identificación de binarios empaquetados

* **Falta de cadenas**: Es común encontrar que los binarios empaquetados no tienen casi ninguna cadena.
* Muchas **cadenas no utilizadas**: Además, cuando un malware utiliza algún tipo de empaquetador comercial, es común encontrar muchas cadenas sin referencias cruzadas. Incluso si estas cadenas existen, eso no significa que el binario no esté empaquetado.
* También se pueden utilizar algunas herramientas para intentar encontrar qué empaquetador se utilizó para empaquetar un binario:
  * [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
  * [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
  * [Language 2000](http://farrokhi.net/language/)

# Recomendaciones básicas

* **Comience** analizando el binario empaquetado **desde abajo en IDA y muévase hacia arriba**. Los desempaquetadores salen una vez que el código desempaquetado sale, por lo que es poco probable que el desempaquetador pase la ejecución al código desempaquetado al principio.
* Busque **JMP's** o **CALLs** a **registros** o **regiones** de **memoria**. También busque **funciones que empujen argumentos y una dirección de dirección y luego llamen a `retn`**, porque el retorno de la función en ese caso puede llamar a la dirección que acaba de ser empujada a la pila antes de llamarla.
* Ponga un **punto de interrupción** en `VirtualAlloc`, ya que esto asigna espacio en memoria donde el programa puede escribir código desempaquetado. Ejecute hasta el código de usuario o use F8 para **obtener el valor dentro de EAX** después de ejecutar la función y "**sigua esa dirección en el volcado**". Nunca se sabe si esa es la región donde se va a guardar el código desempaquetado.
  * **`VirtualAlloc`** con el valor "**40**" como argumento significa Leer+Escribir+Ejecutar (se va a copiar algún código que necesita ejecución aquí).
* **Mientras desempaqueta** el código, es normal encontrar **varias llamadas** a **operaciones aritméticas** y funciones como **`memcopy`** o **`Virtual`**`Alloc`. Si se encuentra en una función que aparentemente solo realiza operaciones aritméticas y tal vez alguna `memcopy`, la recomendación es intentar **encontrar el final de la función** (tal vez un JMP o llamada a algún registro) **o** al menos la **llamada a la última función** y ejecutarla, ya que el código no es interesante.
* Mientras desempaqueta el código, **tenga en cuenta** cada vez que **cambia la región de memoria**, ya que un cambio de región de memoria puede indicar el **inicio del código desempaquetado**. Puede volcar fácilmente una región de memoria usando Process Hacker (proceso --> propiedades --> memoria).
* Mientras intenta desempaquetar el código, una buena manera de **saber si ya está trabajando con el código desempaquetado** (para que pueda simplemente volcarlo) es **verificar las cadenas del binario**. Si en algún momento realiza un salto (tal vez cambiando la región de memoria) y nota que **se agregaron muchas más cadenas**, entonces puede saber que **está trabajando con el código desempaquetado**.\
  Sin embargo, si el empaquetador ya contiene muchas cadenas, puede ver cuántas cadenas contienen la palabra "http" y ver si este número aumenta.
* Cuando se vuelca un ejecutable desde una región de memoria, se pueden corregir algunos encabezados usando [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
