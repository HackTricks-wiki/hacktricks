<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


# Identificando binarios empaquetados

* **Falta de cadenas**: Es común encontrar que los binarios empaquetados no tienen casi ninguna cadena.
* Muchas **cadenas no utilizadas**: Además, cuando un malware está utilizando algún tipo de empaquetador comercial, es común encontrar muchas cadenas sin referencias cruzadas. Incluso si estas cadenas existen, eso no significa que el binario no esté empaquetado.
* También puedes usar algunas herramientas para intentar encontrar qué empaquetador se usó para empaquetar un binario:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Recomendaciones Básicas

* **Comienza** analizando el binario empaquetado **desde abajo en IDA y avanza hacia arriba**. Los desempaquetadores salen una vez que el código desempaquetado sale, por lo que es poco probable que el desempaquetador pase la ejecución al código desempaquetado al principio.
* Busca **JMP's** o **CALLs** a **registros** o **regiones** de **memoria**. También busca **funciones que empujen argumentos y una dirección de dirección y luego llamen a `retn`**, porque el retorno de la función en ese caso puede llamar a la dirección que se acaba de empujar a la pila antes de llamarla.
* Coloca un **punto de interrupción** en `VirtualAlloc` ya que esto asigna espacio en memoria donde el programa puede escribir código desempaquetado. "Ejecutar hasta el código de usuario" o usar F8 para **llegar al valor dentro de EAX** después de ejecutar la función y "**seguir esa dirección en el volcado**". Nunca se sabe si esa es la región donde se va a guardar el código desempaquetado.
* **`VirtualAlloc`** con el valor "**40**" como argumento significa Leer+Escribir+Ejecutar (algún código que necesita ejecución se va a copiar aquí).
* **Mientras desempacas** código, es normal encontrar **varias llamadas** a **operaciones aritméticas** y funciones como **`memcopy`** o **`Virtual`**`Alloc`. Si te encuentras en una función que aparentemente solo realiza operaciones aritméticas y tal vez algo de `memcopy`, la recomendación es intentar **encontrar el final de la función** (quizás un JMP o llamada a algún registro) **o** al menos la **llamada a la última función** y ejecutar hasta entonces ya que el código no es interesante.
* Mientras desempacas código, **nota** cada vez que **cambias de región de memoria** ya que un cambio de región de memoria puede indicar el **inicio del código desempaquetado**. Puedes volcar fácilmente una región de memoria usando Process Hacker (proceso --> propiedades --> memoria).
* Al intentar desempacar código, una buena manera de **saber si ya estás trabajando con el código desempaquetado** (para poder simplemente volcarlo) es **verificar las cadenas del binario**. Si en algún momento realizas un salto (quizás cambiando la región de memoria) y notas que **se agregaron muchas más cadenas**, entonces puedes saber que **estás trabajando con el código desempaquetado**.\
Sin embargo, si el empaquetador ya contiene muchas cadenas, puedes ver cuántas cadenas contienen la palabra "http" y ver si este número aumenta.
* Cuando vuelcas un ejecutable desde una región de memoria, puedes corregir algunos encabezados usando [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).

</details>
