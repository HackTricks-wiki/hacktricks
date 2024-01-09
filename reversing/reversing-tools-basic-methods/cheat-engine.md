<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de HackTricks para AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


[**Cheat Engine**](https://www.cheatengine.org/downloads.php) es un programa útil para encontrar dónde se guardan valores importantes dentro de la memoria de un juego en ejecución y cambiarlos.\
Cuando lo descargas y ejecutas, se te **presenta** un **tutorial** de cómo usar la herramienta. Si quieres aprender a usar la herramienta, es muy recomendable completarlo.

# ¿Qué estás buscando?

![](<../../.gitbook/assets/image (580).png>)

Esta herramienta es muy útil para encontrar **dónde se almacena algún valor** (usualmente un número) **en la memoria** de un programa.\
**Normalmente los números** se almacenan en forma de **4bytes**, pero también podrías encontrarlos en formatos **double** o **float**, o quizás quieras buscar algo **diferente de un número**. Por esa razón necesitas estar seguro de **seleccionar** lo que quieres **buscar**:

![](<../../.gitbook/assets/image (581).png>)

También puedes indicar **diferentes** tipos de **búsquedas**:

![](<../../.gitbook/assets/image (582).png>)

Puedes también marcar la casilla para **detener el juego mientras escaneas la memoria**:

![](<../../.gitbook/assets/image (584).png>)

## Atajos de teclado

En _**Editar --> Configuración --> Atajos de teclado**_ puedes configurar diferentes **atajos de teclado** para distintos propósitos como **detener** el **juego** (lo cual es bastante útil si en algún momento quieres escanear la memoria). Otras opciones están disponibles:

![](<../../.gitbook/assets/image (583).png>)

# Modificando el valor

Una vez que **encuentras** dónde está el **valor** que estás **buscando** (más sobre esto en los siguientes pasos) puedes **modificarlo** haciendo doble clic en él, luego doble clic en su valor:

![](<../../.gitbook/assets/image (585).png>)

Y finalmente **marcando la casilla** para realizar la modificación en la memoria:

![](<../../.gitbook/assets/image (586).png>)

El **cambio** en la **memoria** se **aplicará** inmediatamente (nota que hasta que el juego no utilice este valor de nuevo, el valor **no se actualizará en el juego**).

# Buscando el valor

Entonces, vamos a suponer que hay un valor importante (como la vida de tu usuario) que quieres mejorar, y estás buscando este valor en la memoria)

## A través de un cambio conocido

Suponiendo que estás buscando el valor 100, realizas un **escaneo** buscando ese valor y encuentras muchas coincidencias:

![](<../../.gitbook/assets/image (587).png>)

Luego, haces algo para que **el valor cambie**, y **detienes** el juego y **realizas** un **nuevo escaneo**:

![](<../../.gitbook/assets/image (588).png>)

Cheat Engine buscará los **valores** que **cambiaron de 100 al nuevo valor**. Felicidades, has **encontrado** la **dirección** del valor que buscabas, ahora puedes modificarlo.\
_Si todavía tienes varios valores, haz algo para modificar nuevamente ese valor, y realiza otro "nuevo escaneo" para filtrar las direcciones._

## Valor desconocido, cambio conocido

En el escenario de que **no conoces el valor** pero sabes **cómo hacer que cambie** (e incluso el valor del cambio) puedes buscar tu número.

Entonces, comienza realizando un escaneo de tipo "**Valor inicial desconocido**":

![](<../../.gitbook/assets/image (589).png>)

Luego, haz que el valor cambie, indica **cómo** **cambió el valor** (en mi caso disminuyó en 1) y realiza un **nuevo escaneo**:

![](<../../.gitbook/assets/image (590).png>)

Se te presentarán **todos los valores que fueron modificados de la forma seleccionada**:

![](<../../.gitbook/assets/image (591).png>)

Una vez que has encontrado tu valor, puedes modificarlo.

Nota que hay una **gran cantidad de cambios posibles** y puedes realizar estos **pasos tantas veces como quieras** para filtrar los resultados:

![](<../../.gitbook/assets/image (592).png>)

## Dirección de memoria aleatoria - Encontrando el código

Hasta ahora aprendimos cómo encontrar una dirección que almacena un valor, pero es muy probable que en **diferentes ejecuciones del juego esa dirección esté en diferentes lugares de la memoria**. Así que vamos a descubrir cómo encontrar siempre esa dirección.

Usando algunos de los trucos mencionados, encuentra la dirección donde tu juego actual está almacenando el valor importante. Luego (deteniendo el juego si lo deseas) haz **clic derecho** en la **dirección encontrada** y selecciona "**Descubrir qué accede a esta dirección**" o "**Descubrir qué escribe en esta dirección**":

![](<../../.gitbook/assets/image (593).png>)

La **primera opción** es útil para saber qué **partes** del **código** están **usando** esta **dirección** (lo cual es útil para más cosas como **saber dónde puedes modificar el código** del juego).\
La **segunda opción** es más **específica**, y será más útil en este caso ya que estamos interesados en saber **desde dónde se está escribiendo este valor**.

Una vez que has seleccionado una de esas opciones, el **depurador** se **adjuntará** al programa y aparecerá una nueva **ventana vacía**. Ahora, **juega** y **modifica** ese **valor** (sin reiniciar el juego). La **ventana** se debería **llenar** con las **direcciones** que están **modificando** el **valor**:

![](<../../.gitbook/assets/image (594).png>)

Ahora que encontraste la dirección que está modificando el valor puedes **modificar el código a tu gusto** (Cheat Engine te permite modificarlo por NOPs rápidamente):

![](<../../.gitbook/assets/image (595).png>)

Así, ahora puedes modificarlo para que el código no afecte tu número, o siempre lo afecte de manera positiva.

## Dirección de memoria aleatoria - Encontrando el puntero

Siguiendo los pasos anteriores, encuentra dónde está el valor que te interesa. Luego, usando "**Descubrir qué escribe en esta dirección**" averigua qué dirección escribe este valor y haz doble clic en ella para obtener la vista de desensamblaje:

![](<../../.gitbook/assets/image (596).png>)

Luego, realiza un nuevo escaneo **buscando el valor hexadecimal entre "\[]"** (el valor de $edx en este caso):

![](<../../.gitbook/assets/image (597).png>)

(_Si aparecen varios, normalmente necesitas el de la dirección más pequeña_)\
Ahora, hemos **encontrado el puntero que modificará el valor que nos interesa**.

Haz clic en "**Agregar dirección manualmente**":

![](<../../.gitbook/assets/image (598).png>)

Ahora, marca la casilla "Puntero" y añade la dirección encontrada en el cuadro de texto (en este escenario, la dirección encontrada en la imagen anterior fue "Tutorial-i386.exe"+2426B0):

![](<../../.gitbook/assets/image (599).png>)

(Nota cómo la primera "Dirección" se llena automáticamente a partir de la dirección del puntero que introduces)

Haz clic en OK y se creará un nuevo puntero:

![](<../../.gitbook/assets/image (600).png>)

Ahora, cada vez que modificas ese valor estás **modificando el valor importante incluso si la dirección de memoria donde está el valor es diferente.**

## Inyección de código

La inyección de código es una técnica donde inyectas un fragmento de código en el proceso objetivo, y luego rediriges la ejecución del código para que pase por tu propio código escrito (como darte puntos en lugar de restarlos).

Así que, imagina que has encontrado la dirección que está restando 1 a la vida de tu jugador:

![](<../../.gitbook/assets/image (601).png>)

Haz clic en Mostrar desensamblador para obtener el **código desensamblado**.\
Luego, presiona **CTRL+a** para invocar la ventana de ensamblaje automático y selecciona _**Plantilla --> Inyección de código**_

![](<../../.gitbook/assets/image (602).png>)

Rellena la **dirección de la instrucción que quieres modificar** (esto suele estar prellenado):

![](<../../.gitbook/assets/image (603).png>)

Se generará una plantilla:

![](<../../.gitbook/assets/image (604).png>)

Entonces, inserta tu nuevo código de ensamblaje en la sección "**newmem**" y elimina el código original de la sección "**originalcode**" si no quieres que se ejecute**.** En este ejemplo, el código inyectado sumará 2 puntos en lugar de restar 1:

![](<../../.gitbook/assets/image (605).png>)

**Haz clic en ejecutar y así sucesivamente y tu código debería ser inyectado en el programa cambiando el comportamiento de la funcionalidad!**

# **Referencias**

* **Tutorial de Cheat Engine, complétalo para aprender cómo empezar con Cheat Engine**



<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de HackTricks para AWS)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
