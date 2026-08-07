# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) es un programa útil para encontrar dónde se guardan valores importantes dentro de la memoria de un juego en ejecución y modificarlos.\
Cuando lo descargas y ejecutas, se te **presenta** un **tutorial** sobre cómo usar la herramienta. Si quieres aprender a utilizarla, es muy recomendable completarlo.

## ¿Qué estás buscando?

![Cheat Engine - ¿Qué estás buscando?: ¿Qué estás buscando?](<../../images/image (762).png>)

Esta herramienta es muy útil para encontrar **dónde se almacena algún valor** (normalmente un número) **en la memoria** de un programa.\
**Normalmente, los números** se almacenan en formato de **4bytes**, pero también puedes encontrarlos en formatos **double** o **float**, o quizá quieras buscar algo **diferente de un número**. Por ese motivo, debes asegurarte de **seleccionar** qué quieres **buscar**:

![Cheat Engine - ¿Qué estás buscando?: Normalmente los números se almacenan en formato 4bytes, pero también puedes encontrarlos en formatos double o float, o quizá quieras buscar algo...](<../../images/image (324).png>)

También puedes indicar diferentes tipos de **búsquedas**:

![Cheat Engine - ¿Qué estás buscando?: También puedes indicar diferentes tipos de búsquedas](<../../images/image (311).png>)

También puedes marcar la casilla para **detener el juego mientras se analiza la memoria**:

![Cheat Engine - ¿Qué estás buscando?: También puedes marcar la casilla para detener el juego mientras se analiza la memoria](<../../images/image (1052).png>)

### Hotkeys

En _**Edit --> Settings --> Hotkeys**_ puedes configurar diferentes **hotkeys** para distintos propósitos, como **detener** el **juego** (lo cual resulta bastante útil si en algún momento quieres analizar la memoria). Hay otras opciones disponibles:

![¿Qué estás buscando? - Hotkeys: En Edit -- Settings -- Hotkeys puedes configurar diferentes hotkeys para distintos propósitos, como detener el juego (lo cual resulta bastante útil si en algún momento...](<../../images/image (864).png>)

## Modificar el valor

Una vez que hayas **encontrado** dónde está el **valor** que estás **buscando** (veremos más sobre esto en los siguientes pasos), puedes **modificarlo** haciendo doble clic sobre él y, después, doble clic sobre su valor:

![Hotkeys - Modificar el valor: Una vez que hayas encontrado dónde está el valor que estás buscando (veremos más sobre esto en los siguientes pasos), puedes modificarlo haciendo doble clic sobre él y, después, doble clic...](<../../images/image (563).png>)

Y finalmente **marcando la casilla** para aplicar la modificación en la memoria:

![Hotkeys - Modificar el valor: Y finalmente marcando la casilla para aplicar la modificación en la memoria](<../../images/image (385).png>)

El **cambio** en la **memoria** se **aplicará** inmediatamente (ten en cuenta que, hasta que el juego no vuelva a usar este valor, el valor **no se actualizará en el juego**).

## Buscar el valor

Supongamos que existe un valor importante (como la vida de tu personaje) que quieres mejorar y que estás buscando ese valor en la memoria.

### Mediante un cambio conocido

Supongamos que buscas el valor 100. Realizas un **scan** buscando ese valor y encuentras muchas coincidencias:

![Buscar el valor - Mediante un cambio conocido: Supongamos que buscas el valor 100, realizas un scan buscando ese valor y encuentras muchas coincidencias](<../../images/image (108).png>)

Después, haces algo para que el **valor cambie**, **detienes** el juego y realizas un **next scan**:

![Buscar el valor - Mediante un cambio conocido: Después, haces algo para que el valor cambie, detienes el juego y realizas un next scan](<../../images/image (684).png>)

Cheat Engine buscará los **valores** que **cambiaron de 100 al nuevo valor**. Enhorabuena, has **encontrado** la **dirección** del valor que buscabas y ahora puedes modificarlo.\
_Si todavía tienes varios valores, haz algo para volver a modificar ese valor y realiza otro "next scan" para filtrar las direcciones._

### Valor desconocido, cambio conocido

En el escenario en el que **no conoces el valor**, pero sabes **cómo hacerlo cambiar** (e incluso el valor del cambio), puedes buscarlo.

Comienza realizando un scan del tipo "**Unknown initial value**":

![Mediante un cambio conocido - Valor desconocido, cambio conocido: Comienza realizando un scan del tipo " Unknown initial value "](<../../images/image (890).png>)

Después, haz que cambie el valor, indica **cómo** cambió el **valor** (en mi caso, disminuyó en 1) y realiza un **next scan**:

![Mediante un cambio conocido - Valor desconocido, cambio conocido: Después, haz que cambie el valor, indica cómo cambió el valor (en mi caso, disminuyó en 1) y realiza un next scan](<../../images/image (371).png>)

Se te mostrarán **todos los valores que se modificaron de la forma seleccionada**:

![Mediante un cambio conocido - Valor desconocido, cambio conocido: Se te mostrarán todos los valores que se modificaron de la forma seleccionada](<../../images/image (569).png>)

Cuando hayas encontrado el valor, puedes modificarlo.

Ten en cuenta que existen **muchos cambios posibles** y que puedes realizar estos **pasos tantas veces como quieras** para filtrar los resultados:

![Mediante un cambio conocido - Valor desconocido, cambio conocido: Ten en cuenta que existen muchos cambios posibles y que puedes realizar estos pasos tantas veces como quieras para filtrar los resultados](<../../images/image (574).png>)

### Dirección de memoria aleatoria - Encontrar el código

Hasta ahora hemos aprendido a encontrar una dirección que almacena un valor, pero es muy probable que, en **diferentes ejecuciones del juego, esa dirección se encuentre en distintas ubicaciones de la memoria**. Veamos cómo encontrar siempre esa dirección.

Usando algunos de los trucos mencionados, encuentra la dirección donde el juego actual está almacenando el valor importante. Después (deteniendo el juego si lo deseas), haz **clic derecho** sobre la **dirección** encontrada y selecciona "**Find out what accesses this address**" o "**Find out what writes to this address**":

![Valor desconocido, cambio conocido - Dirección de memoria aleatoria - Encontrar el código: Usando algunos de los trucos mencionados, encuentra la dirección donde el juego actual está almacenando el valor importante. Después...](<../../images/image (1067).png>)

La **primera opción** sirve para saber qué **partes** del **código** están **usando** esta **dirección** (lo cual resulta útil para otras cosas, como **saber dónde puedes modificar el código** del juego).\
La **segunda opción** es más **específica** y será más útil en este caso, ya que nos interesa saber **desde dónde se está escribiendo este valor**.

Una vez seleccionada una de estas opciones, el **debugger** se **adjuntará** al programa y aparecerá una nueva **ventana vacía**. Ahora, **juega** y **modifica** ese **valor** (sin reiniciar el juego). La **ventana** debería **rellenarse** con las **direcciones** que están **modificando** el **valor**:

![Valor desconocido, cambio conocido - Dirección de memoria aleatoria - Encontrar el código: Una vez seleccionada una de estas opciones, el debugger se adjuntará al programa y aparecerá una nueva ventana vacía...](<../../images/image (91).png>)

Ahora que has encontrado la dirección que modifica el valor, puedes **modificar el código como quieras** (Cheat Engine permite modificarlo rápidamente para usar NOPs):

![Valor desconocido, cambio conocido - Dirección de memoria aleatoria - Encontrar el código: Ahora que has encontrado la dirección que modifica el valor, puedes modificar el código como quieras (Cheat Engine...](<../../images/image (1057).png>)

Así, puedes modificarlo para que el código no afecte a tu número o para que siempre lo afecte de forma positiva.

### Dirección de memoria aleatoria - Encontrar el puntero

Siguiendo los pasos anteriores, encuentra dónde está el valor que te interesa. Después, usando "**Find out what writes to this address**", averigua qué dirección escribe este valor y haz doble clic sobre ella para obtener la vista de disassembly:

![Dirección de memoria aleatoria - Encontrar el código - Dirección de memoria aleatoria - Encontrar el puntero: Siguiendo los pasos anteriores, encuentra dónde está el valor que te interesa. Después, usando " Find out...](<../../images/image (1039).png>)

Después, realiza un nuevo scan **buscando el valor hexadecimal entre "\[]"** (el valor de $edx en este caso):

![Dirección de memoria aleatoria - Encontrar el código - Dirección de memoria aleatoria - Encontrar el puntero: Después, realiza un nuevo scan buscando el valor hexadecimal entre " ()" (el valor de $edx en este caso)](<../../images/image (994).png>)

(_Si aparecen varios, normalmente necesitas el que tenga la dirección más pequeña_)\
Ahora hemos **encontrado el puntero que modificará el valor que nos interesa**.

Haz clic en "**Add Address Manually**":

![Dirección de memoria aleatoria - Encontrar el código - Dirección de memoria aleatoria - Encontrar el puntero: Haz clic en " Add Address Manually "](<../../images/image (990).png>)

Ahora, marca la casilla "Pointer" y añade la dirección encontrada en el cuadro de texto (en este escenario, la dirección encontrada en la imagen anterior era "Tutorial-i386.exe"+2426B0):

![Dirección de memoria aleatoria - Encontrar el código - Dirección de memoria aleatoria - Encontrar el puntero: Ahora, marca la casilla "Pointer" y añade la dirección encontrada en el cuadro de texto (en este escenario,...](<../../images/image (392).png>)

(Observa cómo el primer campo "Address" se rellena automáticamente con la dirección del puntero que introduces).

Haz clic en OK y se creará un nuevo puntero:

![Dirección de memoria aleatoria - Encontrar el código - Dirección de memoria aleatoria - Encontrar el puntero: Haz clic en OK y se creará un nuevo puntero](<../../images/image (308).png>)

Ahora, cada vez que modifiques ese valor, estarás **modificando el valor importante aunque la dirección de memoria donde se encuentra sea diferente**.

### Code Injection

Code injection es una técnica en la que inyectas una parte de código en el proceso objetivo y después rediriges la ejecución para que pase por tu propio código (por ejemplo, dándote puntos en lugar de quitártelos).

Imagina que has encontrado la dirección que resta 1 a la vida de tu jugador:

![Dirección de memoria aleatoria - Encontrar el puntero - Code Injection: Imagina que has encontrado la dirección que resta 1 a la vida de tu jugador](<../../images/image (203).png>)

Haz clic en Show disassembler para obtener el **código desensamblado**.\
Después, pulsa **CTRL+a** para abrir la ventana Auto assemble y selecciona _**Template --> Code Injection**_

![Dirección de memoria aleatoria - Encontrar el puntero - Code Injection: Después, pulsa CTRL+a para abrir la ventana Auto assemble y selecciona Template -- Code Injection](<../../images/image (902).png>)

Introduce la **dirección de la instrucción que quieres modificar** (normalmente se rellena automáticamente):

![Dirección de memoria aleatoria - Encontrar el puntero - Code Injection: Introduce la dirección de la instrucción que quieres modificar (normalmente se rellena automáticamente)](<../../images/image (744).png>)

Se generará una plantilla:

![Dirección de memoria aleatoria - Encontrar el puntero - Code Injection: Se generará una plantilla](<../../images/image (944).png>)

Ahora, inserta tu nuevo código assembly en la sección "**newmem**" y elimina el código original de "**originalcode**" si no quieres que se ejecute**.** En este ejemplo, el código inyectado sumará 2 puntos en lugar de restar 1:

![Dirección de memoria aleatoria - Encontrar el puntero - Code Injection: Ahora, inserta tu nuevo código assembly en la sección " newmem " y elimina el código original de " originalcode " si...](<../../images/image (521).png>)

**¡Haz clic en execute y demás, y tu código debería quedar inyectado en el programa, cambiando el comportamiento de la funcionalidad!**

## Funciones avanzadas de Cheat Engine 7.x (2023-2025)

Cheat Engine ha seguido evolucionando desde la versión 7.0 y se han añadido varias funciones de calidad de vida y de *offensive-reversing* que resultan extremadamente útiles al analizar software moderno (¡y no solo juegos!). A continuación se incluye una **guía de campo muy condensada** con las incorporaciones que probablemente utilizarás durante trabajo de red-team/CTF.<sup>[[1]](#references)</sup>

### Mejoras de Pointer Scanner 2
* `Pointers must end with specific offsets` y el nuevo control deslizante **Deviation** (≥7.4) reducen considerablemente los falsos positivos al volver a realizar un scan después de una actualización. Úsalo junto con la comparación de múltiples mapas (`.PTR` → *Compare results with other saved pointer map*) para obtener un **puntero base resistente** en solo unos minutos.
* Atajo para el filtrado masivo: después del primer scan, pulsa `Ctrl+A → Space` para marcarlo todo y, después, `Ctrl+I` (invertir) para deseleccionar las direcciones que no superaron el rescan.

### Ultimap 3 – Intel PT tracing
*Desde la versión 7.5, el antiguo Ultimap se volvió a implementar sobre **Intel Processor-Trace (IPT)**.* Esto significa que ahora puedes registrar *cada branch que ejecuta el objetivo **sin hacer single-stepping*** (solo en user-mode; no activará la mayoría de los gadgets anti-debug).
```
Memory View → Tools → Ultimap 3 → check «Intel PT»
Select number of buffers → Start
```
Después de unos segundos, detén la captura y **haz clic derecho → Save execution list to file**. Combina las direcciones de las ramas con una sesión de `Find out what addresses this instruction accesses` para localizar hotspots de game-logic de alta frecuencia extremadamente rápido.

### Plantillas de `jmp` de 1 byte / auto-patch
La versión 7.5 introdujo un stub de JMP de *one-byte* (0xEB) que instala un handler de SEH y coloca un INT3 en la ubicación original. Se genera automáticamente cuando utilizas **Auto Assembler → Template → Code Injection** en instrucciones que no pueden parchearse con un salto relativo de 5 bytes. Esto permite realizar hooks “tight” dentro de rutinas packed o con restricciones de tamaño.<sup>[[1]](#references)</sup>

### Stealth a nivel de kernel con DBVM (AMD e Intel)
*DBVM* es el hypervisor Type-2 integrado de CE. Las builds recientes añadieron finalmente compatibilidad con **AMD-V/SVM**, por lo que puedes ejecutar `Driver → Load DBVM` en hosts Ryzen/EPYC. DBVM permite:
1. Crear hardware breakpoints invisibles para las comprobaciones de Ring-3/anti-debug.
2. Leer/escribir regiones de memoria del kernel pageable o protegidas incluso cuando el user-mode driver está deshabilitado.
3. Realizar bypasses de timing attacks sin VM-EXIT (por ejemplo, consultar `rdtsc` desde el hypervisor).

**Consejo:** DBVM se negará a cargarse cuando HVCI/Memory-Integrity esté habilitado en Windows 11 → desactívalo o inicia un VM-host dedicado.

### Debugging remoto / cross-platform con **ceserver**
CE ahora incluye una reescritura completa de *ceserver* y puede conectarse mediante TCP a targets en **Linux, Android, macOS e iOS**. Un fork popular integra *Frida* para combinar dynamic instrumentation con la GUI de CE, lo que resulta ideal cuando necesitas parchear juegos de Unity o Unreal que se ejecutan en un teléfono:
```
# on the target (arm64)
./ceserver_arm64 &
# on the analyst workstation
adb forward tcp:52736 tcp:52736   # (or ssh tunnel)
Cheat Engine → "Network" icon → Host = localhost → Connect
```
Para el Frida bridge, consulta `bb33bb/frida-ceserver` en GitHub.<sup>[[1]](#references)[[2]](#references)</sup>

### Otras herramientas destacables
* **Patch Scanner** (MemView → Tools): detecta cambios de código inesperados en secciones ejecutables; resulta útil para el análisis de malware.
* **Structure Dissector 2**: arrastra una dirección → `Ctrl+D` y, a continuación, *Guess fields* para evaluar automáticamente estructuras de C.
* **.NET & Mono Dissector**: mejora la compatibilidad con juegos de Unity; permite llamar a métodos directamente desde la consola Lua de CE.
* **Big-Endian custom types**: escaneo y edición con el orden de bytes invertido, útil para emuladores de consolas y buffers de paquetes de red.
* **Autosave & tabs** para ventanas de AutoAssembler/Lua, además de `reassemble()` para reescribir instrucciones en varias líneas.<sup>[[1]](#references)</sup>

### Notas de instalación y OPSEC (2024-2025)
* El instalador oficial incluye **ofertas publicitarias** de InnoSetup (`RAV`, etc.). **Haz siempre clic en *Decline*** *o compila desde el código fuente* para evitar PUPs. Los AV seguirán marcando `cheatengine.exe` como *HackTool*, lo cual es esperado.
* Los drivers modernos de anti-cheat (EAC/Battleye, ACE-BASE.sys, mhyprot2.sys) detectan la clase de ventana de CE incluso cuando se renombra. Ejecuta tu copia de reversing **dentro de una VM desechable** o después de desactivar el juego en red.
* Si solo necesitas acceso en user-mode, selecciona **`Settings → Extra → Kernel mode debug = off`** para evitar cargar el driver sin firmar de CE, que puede provocar un BSOD en Windows 11 24H2 con Secure-Boot.

---

## Referencias

- [1] [notas de lanzamiento de Cheat Engine 7.5 (GitHub)](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [bridge multiplataforma frida-ceserver](https://github.com/bb33bb/frida-ceserver-Mac-and-IOS)

{{#include ../../banners/hacktricks-training.md}}
