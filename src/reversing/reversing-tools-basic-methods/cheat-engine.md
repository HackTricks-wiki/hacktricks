# Cheat Engine

{{#include ../../banners/hacktricks-training.md}}

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) es un programa útil para encontrar dónde se guardan valores importantes dentro de la memoria de un juego en ejecución y cambiarlos.\
Cuando lo descargas y ejecutas, se te **presenta** un **tutorial** sobre cómo usar la herramienta. Si quieres aprender a usarla, se recomienda encarecidamente completarlo.

## ¿Qué estás buscando?

![Cheat Engine - ¿Qué estás buscando?: ¿Qué estás buscando?](<../../images/image (762).png>)

Esta herramienta es muy útil para encontrar **dónde se almacena algún valor** (normalmente un número) **en la memoria** de un programa.\
**Normalmente, los números** se almacenan en formato de **4bytes**, pero también puedes encontrarlos en formatos **double** o **float**, o puede que quieras buscar algo **diferente de un número**. Por esa razón, debes asegurarte de **seleccionar** lo que quieres **buscar**:

![Cheat Engine - ¿Qué estás buscando?: Normalmente, los números se almacenan en formato 4bytes, pero también puedes encontrarlos en formatos double o float, o puede que quieras buscar algo...](<../../images/image (324).png>)

También puedes indicar **distintos** tipos de **búsquedas**:

![Cheat Engine - ¿Qué estás buscando?: También puedes indicar distintos tipos de búsquedas](<../../images/image (311).png>)

También puedes marcar la casilla para **detener el juego mientras se escanea la memoria**:

![Cheat Engine - ¿Qué estás buscando?: También puedes marcar la casilla para detener el juego mientras se escanea la memoria](<../../images/image (1052).png>)

### Hotkeys

En _**Edit --> Settings --> Hotkeys**_ puedes establecer distintas **hotkeys** para diferentes propósitos, como **detener** el **juego** (lo cual es bastante útil si en algún momento quieres escanear la memoria). Hay otras opciones disponibles:

![¿Qué estás buscando? - Hotkeys: En Edit -- Settings -- Hotkeys puedes establecer distintas hotkeys para diferentes propósitos, como detener el juego (lo cual es bastante útil si en algún momento...](<../../images/image (864).png>)

## Modifying the value

Una vez que hayas **encontrado** dónde está el **valor** que estás **buscando** (hablaremos más sobre esto en los siguientes pasos), puedes **modificarlo** haciendo doble clic sobre él y, después, doble clic sobre su valor:

![Hotkeys - Modifying the value: Una vez que hayas encontrado dónde está el valor que estás buscando (hablaremos más sobre esto en los siguientes pasos), puedes modificarlo haciendo doble clic sobre él y, después, doble clic...](<../../images/image (563).png>)

Y, finalmente, **marcando la casilla** para aplicar la modificación en la memoria:

![Hotkeys - Modifying the value: Y, finalmente, marcando la casilla para aplicar la modificación en la memoria](<../../images/image (385).png>)

El **cambio** en la **memoria** se **aplicará** inmediatamente (ten en cuenta que, hasta que el juego no vuelva a utilizar este valor, el valor **no se actualizará en el juego**).

## Searching the value

Así que vamos a suponer que existe un valor importante (como la vida de tu usuario) que quieres mejorar y que estás buscando este valor en la memoria)

### Through a known change

Suponiendo que estás buscando el valor 100, **realizas un escaneo** buscando ese valor y encuentras muchas coincidencias:

![Searching the value - Through a known change: Suponiendo que estás buscando el valor 100, realizas un escaneo buscando ese valor y encuentras muchas coincidencias](<../../images/image (108).png>)

Después, haces algo para que **el valor cambie**, **detienes** el juego y **realizas un **next scan**:

![Searching the value - Through a known change: Después, haces algo para que el valor cambie, detienes el juego y realizas un next scan](<../../images/image (684).png>)

Cheat Engine buscará los **valores** que **pasaron de 100 al nuevo valor**. Enhorabuena, has **encontrado** la **dirección** del valor que estabas buscando; ahora puedes modificarlo.\
_Si todavía tienes varios valores, haz algo para modificar de nuevo ese valor y realiza otro "next scan" para filtrar las direcciones._

### Unknown Value, known change

En el escenario en el que **no conoces el valor**, pero sabes **cómo hacer que cambie** (e incluso el valor del cambio), puedes buscar tu número.

Comienza realizando un escaneo de tipo "**Unknown initial value**":

![Through a known change - Unknown Value, known change: Comienza realizando un escaneo de tipo " Unknown initial value "](<../../images/image (890).png>)

Después, haz que cambie el valor, indica **cómo** **cambió el valor** (en mi caso, disminuyó en 1) y realiza un **next scan**:

![Through a known change - Unknown Value, known change: Después, haz que cambie el valor, indica cómo cambió el valor (en mi caso, disminuyó en 1) y realiza un next scan](<../../images/image (371).png>)

Se te mostrarán **todos los valores que se modificaron de la forma seleccionada**:

![Through a known change - Unknown Value, known change: Se te mostrarán todos los valores que se modificaron de la forma seleccionada](<../../images/image (569).png>)

Una vez que hayas encontrado tu valor, puedes modificarlo.

Ten en cuenta que existen **muchos cambios posibles** y que puedes realizar estos **pasos tantas veces como quieras** para filtrar los resultados:

![Through a known change - Unknown Value, known change: Ten en cuenta que existen muchos cambios posibles y que puedes realizar estos pasos tantas veces como quieras para filtrar los resultados](<../../images/image (574).png>)

### Random Memory Address - Finding the code

Hasta ahora hemos aprendido a encontrar una dirección que almacena un valor, pero es muy probable que en **distintas ejecuciones del juego esa dirección se encuentre en diferentes lugares de la memoria**. Así que veamos cómo encontrar siempre esa dirección.

Usando algunos de los trucos mencionados, encuentra la dirección donde tu juego actual está almacenando el valor importante. Después (deteniendo el juego si lo deseas), haz **clic derecho** en la **dirección** encontrada y selecciona "**Find out what accesses this address**" o "**Find out what writes to this address**":

![Unknown Value, known change - Random Memory Address - Finding the code: Usando algunos de los trucos mencionados, encuentra la dirección donde tu juego actual está almacenando el valor importante. Después...](<../../images/image (1067).png>)

La **primera opción** es útil para saber qué **partes** del **código** están **usando** esta **dirección** (lo cual resulta útil para otras cosas, como **saber dónde puedes modificar el código** del juego).\
La **segunda opción** es más **específica** y será más útil en este caso, ya que nos interesa saber **desde dónde se está escribiendo este valor**.

Una vez que hayas seleccionado una de esas opciones, el **debugger** se **adjuntará** al programa y aparecerá una nueva **ventana vacía**. Ahora, **juega** y **modifica** ese **valor** (sin reiniciar el juego). La **ventana** debería **llenarse** con las **direcciones** que están **modificando** el **valor**:

![Unknown Value, known change - Random Memory Address - Finding the code: Una vez que hayas seleccionado una de esas opciones, el debugger se adjuntará al programa y aparecerá una nueva ventana vacía...](<../../images/image (91).png>)

Ahora que has encontrado la dirección que modifica el valor, puedes **modificar el código como prefieras** (Cheat Engine permite modificarlo rápidamente con NOPs):

![Unknown Value, known change - Random Memory Address - Finding the code: Ahora que has encontrado la dirección que modifica el valor, puedes modificar el código como prefieras (Cheat Engine...](<../../images/image (1057).png>)

Así que ahora puedes modificarlo para que el código no afecte a tu número o para que siempre lo afecte de forma positiva.

### Random Memory Address - Finding the pointer

Siguiendo los pasos anteriores, encuentra dónde está el valor que te interesa. Después, usando "**Find out what writes to this address**", averigua qué dirección escribe este valor y haz doble clic sobre ella para obtener la vista de desensamblado:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Siguiendo los pasos anteriores, encuentra dónde está el valor que te interesa. Después, usando " Find out...](<../../images/image (1039).png>)

Después, realiza un nuevo escaneo **buscando el valor hexadecimal entre "\[]"** (el valor de $edx en este caso):

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Después, realiza un nuevo escaneo buscando el valor hexadecimal entre " ()" (el valor de $edx en este caso)](<../../images/image (994).png>)

(_Si aparecen varios, normalmente necesitas el de la dirección más pequeña_)\
Ahora hemos **encontrado el puntero que modificará el valor que nos interesa**.

Haz clic en "**Add Address Manually**":

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Haz clic en " Add Address Manually "](<../../images/image (990).png>)

Ahora, marca la casilla "Pointer" y añade la dirección encontrada en el cuadro de texto (en este escenario, la dirección encontrada en la imagen anterior era "Tutorial-i386.exe"+2426B0):

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Ahora, marca la casilla "Pointer" y añade la dirección encontrada en el cuadro de texto (en este escenario,...](<../../images/image (392).png>)

(Observa que el primer "Address" se completa automáticamente con la dirección del puntero que introduces)

Haz clic en OK y se creará un nuevo puntero:

![Random Memory Address - Finding the code - Random Memory Address - Finding the pointer: Haz clic en OK y se creará un nuevo puntero](<../../images/image (308).png>)

Ahora, cada vez que modifiques ese valor estarás **modificando el valor importante, incluso si la dirección de memoria donde se encuentra el valor es diferente.**

### Code Injection

Code injection es una técnica en la que inyectas un fragmento de código en el proceso objetivo y, después, rediriges la ejecución del código para que pase por tu propio código escrito (por ejemplo, dándote puntos en lugar de quitártelos).

Imagina que has encontrado la dirección que resta 1 a la vida de tu jugador:

![Random Memory Address - Finding the pointer - Code Injection: Imagina que has encontrado la dirección que resta 1 a la vida de tu jugador](<../../images/image (203).png>)

Haz clic en Show disassembler para obtener el **código desensamblado**.\
Después, pulsa **CTRL+a** para abrir la ventana Auto assemble y selecciona _**Template --> Code Injection**_

![Random Memory Address - Finding the pointer - Code Injection: Después, pulsa CTRL+a para abrir la ventana Auto assemble y selecciona Template -- Code Injection](<../../images/image (902).png>)

Rellena la **dirección de la instrucción que quieres modificar** (normalmente se completa automáticamente):

![Random Memory Address - Finding the pointer - Code Injection: Rellena la dirección de la instrucción que quieres modificar (normalmente se completa automáticamente)](<../../images/image (744).png>)

Se generará una plantilla:

![Random Memory Address - Finding the pointer - Code Injection: Se generará una plantilla](<../../images/image (944).png>)

Ahora, inserta tu nuevo código assembly en la sección "**newmem**" y elimina el código original de "**originalcode**" si no quieres que se ejecute**.** En este ejemplo, el código inyectado añadirá 2 puntos en lugar de restar 1:

![Random Memory Address - Finding the pointer - Code Injection: Ahora, inserta tu nuevo código assembly en la sección " newmem " y elimina el código original de " originalcode " si no...](<../../images/image (521).png>)

**¡Haz clic en execute y demás, y tu código debería inyectarse en el programa, cambiando el comportamiento de la funcionalidad!**

## Relocation-safe code injection with AOB signatures

Un script que hace hook en `game.exe+123456` puede dejar de funcionar después de ASLR o de una actualización del software. Una **Array of Bytes (AOB) signature** encuentra la instrucción a partir del código máquina que la rodea. Usa `aobscanmodule` para limitar la búsqueda a un módulo. Haz que la signature sea lo bastante larga como para devolver una sola coincidencia. Usa wildcards para los bytes de relocation, las direcciones y otros bytes que puedan cambiar. No uses wildcards para toda la instrucción que necesitas restaurar.<sup>[[4]](#references)</sup>

En Memory View, selecciona la instrucción y usa **Tools → Auto Assemble → Template → AOB Injection**. El bloque `[DISABLE]` generado es importante. Debe restaurar todos los bytes sobrescritos y liberar la allocation.<sup>[[4]](#references)</sup>

<details>
<summary>Esqueleto mínimo de AOB injection para x64</summary>
```asm
[ENABLE]
aobscanmodule(INJECT,game.exe,F3 0F 11 83 A0 00 00 00 48 8B)
alloc(newmem,1024,INJECT)
label(return)
registersymbol(INJECT)
newmem:
movss [rbx+000000A0],xmm0
jmp return
INJECT:
jmp newmem
nop
nop
nop
return:
[DISABLE]
INJECT:
db F3 0F 11 83 A0 00 00 00
unregistersymbol(INJECT)
dealloc(newmem)
```
</details>

Antes de habilitar el script, verifica estos puntos:

1. El AOB devuelve **una** dirección. Añade instrucciones estables a ambos lados si devuelve más de una.
2. El salto reemplaza instrucciones completas. Nunca dividas una instrucción.
3. La cave asignada es accesible mediante el salto generado. En x64, una asignación lejana puede requerir un salto de 14 bytes.
4. El código inyectado conserva los registros, las flags y la alineación de la pila que espera la función original.
5. El bloque de deshabilitación restaura los bytes originales exactos. Prueba habilitarlo y deshabilitarlo varias veces antes de guardar la tabla.

## Flujo de trabajo fiable con punteros

Un puntero encontrado en una ejecución solo es un candidato. Crea mapas de punteros en varias ejecuciones nuevas y vuelve a escanearlos contra todas ellas. Reinicia el objetivo entre capturas para que cambien ASLR y las asignaciones del heap. Prefiere rutas cuya base sea un módulo u otro símbolo estable. Descarta las rutas que solo funcionen con una partida guardada, nivel o instancia de objeto.

El filtro **pointer must end with specific offsets** y su opción de desviación pueden conservar rutas útiles cuando un campo cercano cambia entre builds. La versión 7.5 también añadió este control de desviación. Es un filtro, no una prueba de que una cadena de punteros sea estable.<sup>[[1]](#references)</sup>

Cuando una estructura cambia demasiado a menudo para el pointer scanning, hookea la instrucción que accede a ella. Captura el puntero al objeto activo desde un registro y guárdalo en un símbolo asignado. Esto suele ser más fiable para listas de entidades y objetos gestionados.

## Trazar el código en lugar de escanear valores

Usa **Find out what writes to this address** cuando el valor se modifique directamente. Usa **Find out what accesses this address** cuando necesites el objeto propietario o cuando la escritura se realice mediante datos copiados. Activa una sola acción en el objetivo. Después, compara el número de hits y el estado de los registros.

**Ultimap 2** usa Intel Processor Trace en CPUs Intel compatibles. Registra el flujo de control ejecutado con menos interrupciones que avanzar instrucción por instrucción. Filtra el código que se ejecutó mientras ocurría la acción de interés y elimina el código que también se ejecutó durante una captura en reposo. Intel PT no es una función de stealth. El objetivo aún puede detectar el tracing, los cambios de timing o el propio Cheat Engine.<sup>[[1]](#references)</sup>

Cheat Engine 7.5 también añadió una interfaz Intel PT proporcionada por Windows. El modo Ultimap anterior basado en DBVM y el modo Intel PT tienen requisitos de hardware y sistema operativo diferentes. No asumas que una CPU compatible con DBVM admite Intel PT.<sup>[[1]](#references)</sup>

## Selección del debugger y de los breakpoints

Elige el debugger menos invasivo que funcione:

- **Windows debugger** es sencillo, pero crea eventos de depuración normales. Las comprobaciones anti-debugging pueden detectarlo.
- **VEH debugger** gestiona los breakpoints mediante un manejador de excepciones vectorizado. Evita algunas comprobaciones básicas de debugger, pero no es invisible.
- **Hardware breakpoints** no modifican los bytes de la instrucción, pero x86/x64 solo proporciona un número reducido de slots en los registros de depuración.
- **Software breakpoints** reemplazan un byte por `INT3`. Son fáciles de detectar y pueden entrar en conflicto con las comprobaciones de integridad.
- **DBVM debugger** mueve algunas operaciones por debajo del guest OS. Tiene muchos más privilegios y puede bloquear el host si está mal configurado.

Cheat Engine 7.5 puede usar un salto de un byte basado en un exception handler y `INT3` cuando no hay espacio suficiente para un salto relativo normal. Trátalo como un software breakpoint. Verifica el flujo de excepciones y no asumas que elude las comprobaciones anti-tamper.<sup>[[1]](#references)</sup>

DBVM es un hypervisor, no un interruptor general de invisibilidad. Úsalo únicamente en un lab desechable. No expongas su interfaz de control a código no confiable. Los productos kernel anti-cheat y endpoint aún pueden detectar el driver, el estado del hypervisor o la memoria modificada.

## Managed runtimes y funciones recientes de 7.6/7.7

Para objetivos Mono, IL2CPP, .NET y Java, prioriza los metadatos del runtime en lugar de los blind scans cuando estén disponibles. Abre **Mono → Activate mono features** o la ventana de información del runtime correspondiente. Localiza primero la clase, el campo o el método. Después usa el native disassembly cuando el método gestionado se compile mediante JIT.

La rama 7.6 añadió `AOBSCANEX` para firmas que solo buscan en memoria ejecutable, una interfaz de debugger `gdbserver`, inspección de metadatos de Java, una enumeración IL2CPP más rápida y una opción de pointer scan que ignora el byte superior del puntero utilizado por el etiquetado de memoria de ARM. La rama 7.7 añadió builds nativos para Linux, `HOOK`/`UNHOOK`, `aobscanfunction`, una búsqueda mejorada de métodos genéricos de Mono, soporte mejorado para estructuras PDB y disección básica de estructuras de Unreal Engine.<sup>[[3]](#references)</sup>

Estas incorporaciones permiten un flujo de trabajo útil:

1. Resuelve un método gestionado o un campo estático a partir de los metadatos.
2. Traza o desensambla el código nativo generado para ese método.
3. Usa `AOBSCANEX` o `aobscanfunction` para localizar una firma ejecutable estable.
4. Genera un hook reversible. Conserva las instrucciones originales y valida la ruta de deshabilitación.
5. Vuelve a comprobar la firma después de cada actualización del objetivo. Una coincidencia correcta no garantiza que la lógica circundante conserve el mismo significado.

## Objetivos remotos con `ceserver`

`ceserver` expone la enumeración de procesos, el acceso a memoria y la depuración a la GUI de Cheat Engine. Las builds oficiales cubren Linux y Android. Ejecuta la arquitectura correspondiente en el objetivo y conéctate mediante la pestaña **Network**. En Android, reenviar el puerto predeterminado evita exponerlo en la red:<sup>[[3]](#references)</sup>
```bash
adb push ceserver_arm64 /data/local/tmp/ceserver
adb shell 'su -c "chmod 700 /data/local/tmp/ceserver && /data/local/tmp/ceserver"'
adb forward tcp:52736 tcp:52736
```
El bridge de terceros `frida-ceserver` puede proporcionar una interfaz compatible con Cheat Engine para objetivos iOS. No es el `ceserver` oficial y sus operaciones compatibles pueden diferir.<sup>[[2]](#references)</sup>

Supón que el protocolo concede acceso de nivel depurador. Enlázalo a loopback o colócalo detrás de un túnel SSH/ADB. Nunca expongas el puerto TCP 52736 a una red que no sea de confianza. Detén el servidor cuando finalice la sesión.

## Seguridad operativa

Conéctate únicamente a software que te pertenezca o que tengas autorización para probar. No ejecutes Cheat Engine junto a un juego online o un endpoint de producción. Las escrituras en memoria, el código inyectado, los drivers y DBVM pueden bloquear o corromper el objetivo.<sup>[[3]](#references)</sup>

Descarga las builds desde el sitio oficial o compila el código fuente publicado. Los productos de seguridad suelen clasificar los editores de memoria, los depuradores y sus drivers como hack tools. No desactives globalmente la protección del host. Usa una VM o un host de laboratorio dedicado y verifica el artifact antes de ejecutarlo.<sup>[[3]](#references)</sup>



## References

- [1] [Notas de lanzamiento de Cheat Engine 7.5](https://github.com/cheat-engine/cheat-engine/releases/tag/7.5)
- [2] [Bridge frida-ceserver para objetivos remotos](https://github.com/gmh5225/frida-ceserver)
- [3] [Noticias oficiales de lanzamiento de Cheat Engine](https://www.cheatengine.org/)
- [4] [Wiki de Cheat Engine: AOBs de Auto Assembler](https://wiki.cheatengine.org/index.php?title=Tutorials:AOBs)
{{#include ../../banners/hacktricks-training.md}}
