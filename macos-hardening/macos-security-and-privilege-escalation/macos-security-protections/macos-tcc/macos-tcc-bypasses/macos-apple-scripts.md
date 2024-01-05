# macOS Apple Scripts

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Apple Scripts

Es un lenguaje de scripting utilizado para la automatización de tareas **interactuando con procesos remotos**. Facilita mucho **pedir a otros procesos que realicen algunas acciones**. El **malware** puede abusar de estas características para abusar de funciones exportadas por otros procesos.\
Por ejemplo, un malware podría **inyectar código JS arbitrario en páginas abiertas del navegador**. O realizar **clics automáticos** en algunos permisos solicitados al usuario;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Aquí tienes algunos ejemplos: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Encuentra más información sobre malware utilizando applescripts [**aquí**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Los Apple scripts pueden ser fácilmente "**compilados**". Estas versiones pueden ser fácilmente "**descompiladas**" con `osadecompile`

Sin embargo, estos scripts también pueden ser **exportados como "Solo lectura"** (a través de la opción "Exportar..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
y en este caso el contenido no puede ser descompilado ni siquiera con `osadecompile`

Sin embargo, todavía hay algunas herramientas que se pueden utilizar para entender este tipo de ejecutables, [**lee esta investigación para más información**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). La herramienta [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) con [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) será muy útil para entender cómo funciona el script.

<details>

<summary><strong>Aprende AWS hacking de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
