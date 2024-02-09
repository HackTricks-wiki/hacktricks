# SmbExec/ScExec

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Cómo Funciona

**Smbexec** es una herramienta utilizada para la ejecución remota de comandos en sistemas Windows, similar a **Psexec**, pero evita colocar archivos maliciosos en el sistema objetivo.

### Puntos Clave sobre **SMBExec**

- Opera creando un servicio temporal (por ejemplo, "BTOBTO") en la máquina objetivo para ejecutar comandos a través de cmd.exe (%COMSPEC%), sin dejar caer ningún binario.
- A pesar de su enfoque sigiloso, genera registros de eventos para cada comando ejecutado, ofreciendo una forma de "shell" no interactiva.
- El comando para conectarse usando **Smbexec** se ve así:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Ejecución de Comandos Sin Binarios

- **Smbexec** permite la ejecución directa de comandos a través de binPaths de servicios, eliminando la necesidad de binarios físicos en el objetivo.
- Este método es útil para ejecutar comandos de una sola vez en un objetivo de Windows. Por ejemplo, al combinarlo con el módulo `web_delivery` de Metasploit, se permite la ejecución de una carga útil de Meterpreter inverso dirigida a PowerShell.
- Al crear un servicio remoto en la máquina del atacante con binPath configurado para ejecutar el comando proporcionado a través de cmd.exe, es posible ejecutar la carga útil con éxito, logrando la devolución de llamada y la ejecución de la carga útil con el escucha de Metasploit, incluso si se producen errores de respuesta del servicio.

### Ejemplo de Comandos

La creación y el inicio del servicio se pueden lograr con los siguientes comandos:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Para más detalles, consulta [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


## Referencias
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
