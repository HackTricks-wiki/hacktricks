# SmbExec/ScExec

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Cómo Funciona

**Smbexec** opera de manera similar a **Psexec**, apuntando a **cmd.exe** o **powershell.exe** en el sistema de la víctima para la ejecución de una puerta trasera, evitando el uso de ejecutables maliciosos.

## **SMBExec**
```bash
smbexec.py WORKGROUP/username:password@10.10.10.10
```
La funcionalidad de Smbexec implica crear un servicio temporal (por ejemplo, "BTOBTO") en la máquina objetivo para ejecutar comandos sin dejar un binario. Este servicio, diseñado para ejecutar un comando a través de la ruta de cmd.exe (%COMSPEC%), redirige la salida a un archivo temporal y se elimina a sí mismo después de la ejecución. El método es sigiloso pero genera registros de eventos para cada comando, ofreciendo un "shell" no interactivo repitiendo este proceso para cada comando emitido desde el lado del atacante.

## Ejecución de Comandos Sin Binarios

Este enfoque permite la ejecución directa de comandos a través de binPaths de servicios, eliminando la necesidad de binarios. Es particularmente útil para la ejecución de comandos puntuales en un objetivo Windows. Por ejemplo, utilizando el módulo `web_delivery` de Metasploit con una carga útil de Meterpreter inverso dirigida por PowerShell se puede establecer un escucha que proporcione el comando de ejecución necesario. Crear y iniciar un servicio remoto en la máquina Windows del atacante con el binPath configurado para ejecutar este comando a través de cmd.exe permite la ejecución de la carga útil, a pesar de posibles errores de respuesta del servicio, logrando la devolución de llamada y la ejecución de la carga útil en el lado del escucha de Metasploit.

### Ejemplo de Comandos

La creación e inicio del servicio se puede lograr con los siguientes comandos:
```cmd
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Para más detalles, consulta [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


# Referencias
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
