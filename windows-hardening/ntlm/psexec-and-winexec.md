# PsExec/Winexec/ScExec

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? o ¿quieres acceder a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Cómo funcionan

1. Copiar un binario de servicio en el recurso compartido ADMIN$ a través de SMB
2. Crear un servicio en la máquina remota que apunte al binario
3. Iniciar el servicio de forma remota
4. Al salir, detener el servicio y eliminar el binario

## **PsExec manual**

Primero supongamos que tenemos un ejecutable de carga útil que generamos con msfvenom y ofuscamos con Veil (para que el AV no lo detecte). En este caso, creé una carga útil de meterpreter reverse_http y la llamé 'met8888.exe'

**Copiar el binario**. Desde nuestra línea de comandos "jarrieta", simplemente copiamos el binario al ADMIN$. Realmente, podría ser copiado y ocultado en cualquier lugar del sistema de archivos.

![](../../.gitbook/assets/copy\_binary\_admin.png)

**Crear un servicio**. El comando `sc` de Windows se utiliza para consultar, crear, eliminar, etc. servicios de Windows y se puede usar de forma remota. Lee más sobre esto [aquí](https://technet.microsoft.com/en-us/library/bb490995.aspx). Desde nuestra línea de comandos, crearemos de forma remota un servicio llamado "meterpreter" que apunte a nuestro binario subido:

![](../../.gitbook/assets/sc\_create.png)

**Iniciar el servicio**. El último paso es iniciar el servicio y ejecutar el binario. _Nota:_ cuando el servicio se inicie, "se agotará el tiempo" y generará un error. Esto se debe a que nuestro binario de meterpreter no es un binario de servicio real y no devolverá el código de respuesta esperado. Eso está bien porque solo necesitamos que se ejecute una vez para activarse:

![](../../.gitbook/assets/sc\_start\_error.png)

Si miramos nuestro oyente de Metasploit, veremos que la sesión se ha abierto.

**Limpiar el servicio.**

![](../../.gitbook/assets/sc\_delete.png)

Extraído de aquí: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**También podrías usar el binario de Windows Sysinternals PsExec.exe:**

![](<../../.gitbook/assets/image (165).png>)

También podrías usar [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver a tu **empresa anunciada en HackTricks**? o ¿quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
