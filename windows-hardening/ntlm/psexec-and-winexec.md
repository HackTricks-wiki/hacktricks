# PsExec/Winexec/ScExec

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Cómo funcionan

1. Copiar un binario de servicio en el recurso compartido ADMIN$ a través de SMB
2. Crear un servicio en la máquina remota que apunte al binario
3. Iniciar el servicio de forma remota
4. Al salir, detener el servicio y eliminar el binario

## **PsExec manual**

Primero supongamos que tenemos un ejecutable de carga útil que generamos con msfvenom y ofuscamos con Veil (para que el AV no lo detecte). En este caso, creé una carga útil de meterpreter reverse_http y la llamé 'met8888.exe'

**Copiar el binario**. Desde nuestra línea de comandos "jarrieta", simplemente copiamos el binario al ADMIN$. Realmente, podría copiarse y ocultarse en cualquier lugar del sistema de archivos.

![](../../.gitbook/assets/copy\_binary\_admin.png)

**Crear un servicio**. El comando `sc` de Windows se utiliza para consultar, crear, eliminar, etc. servicios de Windows y se puede usar de forma remota. Lee más sobre esto [aquí](https://technet.microsoft.com/en-us/library/bb490995.aspx). Desde nuestra línea de comandos, crearemos de forma remota un servicio llamado "meterpreter" que apunte a nuestro binario subido:

![](../../.gitbook/assets/sc\_create.png)

**Iniciar el servicio**. El último paso es iniciar el servicio y ejecutar el binario. _Nota:_ cuando el servicio se inicie, "se agotará el tiempo" y generará un error. Eso es porque nuestro binario de meterpreter no es un binario de servicio real y no devolverá el código de respuesta esperado. Eso está bien porque solo necesitamos que se ejecute una vez para activarse:

![](../../.gitbook/assets/sc\_start\_error.png)

Si miramos nuestro oyente de Metasploit, veremos que la sesión se ha abierto.

**Limpiar el servicio.**

![](../../.gitbook/assets/sc\_delete.png)

Extraído de aquí: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**También podrías usar el binario PsExec.exe de Windows Sysinternals:**

![](<../../.gitbook/assets/image (165).png>)

También podrías usar [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
