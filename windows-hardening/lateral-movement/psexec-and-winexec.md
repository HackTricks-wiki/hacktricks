# PsExec/Winexec/ScExec

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**productos oficiales de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

## ¿Cómo funcionan?

El proceso se describe en los siguientes pasos, ilustrando cómo se manipulan los binarios de servicio para lograr la ejecución remota en una máquina objetivo a través de SMB:

1. Se realiza la **copia de un binario de servicio en el recurso ADMIN$ a través de SMB**.
2. Se **crea un servicio en la máquina remota** apuntando al binario.
3. El servicio se **inicia de forma remota**.
4. Al salir, el servicio se **detiene y el binario se elimina**.

### **Proceso de Ejecución Manual de PsExec**

Suponiendo que hay un payload ejecutable (creado con msfvenom y obfuscado usando Veil para evadir la detección de antivirus), llamado 'met8888.exe', que representa un payload meterpreter reverse\_http, se siguen los siguientes pasos:

* **Copia del binario**: El ejecutable se copia en el recurso ADMIN$ desde un símbolo del sistema, aunque puede colocarse en cualquier lugar del sistema de archivos para permanecer oculto.
* **Creación de un servicio**: Utilizando el comando `sc` de Windows, que permite consultar, crear y eliminar servicios de Windows de forma remota, se crea un servicio llamado "meterpreter" que apunta al binario cargado.
* **Inicio del servicio**: El paso final implica iniciar el servicio, lo que probablemente resultará en un error de "tiempo de espera" debido a que el binario no es un binario de servicio genuino y no devuelve el código de respuesta esperado. Este error es inconsecuente ya que el objetivo principal es la ejecución del binario.

La observación del escucha de Metasploit revelará que la sesión se ha iniciado con éxito.

[Aprende más sobre el comando `sc`](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Encuentra pasos más detallados en: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**También podrías usar el binario de Windows Sysinternals PsExec.exe:**

![](<../../.gitbook/assets/image (928).png>)

También puedes usar [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{% endcode %}

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**swag oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>
