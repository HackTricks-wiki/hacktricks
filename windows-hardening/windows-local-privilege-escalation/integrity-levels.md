# Niveles de integridad

A partir de Windows Vista, todos los **objetos protegidos están etiquetados con un nivel de integridad**. La mayoría de los archivos de usuario y del sistema y las claves del registro en el sistema tienen una etiqueta predeterminada de integridad "media". La principal excepción es un conjunto de carpetas y archivos específicos que pueden ser escritos por Internet Explorer 7 con baja integridad. La mayoría de los procesos ejecutados por **usuarios estándar** están etiquetados con **integridad media** (incluso los iniciados por un usuario dentro del grupo de administradores), y la mayoría de los **servicios** están etiquetados con **integridad del sistema**. El directorio raíz está protegido por una etiqueta de alta integridad.\
Tenga en cuenta que **un proceso con un nivel de integridad inferior no puede escribir en un objeto con un nivel de integridad superior**.\
Existen varios niveles de integridad:

* **No confiable** - los procesos que inician sesión de forma anónima se designan automáticamente como No confiables. _Ejemplo: Chrome_
* **Bajo** - El nivel de integridad Bajo es el nivel utilizado por defecto para la interacción con Internet. Mientras se ejecute Internet Explorer en su estado predeterminado, Modo protegido, todos los archivos y procesos asociados a él se asignan el nivel de integridad Bajo. Algunas carpetas, como la **Carpeta de Internet temporal**, también se asignan el nivel de integridad **Bajo** de forma predeterminada. Sin embargo, tenga en cuenta que un **proceso de baja integridad** está muy **restringido**, no puede escribir en el **registro** y está limitado para escribir en **la mayoría de las ubicaciones** en el perfil del usuario actual. _Ejemplo: Internet Explorer o Microsoft Edge_
* **Media** - Media es el contexto en el que **la mayoría de los objetos se ejecutarán**. Los usuarios estándar reciben el nivel de integridad Media, y cualquier objeto que no se designe explícitamente con un nivel de integridad inferior o superior es Media de forma predeterminada. Tenga en cuenta que un usuario dentro del grupo de administradores por defecto usará niveles de integridad media.
* **Alto** - Los **administradores** reciben el nivel de integridad Alto. Esto asegura que los administradores sean capaces de interactuar y modificar objetos asignados con niveles de integridad Media o Bajo, pero también pueden actuar sobre otros objetos con un nivel de integridad Alto, lo que los usuarios estándar no pueden hacer. _Ejemplo: "Ejecutar como administrador"_
* **Sistema** - Como su nombre indica, el nivel de integridad del sistema está reservado para el sistema. El kernel de Windows y los servicios principales reciben el nivel de integridad del sistema. Al ser incluso más alto que el nivel de integridad Alto de los administradores, protege estas funciones principales de ser afectadas o comprometidas incluso por los administradores. Ejemplo: Servicios
* **Instalador** - El nivel de integridad del instalador es un caso especial y es el más alto de todos los niveles de integridad. Por ser igual o superior a todos los demás niveles de integridad de WIC, los objetos asignados al nivel de integridad del instalador también pueden desinstalar todos los demás objetos.

Puede obtener el nivel de integridad de un proceso utilizando **Process Explorer** de **Sysinternals**, accediendo a las **propiedades** del proceso y viendo la pestaña "**Seguridad**":

![](<../../.gitbook/assets/image (318).png>)

También puede obtener su **nivel de integridad actual** utilizando `whoami /groups`

![](<../../.gitbook/assets/image (319).png>)

## Niveles de integridad en el sistema de archivos

Un objeto dentro del sistema de archivos puede necesitar un **requisito mínimo de nivel de integridad** y si un proceso no tiene este nivel de integridad, no podrá interactuar con él.\
Por ejemplo, creemos un archivo desde una consola de usuario regular y verifiquemos los permisos:
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
        DESKTOP-IDJHTKP\user:(I)(F)
        NT AUTHORITY\SYSTEM:(I)(F)
        NT AUTHORITY\INTERACTIVE:(I)(M,DC)
        NT AUTHORITY\SERVICE:(I)(M,DC)
        NT AUTHORITY\BATCH:(I)(M,DC)
```
Ahora, asignemos un nivel mínimo de integridad de **Alto** al archivo. Esto **debe hacerse desde una consola** ejecutándose como **administrador** ya que una **consola regular** se ejecutará en el nivel de integridad Medio y **no se permitirá** asignar un nivel de integridad Alto a un objeto:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
        DESKTOP-IDJHTKP\user:(I)(F)
        NT AUTHORITY\SYSTEM:(I)(F)
        NT AUTHORITY\INTERACTIVE:(I)(M,DC)
        NT AUTHORITY\SERVICE:(I)(M,DC)
        NT AUTHORITY\BATCH:(I)(M,DC)
        Mandatory Label\High Mandatory Level:(NW)
```
Aquí es donde las cosas se ponen interesantes. Puedes ver que el usuario `DESKTOP-IDJHTKP\user` tiene **privilegios COMPLETOS** sobre el archivo (de hecho, este fue el usuario que creó el archivo), sin embargo, debido al nivel mínimo de integridad implementado, no podrá modificar el archivo a menos que esté ejecutándose dentro de un Nivel de Integridad Alto (nota que podrá leerlo):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
Por lo tanto, cuando un archivo tiene un nivel mínimo de integridad, para modificarlo es necesario ejecutar al menos en ese nivel de integridad.
{% endhint %}

## Niveles de integridad en binarios

Hice una copia de `cmd.exe` en `C:\Windows\System32\cmd-low.exe` y le asigné un **nivel de integridad bajo desde una consola de administrador:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
                                BUILTIN\Administrators:(I)(F)
                                BUILTIN\Users:(I)(RX)
                                APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
                                Mandatory Label\Low Mandatory Level:(NW)
```
Ahora, cuando ejecuto `cmd-low.exe`, se ejecutará **con un nivel de integridad bajo** en lugar de uno medio:

![](<../../.gitbook/assets/image (320).png>)

Para las personas curiosas, si asignas un nivel de integridad alto a un binario (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), no se ejecutará automáticamente con un nivel de integridad alto (si lo invocas desde un nivel de integridad medio, por defecto, se ejecutará con un nivel de integridad medio).

## Niveles de integridad en procesos

No todos los archivos y carpetas tienen un nivel de integridad mínimo, **pero todos los procesos se ejecutan con un nivel de integridad**. Y, similar a lo que sucede con el sistema de archivos, **si un proceso quiere escribir dentro de otro proceso, debe tener al menos el mismo nivel de integridad**. Esto significa que un proceso con un nivel de integridad bajo no puede abrir un identificador con acceso completo a un proceso con un nivel de integridad medio.

Debido a las restricciones comentadas en esta y la sección anterior, desde un punto de vista de seguridad, siempre es **recomendable ejecutar un proceso con el nivel de integridad más bajo posible**.


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
