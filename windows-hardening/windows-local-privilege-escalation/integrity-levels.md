<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>


# Niveles de Integridad

Desde Windows Vista, todos los **objetos protegidos están etiquetados con un nivel de integridad**. La mayoría de archivos y claves de registro de usuario y sistema en el sistema tienen una etiqueta predeterminada de integridad “media”. La principal excepción es un conjunto de carpetas y archivos específicos escribibles por Internet Explorer 7 con integridad Baja. **La mayoría de procesos** ejecutados por **usuarios estándar** están etiquetados con integridad **media** (incluso aquellos iniciados por un usuario dentro del grupo de administradores), y la mayoría de **servicios** están etiquetados con integridad **Sistema**. El directorio raíz está protegido por una etiqueta de alta integridad.\
Nota que **un proceso con un nivel de integridad más bajo no puede escribir en un objeto con un nivel de integridad más alto.**\
Hay varios niveles de integridad:

* **No confiable** – procesos que han iniciado sesión de forma anónima son automáticamente designados como No confiables. _Ejemplo: Chrome_
* **Bajo** – El nivel de integridad Bajo es el nivel utilizado por defecto para la interacción con Internet. Mientras Internet Explorer se ejecute en su estado predeterminado, Modo Protegido, todos los archivos y procesos asociados con él se asignan el nivel de integridad Bajo. Algunas carpetas, como la **Carpeta de Internet Temporal**, también se asignan el nivel de integridad **Bajo** por defecto. Sin embargo, ten en cuenta que un **proceso de baja integridad** es muy **restringido**, **no puede** escribir en el **registro** y está limitado para escribir en **la mayoría de ubicaciones** en el perfil del usuario actual.  _Ejemplo: Internet Explorer o Microsoft Edge_
* **Medio** – Medio es el contexto en el que **la mayoría de objetos se ejecutarán**. Los usuarios estándar reciben el nivel de integridad Medio, y cualquier objeto no designado explícitamente con un nivel de integridad más bajo o más alto es Medio por defecto. Nota que un usuario dentro del grupo de Administradores por defecto usará niveles de integridad medios.
* **Alto** – Los **Administradores** reciben el nivel de integridad Alto. Esto asegura que los Administradores sean capaces de interactuar con y modificar objetos asignados con niveles de integridad Medio o Bajo, pero también pueden actuar sobre otros objetos con un nivel de integridad Alto, lo cual los usuarios estándar no pueden hacer. _Ejemplo: "Ejecutar como Administrador"_
* **Sistema** – Como su nombre indica, el nivel de integridad Sistema está reservado para el sistema. El núcleo de Windows y los servicios centrales reciben el nivel de integridad Sistema. Estar incluso más alto que el nivel de integridad Alto de los Administradores protege estas funciones centrales de ser afectadas o comprometidas incluso por los Administradores. Ejemplo: Servicios
* **Instalador** – El nivel de integridad Instalador es un caso especial y es el más alto de todos los niveles de integridad. En virtud de ser igual o superior a todos los demás niveles de integridad WIC, los objetos asignados al nivel de integridad Instalador también son capaces de desinstalar todos los demás objetos.

Puedes obtener el nivel de integridad de un proceso usando **Process Explorer** de **Sysinternals**, accediendo a las **propiedades** del proceso y viendo la pestaña "**Seguridad**":

![](<../../.gitbook/assets/image (318).png>)

También puedes obtener tu **nivel de integridad actual** usando `whoami /groups`

![](<../../.gitbook/assets/image (319).png>)

## Niveles de Integridad en el Sistema de Archivos

Un objeto dentro del sistema de archivos puede requerir un **requisito mínimo de nivel de integridad** y si un proceso no tiene este nivel de integridad no podrá interactuar con él.\
Por ejemplo, vamos a **crear un archivo regular desde una consola de usuario regular y verificar los permisos**:
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
Ahora, asignemos un nivel de integridad mínimo de **High** al archivo. Esto **debe hacerse desde una consola** ejecutándose como **administrador**, ya que una **consola regular** estará funcionando en el nivel de integridad Medium y **no se le permitirá** asignar el nivel de integridad High a un objeto:
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
Aquí es donde las cosas se ponen interesantes. Puedes ver que el usuario `DESKTOP-IDJHTKP\user` tiene **privilegios COMPLETOS** sobre el archivo (de hecho, este fue el usuario que creó el archivo), sin embargo, debido al nivel de integridad mínimo implementado, no podrá modificar el archivo a menos que se ejecute dentro de un Nivel de Integridad Alto (nota que podrá leerlo):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
{% hint style="info" %}
**Por lo tanto, cuando un archivo tiene un nivel de integridad mínimo, para modificarlo necesitas estar ejecutándote al menos en ese nivel de integridad.**
{% endhint %}

## Niveles de Integridad en Binarios

Hice una copia de `cmd.exe` en `C:\Windows\System32\cmd-low.exe` y le asigné **un nivel de integridad bajo desde una consola de administrador:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Ahora, cuando ejecuto `cmd-low.exe` se **ejecutará bajo un nivel de integridad bajo** en lugar de uno medio:

![](<../../.gitbook/assets/image (320).png>)

Para las personas curiosas, si asignas un nivel de integridad alto a un binario (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) no se ejecutará automáticamente con un nivel de integridad alto (si lo invocas desde un nivel de integridad medio --por defecto-- se ejecutará bajo un nivel de integridad medio).

## Niveles de Integridad en Procesos

No todos los archivos y carpetas tienen un nivel de integridad mínimo, **pero todos los procesos se ejecutan bajo un nivel de integridad**. Y de manera similar a lo que sucedió con el sistema de archivos, **si un proceso quiere escribir dentro de otro proceso debe tener al menos el mismo nivel de integridad**. Esto significa que un proceso con nivel de integridad bajo no puede abrir un manejador con acceso completo a un proceso con nivel de integridad medio.

Debido a las restricciones comentadas en esta y la sección anterior, desde un punto de vista de seguridad, siempre se **recomienda ejecutar un proceso en el nivel de integridad más bajo posible**.


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
