<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>


# Niveles de Integridad

En Windows Vista y versiones posteriores, todos los elementos protegidos vienen con una etiqueta de **nivel de integridad**. Este sistema asigna principalmente un nivel de integridad "medio" a archivos y claves del registro, excepto para ciertas carpetas y archivos a los que Internet Explorer 7 puede escribir a un nivel de integridad bajo. El comportamiento predeterminado es que los procesos iniciados por usuarios estándar tengan un nivel de integridad medio, mientras que los servicios suelen operar a un nivel de integridad del sistema. Una etiqueta de alta integridad protege el directorio raíz.

Una regla clave es que los objetos no pueden ser modificados por procesos con un nivel de integridad inferior al nivel del objeto. Los niveles de integridad son:

- **No confiable**: Este nivel es para procesos con accesos anónimos. %%%Ejemplo: Chrome%%%
- **Bajo**: Principalmente para interacciones en internet, especialmente en el Modo Protegido de Internet Explorer, afectando archivos y procesos asociados, y ciertas carpetas como la **Carpeta de Internet Temporal**. Los procesos de baja integridad enfrentan restricciones significativas, incluido el acceso limitado de escritura al registro y al perfil de usuario.
- **Medio**: El nivel predeterminado para la mayoría de las actividades, asignado a usuarios estándar y objetos sin niveles de integridad específicos. Incluso los miembros del grupo de Administradores operan en este nivel de forma predeterminada.
- **Alto**: Reservado para administradores, permitiéndoles modificar objetos en niveles de integridad inferiores, incluidos los del propio nivel alto.
- **Sistema**: El nivel operativo más alto para el kernel de Windows y servicios principales, fuera del alcance incluso de los administradores, garantizando la protección de funciones vitales del sistema.
- **Instalador**: Un nivel único que se sitúa por encima de todos los demás, permitiendo que los objetos en este nivel desinstalen cualquier otro objeto.

Puedes obtener el nivel de integridad de un proceso utilizando **Process Explorer** de **Sysinternals**, accediendo a las **propiedades** del proceso y viendo la pestaña "**Seguridad**":

![](<../../.gitbook/assets/image (318).png>)

También puedes obtener tu **nivel de integridad actual** usando `whoami /groups`

![](<../../.gitbook/assets/image (319).png>)

## Niveles de Integridad en el Sistema de Archivos

Un objeto dentro del sistema de archivos puede necesitar un **requisito mínimo de nivel de integridad** y si un proceso no tiene este nivel de integridad, no podrá interactuar con él.\
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
Ahora, asignemos un nivel de integridad mínimo de **Alto** al archivo. Esto **debe hacerse desde una consola** ejecutándose como **administrador** ya que una **consola regular** se ejecutará en el nivel de integridad Medio y **no se permitirá** asignar el nivel de integridad Alto a un objeto:
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
Esto es donde las cosas se ponen interesantes. Puedes ver que el usuario `DESKTOP-IDJHTKP\user` tiene **privilegios COMPLETOS** sobre el archivo (de hecho, este fue el usuario que creó el archivo), sin embargo, debido al nivel de integridad mínimo implementado, no podrá modificar el archivo a menos que esté ejecutándose dentro de un Nivel de Integridad Alto (nota que podrá leerlo):
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
Ahora, cuando ejecuto `cmd-low.exe` se ejecutará **bajo un nivel de integridad bajo** en lugar de uno medio:

![](<../../.gitbook/assets/image (320).png>)

Para las personas curiosas, si asignas un nivel de integridad alto a un binario (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) no se ejecutará automáticamente con un nivel de integridad alto (si lo invocas desde un nivel de integridad medio --por defecto-- se ejecutará bajo un nivel de integridad medio).

## Niveles de Integridad en Procesos

No todos los archivos y carpetas tienen un nivel mínimo de integridad, **pero todos los procesos se ejecutan bajo un nivel de integridad**. Y similar a lo que sucedió con el sistema de archivos, **si un proceso quiere escribir dentro de otro proceso debe tener al menos el mismo nivel de integridad**. Esto significa que un proceso con un nivel de integridad bajo no puede abrir un identificador con acceso completo a un proceso con un nivel de integridad medio.

Debido a las restricciones comentadas en esta y la sección anterior, desde un punto de vista de seguridad, siempre es **recomendable ejecutar un proceso en el nivel de integridad más bajo posible**.


<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
