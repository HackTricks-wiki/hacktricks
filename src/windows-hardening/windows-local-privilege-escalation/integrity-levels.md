# Niveles de Integridad

{{#include ../../banners/hacktricks-training.md}}

## Niveles de Integridad

En Windows Vista y versiones posteriores, todos los elementos protegidos vienen con una etiqueta de **nivel de integridad**. Esta configuración asigna principalmente un nivel de integridad "medio" a archivos y claves de registro, excepto por ciertas carpetas y archivos a los que Internet Explorer 7 puede escribir a un nivel de integridad bajo. El comportamiento predeterminado es que los procesos iniciados por usuarios estándar tengan un nivel de integridad medio, mientras que los servicios operan típicamente a un nivel de integridad del sistema. Una etiqueta de alta integridad protege el directorio raíz.

Una regla clave es que los objetos no pueden ser modificados por procesos con un nivel de integridad más bajo que el nivel del objeto. Los niveles de integridad son:

- **No confiable**: Este nivel es para procesos con inicios de sesión anónimos. %%%Ejemplo: Chrome%%%
- **Bajo**: Principalmente para interacciones en internet, especialmente en el Modo Protegido de Internet Explorer, afectando archivos y procesos asociados, y ciertas carpetas como la **Carpeta Temporal de Internet**. Los procesos de baja integridad enfrentan restricciones significativas, incluyendo la falta de acceso para escribir en el registro y acceso limitado para escribir en el perfil de usuario.
- **Medio**: El nivel predeterminado para la mayoría de las actividades, asignado a usuarios estándar y objetos sin niveles de integridad específicos. Incluso los miembros del grupo de Administradores operan a este nivel por defecto.
- **Alto**: Reservado para administradores, permitiéndoles modificar objetos en niveles de integridad más bajos, incluyendo aquellos en el nivel alto mismo.
- **Sistema**: El nivel operativo más alto para el núcleo de Windows y servicios centrales, fuera del alcance incluso para administradores, asegurando la protección de funciones vitales del sistema.
- **Instalador**: Un nivel único que se encuentra por encima de todos los demás, permitiendo a los objetos en este nivel desinstalar cualquier otro objeto.

Puedes obtener el nivel de integridad de un proceso usando **Process Explorer** de **Sysinternals**, accediendo a las **propiedades** del proceso y viendo la pestaña de "**Seguridad**":

![](<../../images/image (824).png>)

También puedes obtener tu **nivel de integridad actual** usando `whoami /groups`

![](<../../images/image (325).png>)

### Niveles de Integridad en el Sistema de Archivos

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
Ahora, asignemos un nivel de integridad mínimo de **Alto** al archivo. Esto **debe hacerse desde una consola** que se ejecute como **administrador**, ya que una **consola regular** se ejecutará en un nivel de integridad Medio y **no se permitirá** asignar un nivel de integridad Alto a un objeto:
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
Aquí es donde las cosas se ponen interesantes. Puedes ver que el usuario `DESKTOP-IDJHTKP\user` tiene **privilegios COMPLETOS** sobre el archivo (de hecho, este fue el usuario que creó el archivo), sin embargo, debido al nivel de integridad mínimo implementado, no podrá modificar el archivo a menos que esté ejecutándose dentro de un Nivel de Integridad Alto (ten en cuenta que podrá leerlo):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!NOTE]
> **Por lo tanto, cuando un archivo tiene un nivel de integridad mínimo, para modificarlo necesitas estar ejecutando al menos en ese nivel de integridad.**

### Niveles de Integridad en Binarios

Hice una copia de `cmd.exe` en `C:\Windows\System32\cmd-low.exe` y le establecí un **nivel de integridad bajo desde una consola de administrador:**
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

![](<../../images/image (313).png>)

Para los curiosos, si asignas un nivel de integridad alto a un binario (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) no se ejecutará automáticamente con un nivel de integridad alto (si lo invocas desde un nivel de integridad medio --por defecto-- se ejecutará bajo un nivel de integridad medio).

### Niveles de Integridad en Procesos

No todos los archivos y carpetas tienen un nivel de integridad mínimo, **pero todos los procesos se ejecutan bajo un nivel de integridad**. Y similar a lo que ocurrió con el sistema de archivos, **si un proceso quiere escribir dentro de otro proceso debe tener al menos el mismo nivel de integridad**. Esto significa que un proceso con un nivel de integridad bajo no puede abrir un manejador con acceso total a un proceso con un nivel de integridad medio.

Debido a las restricciones comentadas en esta y la sección anterior, desde un punto de vista de seguridad, siempre es **recomendado ejecutar un proceso en el nivel de integridad más bajo posible**.

{{#include ../../banners/hacktricks-training.md}}
