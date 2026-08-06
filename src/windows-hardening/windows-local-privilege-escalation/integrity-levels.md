# Niveles de integridad

{{#include ../../banners/hacktricks-training.md}}

## Niveles de integridad

En Windows Vista y versiones posteriores, todos los elementos protegidos incluyen una etiqueta de **nivel de integridad**. Esta configuración asigna principalmente un nivel de integridad "medio" a los archivos y las claves del registro, excepto a determinadas carpetas y archivos en los que Internet Explorer 7 puede escribir con un nivel de integridad bajo. El comportamiento predeterminado es que los procesos iniciados por usuarios estándar tengan un nivel de integridad medio, mientras que los servicios suelen operar con un nivel de integridad del sistema. Una etiqueta de alta integridad protege el directorio raíz.

Una regla fundamental es que los objetos no pueden ser modificados por procesos con un nivel de integridad inferior al nivel del objeto. Los niveles de integridad son:

- **No confiable**: Este nivel es para procesos con inicios de sesión anónimos. Ejemplo: Chrome
- **Bajo**: Se utiliza principalmente para interacciones con Internet, especialmente en el Modo protegido de Internet Explorer, afectando a los archivos y procesos asociados, así como a determinadas carpetas como la **Carpeta temporal de Internet**. Los procesos con integridad baja tienen restricciones importantes, incluido el acceso de escritura al registro y un acceso de escritura limitado al perfil del usuario.
- **Medio**: El nivel predeterminado para la mayoría de las actividades, asignado a usuarios estándar y objetos sin niveles de integridad específicos. Incluso los miembros del grupo Administradores operan en este nivel de forma predeterminada.
- **Alto**: Reservado para los administradores, permitiéndoles modificar objetos con niveles de integridad inferiores, incluidos los que tienen el mismo nivel alto.
- **Sistema**: El nivel operativo más alto para el kernel de Windows y los servicios principales, fuera del alcance incluso de los administradores, lo que garantiza la protección de funciones esenciales del sistema.
- **Instalador**: Un nivel único que se encuentra por encima de todos los demás y permite que los objetos con este nivel desinstalen cualquier otro objeto.

Puedes obtener el nivel de integridad de un proceso utilizando **Process Explorer** de **Sysinternals**, accediendo a las **propiedades** del proceso y consultando la pestaña "**Security**":

![Niveles de integridad - Niveles de integridad: Puedes obtener el nivel de integridad de un proceso utilizando Process Explorer de Sysinternals, accediendo a las propiedades del proceso y consultando la pestaña "...](<../../images/image (824).png>)

También puedes obtener tu **nivel de integridad actual** utilizando `whoami /groups`

![Niveles de integridad - Niveles de integridad: También puedes obtener tu nivel de integridad actual utilizando whoami /groups](<../../images/image (325).png>)

### Niveles de integridad en el sistema de archivos

Un objeto dentro del sistema de archivos puede requerir un **nivel de integridad mínimo** y, si un proceso no tiene este nivel de integridad, no podrá interactuar con él.\
Por ejemplo, vamos a **crear un archivo normal desde una consola de un usuario estándar y comprobar los permisos**:
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
Ahora, asignemos un nivel de integridad mínimo **High** al archivo. Esto **debe hacerse desde una consola** ejecutada como **administrador**, ya que una **consola normal** se ejecutará con un nivel de integridad Medium y **no podrá** asignar un nivel de integridad High a un objeto:
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
Aquí es donde las cosas se ponen interesantes. Puedes ver que el usuario `DESKTOP-IDJHTKP\user` tiene **FULL privileges** sobre el archivo (de hecho, este fue el usuario que creó el archivo); sin embargo, debido al nivel de integridad mínimo implementado, ya no podrá modificar el archivo a menos que se esté ejecutando dentro de un High Integrity Level (ten en cuenta que podrá leerlo):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Por lo tanto, cuando un archivo tiene un nivel de integridad mínimo, para modificarlo debes ejecutarlo al menos con ese nivel de integridad.**

### Niveles de integridad en los binarios

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

![Niveles de integridad en el sistema de archivos - Niveles de integridad en binarios: Ahora, cuando ejecuto cmd-low.exe, se ejecutará con un nivel de integridad bajo en lugar de uno medio](<../../images/image (313).png>)

Para los curiosos, si asignas un nivel de integridad alto a un binario (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), no se ejecutará automáticamente con un nivel de integridad alto (si lo invocas desde un nivel de integridad medio --por defecto--, se ejecutará con un nivel de integridad medio).

### Niveles de integridad en procesos

No todos los archivos y carpetas tienen un nivel de integridad mínimo, **pero todos los procesos se ejecutan con un nivel de integridad**. Y, de forma similar a lo que ocurre con el sistema de archivos, **si un proceso quiere escribir dentro de otro proceso, debe tener al menos el mismo nivel de integridad**. Esto significa que un proceso con un nivel de integridad bajo no puede abrir un handle con acceso total a un proceso con un nivel de integridad medio.

Debido a las restricciones mencionadas en esta sección y en la anterior, desde el punto de vista de la seguridad, siempre se **recomienda ejecutar un proceso con el nivel de integridad más bajo posible**.

{{#include ../../banners/hacktricks-training.md}}
