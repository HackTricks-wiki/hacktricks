# Niveles de integridad

{{#include ../../banners/hacktricks-training.md}}

## Niveles de integridad

En Windows Vista y versiones posteriores, los objetos protegibles pueden contener una etiqueta de **nivel de integridad**. La mayoría de los objetos se consideran de integridad media, mientras que las ubicaciones específicas destinadas a aplicaciones de baja integridad pueden etiquetarse como bajas. Los procesos iniciados por usuarios estándar normalmente se ejecutan con integridad media, las aplicaciones elevadas se ejecutan con integridad alta y muchos servicios se ejecutan con integridad de sistema.<sup>[[1]](#references)</sup>

Una regla clave es que los objetos no pueden ser modificados por procesos con un nivel de integridad inferior al nivel del objeto. Windows aplica esta comprobación de Mandatory Integrity Control (MIC) antes de evaluar la lista de control de acceso discrecional (DACL) del objeto. Los niveles habituales son:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: El nivel más bajo, representado por `SECURITY_MANDATORY_UNTRUSTED_RID`.
- **Low**: Se utiliza principalmente para interacciones con Internet, especialmente en el Protected Mode de Internet Explorer, afectando a los archivos y procesos asociados, además de ciertas carpetas como **Temporary Internet Folder**. Los procesos de baja integridad tienen restricciones importantes, incluido el acceso de escritura al registro y un acceso de escritura limitado al perfil de usuario.
- **Medium**: El nivel predeterminado para la mayoría de las actividades, asignado a los usuarios estándar y a los objetos sin niveles de integridad específicos. Incluso los miembros del grupo Administrators operan en este nivel de forma predeterminada.
- **High**: Reservado para los administradores, lo que les permite modificar objetos con niveles de integridad inferiores, incluidos los que tienen el propio nivel alto.
- **System**: El nivel operativo más alto para el kernel de Windows y los servicios principales, fuera del alcance incluso de los administradores, lo que garantiza la protección de funciones esenciales del sistema.

Windows también define un valor de integridad de proceso protegido superior a System. Sin embargo, **TrustedInstaller** es una identidad de servicio de Windows y no un nivel MIC independiente; su capacidad para modificar recursos protegidos del sistema operativo proviene de los permisos concedidos a esa identidad.

Puedes obtener el nivel de integridad de un proceso usando **Process Explorer** de **Sysinternals**, abriendo las propiedades del proceso y consultando la pestaña **Security**:<sup>[[3]](#references)</sup>

![Niveles de integridad - Niveles de integridad: Puedes obtener el nivel de integridad de un proceso usando Process Explorer de Sysinternals, accediendo a las propiedades del proceso y consultando la pestaña "...](<../../images/image (824).png>)

También puedes obtener tu **nivel de integridad actual** usando `whoami /groups`:

![Niveles de integridad - Niveles de integridad: También puedes obtener tu nivel de integridad actual usando whoami /groups](<../../images/image (325).png>)

### Niveles de integridad en el sistema de archivos

Un objeto del sistema de archivos puede tener un **requisito de nivel de integridad mínimo**. Un proceso con un nivel inferior está sujeto a la política obligatoria del objeto incluso cuando su DACL concedería acceso de otro modo. Por ejemplo, crea un archivo normal desde una consola de usuario estándar e inspecciona sus permisos:<sup>[[1]](#references)[[4]](#references)</sup>
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
Ahora, asigna un nivel de integridad mínimo de **High** al archivo. Esto **debe hacerse desde una consola** ejecutada como **administrador**, porque una consola normal se ejecuta con integridad Medium y **no podrá** asignar integridad High a un objeto:
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
El usuario `DESKTOP-IDJHTKP\user` tiene **privilegios COMPLETOS** sobre el archivo porque lo creó. Sin embargo, la etiqueta obligatoria impide que el usuario modifique el archivo a menos que el proceso se esté ejecutando con un nivel de integridad Alto. El usuario aún puede leerlo porque la política obligatoria mostrada es `(NW)`, o no-write-up:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **Por lo tanto, cuando un archivo tiene un nivel de integridad mínimo, para modificarlo debes ejecutarlo al menos con ese nivel de integridad.**

### Niveles de integridad en binarios

El siguiente ejemplo utiliza una copia de `cmd.exe` en `C:\Windows\System32\cmd-low.exe` y le asigna un **nivel de integridad Low desde una consola de administrador**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
Ahora, cuando ejecuto `cmd-low.exe`, se ejecutará con un **nivel de integridad bajo** en lugar de uno medio:

![Niveles de integridad en el sistema de archivos - Niveles de integridad en binarios: Ahora, cuando ejecuto cmd-low.exe, se ejecutará con un nivel de integridad bajo en lugar de uno medio](<../../images/image (313).png>)

Asignar una etiqueta de integridad Alta a un binario (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) no hace que se ejecute automáticamente con integridad Alta. Si se invoca desde un proceso con integridad Media, se ejecuta con integridad Media, porque un proceso nuevo recibe el nivel de integridad más bajo entre el del archivo ejecutable y el del proceso que lo invoca.<sup>[[1]](#references)</sup>

### Niveles de integridad en procesos

No todos los archivos y carpetas tienen una etiqueta de integridad mínima explícita, **pero todos los procesos se ejecutan con un nivel de integridad**. Al igual que ocurre con los objetos del sistema de archivos, **un proceso que quiere acceso de escritura a otro proceso debe tener al menos el mismo nivel de integridad**. Por lo tanto, un proceso con integridad Baja no puede abrir un proceso con integridad Media con acceso total.<sup>[[1]](#references)</sup>

Debido a estas restricciones, el enfoque más seguro es **ejecutar cada proceso con el nivel de integridad más bajo que aún le permita realizar el trabajo previsto**.

## References

- [1] [Microsoft Learn – Control de integridad obligatorio](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – Enumeración MANDATORY_LEVEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
{{#include ../../banners/hacktricks-training.md}}
