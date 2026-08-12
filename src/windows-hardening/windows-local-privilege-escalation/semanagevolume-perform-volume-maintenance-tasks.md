# SeManageVolumePrivilege: abuso del mantenimiento de volúmenes y validación del acceso raw

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

Derecho de usuario de Windows: realizar tareas de mantenimiento de volúmenes (constante: SeManageVolumePrivilege).

Este derecho autoriza operaciones de mantenimiento de volúmenes, como la desfragmentación y la creación o eliminación de volúmenes. Microsoft advierte que un titular podría extender archivos hacia almacenamiento que contenga otros datos y, posteriormente, leer o modificar los bytes adquiridos.<sup>[[1]](#references)</sup>

No equipares la posesión de `SeManageVolumePrivilege` con un acceso garantizado al disco raw. Microsoft documenta que abrir un disco o volumen físico mediante `CreateFile` para obtener acceso directo requiere privilegios administrativos, y que las comprobaciones normales de acceso a objetos y dispositivos siguen aplicándose. En una compilación o producto concreto, comprueba si el token, la ACL del dispositivo, el acceso solicitado, los indicadores de uso compartido y el estado del volumen permiten obtener un handle raw antes de afirmar que es posible leer cualquier archivo.<sup>[[3]](#references)</sup>

Valor predeterminado: Administrators en servidores y controladores de dominio.<sup>[[1]](#references)</sup>

## Escenarios de abuso

- Si la cuenta puede obtener realmente un handle legible del volumen raw, un parser compatible con NTFS puede omitir las ACL por archivo y recuperar archivos protegidos o bloqueados de los clústeres asignados.
- Los posibles objetivos incluyen contenido bloqueado o protegido por ACL bajo `C:\Windows\System32`, registry hives, claves maestras DPAPI, el SAM y —cuando sea accesible por separado mediante un snapshot o un volumen offline— `ntds.dit`.
- En hosts de servicios de certificados, las ubicaciones útiles de software keys incluyen `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` y `%ProgramData%\Microsoft\Crypto\Keys`; recuperar un archivo solo es útil cuando su key material es exportable y también puede descifrarse.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- En un host de AD CS, una clave privada de CA **exportable y respaldada por software** recuperada correctamente puede permitir el abuso de Golden Certificate. Los diseños con claves respaldadas por hardware o no exportables modifican esta vía.<sup>[[2]](#references)</sup>

Nota: aún necesitas un parser para las estructuras de NTFS, salvo que dependas de helper tools. Muchas herramientas disponibles en el mercado abstraen el acceso raw.

## Técnicas prácticas

- Abrir un handle raw del volumen y leer clústeres:

<details>
<summary>Haz clic para expandir</summary>
```powershell
# Validation attempt: current Windows versions normally require an administrative token
$fs = [System.IO.File]::Open("\\.\\C:",[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
$buf = New-Object byte[] (1MB)
$null = $fs.Read($buf,0,$buf.Length)
$fs.Close()
[IO.File]::WriteAllBytes("C:\\temp\\c_first_mb.bin", $buf)
```

```csharp
// C# (compile with Add-Type) – read an arbitrary offset of \\.\nusing System;
using System.IO;
class R {
static void Main(string[] a){
using(var fs = new FileStream("\\\\.\\C:", FileMode.Open, FileAccess.Read, FileShare.ReadWrite)){
fs.Position = 0x100000; // seek
var buf = new byte[4096];
fs.Read(buf,0,buf.Length);
File.WriteAllBytes("C:\\temp\\blk.bin", buf);
}
}
}
```
</details>

- Usa una herramienta compatible con NTFS para recuperar archivos específicos del volumen sin formato:
- RawCopy/RawCopy64 (copia a nivel de sector de archivos en uso)
- FTK Imager o The Sleuth Kit (creación de imágenes de solo lectura y posterior recuperación de archivos)
- vssadmin/diskshadow + shadow copy; después, copia el archivo objetivo desde la instantánea (si puedes crear una VSS; normalmente requiere permisos de administrador, pero suele estar disponible para los mismos operadores que tienen SeManageVolumePrivilege)

Rutas sensibles típicas a las que apuntar:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (secretos locales)
- C:\Windows\NTDS\ntds.dit (controladores de dominio, mediante shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (certificados/CRL de la CA; las claves privadas se encuentran en el almacén de claves de máquina indicado anteriormente)

## Relación con AD CS: Forging a Golden Certificate

Si puedes leer la clave privada de la CA empresarial desde el almacén de claves de máquina, puedes falsificar certificados de autenticación de cliente para cualquier principal y autenticarte mediante PKINIT/Schannel. Esto suele denominarse Golden Certificate.<sup>[[2]](#references)</sup> Consulta:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sección: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detección y hardening

- Limita estrictamente la asignación de SeManageVolumePrivilege (Perform volume maintenance tasks) únicamente a administradores de confianza.
- Supervisa el uso de privilegios sensibles y la apertura de handles de procesos a objetos de dispositivo como \\.\C:, \\.\PhysicalDrive0.
- Prefiere claves de CA no exportables respaldadas por HSM o TPM y configuradas correctamente, de modo que copiar un archivo contenedor de claves no sea suficiente para recuperar material de clave privada utilizable.
- Para los secretos de aplicaciones fuera de la ruta de la clave de la CA, DPAPI o DPAPI-NG puede hacer que copiar un archivo de datos no sea suficiente, ya que lo protege para un usuario, equipo, grupo u otro principal autorizado. Esto no protege el texto plano que ya sea accesible para el principal comprometido.<sup>[[4]](#references)</sup>
- Mantén las rutas de carga, temporales y extracción como no ejecutables y separadas (una defensa del contexto web que suele combinarse con esta cadena post-exploitation).

## References

- [1] [Microsoft – Realizar tareas de mantenimiento de volúmenes (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege usado para leer la clave de la CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile`, discos físicos y volúmenes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - API de criptografía: Next Generation y DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
