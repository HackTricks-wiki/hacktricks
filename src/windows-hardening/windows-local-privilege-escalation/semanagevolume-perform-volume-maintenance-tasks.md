# SeManageVolumePrivilege: abuso del mantenimiento de volúmenes y validación del acceso raw

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

Derecho de usuario de Windows: Realizar tareas de mantenimiento de volúmenes (constante: SeManageVolumePrivilege).

Este derecho autoriza operaciones de mantenimiento de volúmenes, como desfragmentar y crear o quitar volúmenes. Microsoft advierte que quien lo posee puede tener la capacidad de extender archivos hacia almacenamiento que contiene otros datos y, luego, leer o modificar los bytes obtenidos.<sup>[[1]](#references)</sup>

No equipares tener `SeManageVolumePrivilege` con tener garantizado el acceso al disco raw. Microsoft documenta que abrir un disco físico o volumen mediante `CreateFile` para acceso directo requiere privilegios administrativos, y que siguen aplicándose las comprobaciones normales de acceso a objetos y dispositivos. En una compilación o producto concreto, comprueba si el token, la ACL del dispositivo, el acceso solicitado, los flags de uso compartido y el estado del volumen permiten obtener un identificador raw antes de afirmar que se puede leer cualquier archivo.<sup>[[3]](#references)</sup>

Valor predeterminado: Administradores en servidores y controladores de dominio.<sup>[[1]](#references)</sup>

## Escenarios de abuso

- Si la cuenta puede obtener realmente un identificador de volumen raw con permisos de lectura, un parser compatible con NTFS puede omitir las ACL por archivo y recuperar archivos protegidos o bloqueados de clústeres asignados.
- Entre los posibles objetivos están el contenido bloqueado o protegido por ACL en `C:\Windows\System32`, los subárboles del registro, las claves maestras de DPAPI, el SAM y, cuando se puede acceder por separado mediante una instantánea o un volumen offline, `ntds.dit`.
- En hosts de servicios de certificados, las ubicaciones útiles de claves de software incluyen `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` y `%ProgramData%\Microsoft\Crypto\Keys`; recuperar un archivo solo es útil si su material de clave se puede exportar y también se puede descifrar.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- En un host de AD CS, una clave privada de CA **exportable y respaldada por software** que se haya recuperado correctamente puede permitir el abuso de Golden Certificate. Los diseños con claves respaldadas por hardware o no exportables cambian esta vía.<sup>[[2]](#references)</sup>
- Algunas herramientas de mantenimiento de volúmenes usan `FSCTL_SD_GLOBAL_CHANGE` para reemplazar entradas de ACL del sistema de archivos cuando se permite esa operación. Esto cambia los controles de acceso en lugar de leer bloques raw de forma pasiva, puede afectar a gran parte de un volumen y debe validarse según el comportamiento real del token y el dispositivo. El [código fuente de la herramienta](https://github.com/CsEnox/SeManageVolumeExploit) muestra este mecanismo concreto; tener el privilegio por sí solo no demuestra que vaya a funcionar.
- Obtener acceso a archivos mediante cambios en las ACL no descifra un archivo cifrado con EFS. Para obtener el texto sin cifrar sigue siendo necesaria una clave privada de usuario o de recuperación coincidente. Del mismo modo, exportar una clave de CA respaldada por software con [`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) depende de que la clave esté disponible localmente, sea exportable y se pueda acceder a ella.

Nota: Aún necesitas un parser para las estructuras NTFS, salvo que uses herramientas auxiliares. Muchas herramientas disponibles abstraen el acceso raw.

## Técnicas prácticas

- Abrir un identificador de volumen raw y leer clústeres:

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

- Usa una herramienta compatible con NTFS para recuperar archivos específicos de un volumen raw:
  - RawCopy/RawCopy64 (copia a nivel de sector de archivos en uso)
  - FTK Imager o The Sleuth Kit (crea una imagen de solo lectura y luego extrae los archivos)
  - vssadmin/diskshadow + shadow copy; luego copia el archivo objetivo desde la snapshot (si puedes crear una VSS; suele requerir admin, pero normalmente está disponible para los mismos operadores que tienen SeManageVolumePrivilege)

Rutas sensibles típicas a las que apuntar:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (secretos locales)
- C:\Windows\NTDS\ntds.dit (controladores de dominio; mediante shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (certificados/CRL de la CA; las claves privadas están en el almacén de claves de equipo indicado anteriormente)

## Relación con AD CS: forjar un Golden Certificate

Si puedes leer la clave privada de la Enterprise CA del almacén de claves de equipo, puedes forjar certificados de autenticación de cliente para principales arbitrarios y autenticarte mediante PKINIT/Schannel. A esto se le suele llamar Golden Certificate.<sup>[[2]](#references)</sup> Consulta:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sección: “Forjar certificados con certificados de CA robados (Golden Certificate) – DPERSIST1”).

## Detección y hardening

- Limita estrictamente la asignación de SeManageVolumePrivilege (Perform volume maintenance tasks) solo a administradores de confianza.
- Supervisa Sensitive Privilege Use y las aperturas de identificadores de proceso a objetos de dispositivo como \\.\C:, \\.\PhysicalDrive0.
- Prefiere claves de CA no exportables, respaldadas por HSM o TPM y configuradas correctamente, para que copiar un archivo contenedor de claves no sea suficiente para recuperar material de clave privada utilizable.
- Para los secretos de aplicaciones fuera de la ruta de la clave de CA, DPAPI o DPAPI-NG pueden hacer que copiar un archivo de datos no sea suficiente, al protegerlo para un usuario, equipo, grupo u otro principal autorizado. Esto no protege el texto plano que ya sea accesible para el principal comprometido.<sup>[[4]](#references)</sup>
- Mantén las rutas de carga, temporales y extracción como no ejecutables y separadas (una defensa en el contexto web que suele complementar esta cadena de post-exploitation).

## References

- [1] [Microsoft – Realizar tareas de mantenimiento de volúmenes (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege usado para leer la clave de CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` discos físicos y volúmenes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - API de criptografía: Next Generation y DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
