# SeManageVolumePrivilege: acceso al volumen raw para leer archivos arbitrarios

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

Derecho de usuario de Windows: Realizar tareas de mantenimiento de volúmenes (constante: SeManageVolumePrivilege).

Los titulares pueden realizar operaciones de bajo nivel en volúmenes, como desfragmentación, creación o eliminación de volúmenes y operaciones de mantenimiento de E/S. Lo más importante para los atacantes es que este derecho permite abrir handles de dispositivos de volumen raw (por ejemplo, \\.\C:) y emitir operaciones directas de E/S de disco que omiten las ACL de archivos de NTFS. Con acceso raw, puedes copiar los bytes de cualquier archivo del volumen aunque esté denegado por la DACL, analizando offline las estructuras del sistema de archivos o utilizando herramientas que lean a nivel de bloques o clústeres.

Valor predeterminado: Administrators en servidores y controladores de dominio.<sup>[[1]](#references)</sup>

## Escenarios de abuso

- Lectura arbitraria de archivos omitiendo las ACL mediante la lectura del dispositivo de disco (por ejemplo, exfiltrar material sensible protegido por el sistema, como claves privadas de máquina en %ProgramData%\Microsoft\Crypto\RSA\MachineKeys y %ProgramData%\Microsoft\Crypto\Keys, colmenas del registro, masterkeys de DPAPI, SAM, ntds.dit mediante VSS, etc.).
- Omitir rutas bloqueadas o privilegiadas (C:\Windows\System32\…) copiando bytes directamente desde el dispositivo raw.
- En entornos de AD CS, exfiltrar el material de claves de la CA (almacén de claves de máquina) para crear “Golden Certificates” y suplantar a cualquier principal del dominio mediante PKINIT. Consulta el enlace siguiente.<sup>[[2]](#references)</sup>

Nota: Aún necesitas un parser para las estructuras de NTFS, a menos que dependas de herramientas auxiliares. Muchas herramientas disponibles abstraen el acceso raw.

## Técnicas prácticas

- Abrir un handle de volumen raw y leer clústeres:

<details>
<summary>Haz clic para expandir</summary>
```powershell
# PowerShell – read first MB from C: raw device (requires SeManageVolumePrivilege)
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

- Usa una herramienta compatible con NTFS para recuperar archivos específicos del volumen raw:
- RawCopy/RawCopy64 (copia a nivel de sector de archivos en uso)
- FTK Imager o The Sleuth Kit (creación de imágenes de solo lectura y posterior carving de archivos)
- vssadmin/diskshadow + shadow copy; después copia el archivo objetivo desde el snapshot (si puedes crear VSS; normalmente requiere admin, pero suele estar disponible para los mismos operadores que poseen SeManageVolumePrivilege)

Rutas sensibles típicas que puedes buscar:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (secretos locales)
- C:\Windows\NTDS\ntds.dit (controladores de dominio; mediante shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (certificados/CRL de la CA; las claves privadas se encuentran en el almacén de claves de máquina anterior)

## Relación con AD CS: Forging a Golden Certificate

Si puedes leer la clave privada de la Enterprise CA desde el almacén de claves de máquina, puedes falsificar certificados de autenticación de cliente para principals arbitrarios y autenticarte mediante PKINIT/Schannel. Esto suele denominarse Golden Certificate.<sup>[[2]](#references)</sup> Consulta:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sección: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detección y hardening

- Limita estrictamente la asignación de SeManageVolumePrivilege (Perform volume maintenance tasks) únicamente a admins de confianza.
- Supervisa Sensitive Privilege Use y las aperturas de handles de procesos a objetos de dispositivo como \\.\C:, \\.\PhysicalDrive0.
- Prefiere claves de CA respaldadas por HSM/TPM o DPAPI-NG, de modo que las lecturas raw de archivos no puedan recuperar el material criptográfico en un formato utilizable.
- Mantén las rutas de uploads, temporales y extracción como no ejecutables y separadas (una defensa del contexto web que suele acompañar a esta cadena de post-exploitation).

## Referencias

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
