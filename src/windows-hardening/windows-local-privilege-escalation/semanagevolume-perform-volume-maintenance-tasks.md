# SeManageVolumePrivilege: Acceso raw al volumen para lectura arbitraria de archivos

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

Derecho de usuario de Windows: Realizar tareas de mantenimiento de volúmenes (constante: SeManageVolumePrivilege).

Los titulares pueden realizar operaciones de volumen a bajo nivel como desfragmentación, crear/eliminar volúmenes y I/O de mantenimiento. Críticamente para los atacantes, este derecho permite abrir raw volume device handles (p. ej., \\.\C:) y emitir I/O de disco directo que elude los ACLs de archivos NTFS. Con acceso raw puedes copiar bytes de cualquier archivo en el volumen aun si está denegado por la DACL, analizando las estructuras del sistema de ficheros offline o aprovechando herramientas que leen a nivel de bloque/cluster.

Por defecto: Administradores en servidores y controladores de dominio.

## Escenarios de abuso

- Lectura arbitraria de archivos saltándose ACLs leyendo el dispositivo de disco (p. ej., exfiltrar material protegido del sistema sensible como claves privadas de máquina bajo %ProgramData%\Microsoft\Crypto\RSA\MachineKeys y %ProgramData%\Microsoft\Crypto\Keys, hives del registro, masterkeys de DPAPI, SAM, ntds.dit vía VSS, etc.).
- Omitir rutas bloqueadas/privilegiadas (C:\Windows\System32\…) copiando bytes directamente desde el dispositivo raw.
- En entornos AD CS, exfiltrar el material de claves de la CA (almacén de claves de máquina) para crear “Golden Certificates” e impersonar a cualquier principal de dominio vía PKINIT. Ver enlace abajo.

Nota: Aún necesitas un analizador para las estructuras NTFS a menos que dependas de herramientas auxiliares. Muchas herramientas existentes abstraen el acceso raw.

## Técnicas prácticas

- Abrir un raw volume handle y leer clusters:

<details>
<summary>Haga clic para expandir</summary>
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

- Usa una herramienta con soporte NTFS para recuperar archivos específicos desde el volumen raw:
- RawCopy/RawCopy64 (copia a nivel de sector de archivos en uso)
- FTK Imager or The Sleuth Kit (imagen de solo lectura, luego recuperar archivos mediante carving)
- vssadmin/diskshadow + shadow copy, luego copiar el archivo objetivo desde la instantánea (si puedes crear VSS; a menudo requiere admin pero suele estar disponible para los mismos operadores que poseen SeManageVolumePrivilege)

Typical sensitive paths to target:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## Vínculo con AD CS: Forging a Golden Certificate

Si puedes leer la clave privada de la Enterprise CA desde el almacén de claves de máquina, puedes forjar certificados de client‑auth para principales arbitrarios y autenticarte vía PKINIT/Schannel. A esto a menudo se le llama Golden Certificate. Ver:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Sección: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detección y endurecimiento

- Limitar fuertemente la asignación de SeManageVolumePrivilege (Perform volume maintenance tasks) solo a administradores de confianza.
- Monitorea Sensitive Privilege Use y aperturas de handles de procesos a objetos de dispositivo como \\.\C:, \\.\PhysicalDrive0.
- Prefiere claves CA respaldadas por HSM/TPM o DPAPI-NG para que lecturas raw de archivos no puedan recuperar material clave en forma utilizable.
- Mantén los paths de uploads, temp y extracción no ejecutables y separados (defensa en contexto web que a menudo acompaña esta cadena post‑exploitation).

## References

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
