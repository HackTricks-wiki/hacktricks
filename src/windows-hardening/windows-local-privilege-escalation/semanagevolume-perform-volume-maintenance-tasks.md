# SeManageVolumePrivilege: Acceso a volumen sin procesar para lectura arbitraria de archivos

{{#include ../../banners/hacktricks-training.md}}

## Descripción general

Derecho de usuario de Windows: Perform volume maintenance tasks (constante: SeManageVolumePrivilege).

Los titulares pueden realizar operaciones de volumen a bajo nivel como desfragmentación, crear/eliminar volúmenes y E/S de mantenimiento. Críticamente para los atacantes, este derecho permite abrir handles de dispositivo de volumen en bruto (por ejemplo, \\.\C:) y emitir I/O de disco directo que evita las ACLs de archivos NTFS. Con acceso en bruto puedes copiar bytes de cualquier archivo en el volumen incluso si está denegado por el DACL, analizando las estructuras del sistema de archivos fuera de línea o aprovechando herramientas que leen a nivel de bloque/clúster.

Predeterminado: Administrators en servidores y controladores de dominio.

## Escenarios de abuso

- Lectura arbitraria de archivos eludiendo ACLs leyendo el dispositivo de disco (por ejemplo, exfiltrar material sensible protegido por el sistema como claves privadas de máquina bajo %ProgramData%\Microsoft\Crypto\RSA\MachineKeys y %ProgramData%\Microsoft\Crypto\Keys, hives del registro, DPAPI masterkeys, SAM, ntds.dit vía VSS, etc.).
- Eludir rutas bloqueadas/privilegiadas (C:\Windows\System32\…) copiando bytes directamente desde el dispositivo en bruto.
- En entornos AD CS, exfiltrar el material de claves de la CA (almacén de claves de máquina) para acuñar “Golden Certificates” e impersonar cualquier principal del dominio vía PKINIT. Ver enlace más abajo.

Nota: Aún necesitas un analizador para las estructuras NTFS a menos que confíes en herramientas auxiliares. Muchas herramientas listas para usar abstraen el acceso en bruto.

## Técnicas prácticas

- Abrir un handle de volumen en bruto y leer clústeres:

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

- Usa una herramienta compatible con NTFS para recuperar archivos específicos desde un volumen bruto:
- RawCopy/RawCopy64 (sector-level copy of in-use files)
- FTK Imager or The Sleuth Kit (read-only imaging, then carve files)
- vssadmin/diskshadow + shadow copy, luego copia el archivo objetivo desde la instantánea (si puedes crear VSS; a menudo requiere admin pero comúnmente está disponible para los mismos operadores que poseen SeManageVolumePrivilege)

Rutas sensibles típicas:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS tie‑in: Forging a Golden Certificate

If you can read the Enterprise CA’s private key from the machine key store, you can forge client‑auth certificates for arbitrary principals and authenticate via PKINIT/Schannel. This is often referred to as a Golden Certificate. See:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detección y hardening

- Limita fuertemente la asignación de SeManageVolumePrivilege (Perform volume maintenance tasks) solo a administradores de confianza.
- Monitorea el uso de Privilegios Sensibles y las aperturas de handle de procesos a objetos de dispositivo como \\.\C:, \\.\PhysicalDrive0.
- Prefiere claves de CA respaldadas por HSM/TPM o DPAPI-NG para que la lectura de archivos en bruto no pueda recuperar material de clave en forma usable.
- Mantén las rutas de uploads, temp y extracción no ejecutables y separadas (defensa en contexto web que a menudo acompaña esta cadena post‑explotación).

## References

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
