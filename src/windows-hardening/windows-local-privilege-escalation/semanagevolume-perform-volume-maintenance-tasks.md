# SeManageVolumePrivilege: Доступ до raw volume для довільного читання файлів

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Право користувача Windows: Виконання завдань з обслуговування томів (константа: SeManageVolumePrivilege).

Власники цього права можуть виконувати низькорівневі операції з томами, зокрема дефрагментацію, створення/видалення томів і maintenance IO. Критично важливо для attackers те, що це право дозволяє відкривати raw volume device handles (наприклад, \\.\C:) і виконувати прямий дисковий ввід/вивід, який обходить file ACLs NTFS. Маючи raw access, можна копіювати байти будь-якого файлу на томі, навіть якщо доступ заборонено DACL, аналізуючи структури файлової системи offline або використовуючи tools, які читають дані на рівні блоків/кластерів.

За замовчуванням: Administrators на серверах і domain controllers.<sup>[[1]](#references)</sup>

## Сценарії зловживання

- Довільне читання файлів в обхід ACL шляхом читання disk device (наприклад, exfiltrate чутливі system-protected матеріали, такі як machine private keys у %ProgramData%\Microsoft\Crypto\RSA\MachineKeys і %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit через VSS тощо).
- Обхід locked/privileged paths (C:\Windows\System32\…) шляхом прямого копіювання байтів із raw device.
- У середовищах AD CS exfiltrate key material CA (machine key store), щоб створювати “Golden Certificates” і impersonate будь-який domain principal через PKINIT. Див. посилання нижче.<sup>[[2]](#references)</sup>

Примітка: вам усе одно потрібен parser для структур NTFS, якщо ви не покладаєтеся на helper tools. Багато готових tools абстрагують raw access.

## Практичні техніки

- Відкрити raw volume handle і прочитати кластери:

<details>
<summary>Натисніть, щоб розгорнути</summary>
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

- Використовуйте NTFS-aware tool для відновлення певних файлів із raw volume:
- RawCopy/RawCopy64 (sector-level copy файлів, що використовуються)
- FTK Imager або The Sleuth Kit (read-only imaging, після чого виконайте carving файлів)
- vssadmin/diskshadow + shadow copy, після чого скопіюйте цільовий файл зі snapshot (якщо ви можете створювати VSS; часто для цього потрібні права адміністратора, але вони зазвичай доступні тим самим операторам, які мають SeManageVolumePrivilege)

Типові sensitive paths для перевірки:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – через shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys зберігаються у вказаному вище machine key store)

## AD CS tie‑in: Forging a Golden Certificate

Якщо ви можете прочитати private key Enterprise CA із machine key store, ви можете підробити client-auth certificates для довільних principals і виконати authentication через PKINIT/Schannel. Це часто називають Golden Certificate.<sup>[[2]](#references)</sup> Дивіться:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Розділ: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Detection and hardening

- Суворо обмежте призначення SeManageVolumePrivilege (Perform volume maintenance tasks) лише довіреними адміністраторами.
- Відстежуйте Sensitive Privilege Use і відкриття process handles до device objects на кшталт \\.\C:, \\.\PhysicalDrive0.
- Надавайте перевагу CA keys, захищеним HSM/TPM, або DPAPI-NG, щоб raw file reads не могли відновити key material у придатній для використання формі.
- Зберігайте uploads, temp і extraction paths такими, що не підтримують виконання, та відокремлюйте їх (захист web context, який часто поєднується з цим post‑exploitation chain).

## References

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
