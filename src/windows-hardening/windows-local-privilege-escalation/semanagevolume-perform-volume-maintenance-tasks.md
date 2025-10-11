# SeManageVolumePrivilege: Доступ до сирого тому для довільного читання файлів

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Право користувача Windows: Perform volume maintenance tasks (константа: SeManageVolumePrivilege).

Тримачі цього права можуть виконувати низькорівневі операції з томом, такі як дефрагментація, створення/видалення томів та обслуговуючі I/O. Критично для атакуючих: це право дозволяє відкривати дескриптори пристрою сирого тому (наприклад, \\.\C:) та виконувати прямі дискові I/O, що обходять NTFS file ACLs. Маючи сирий доступ, можна копіювати байти будь-якого файлу на томі навіть якщо доступ заборонений DACL, парсити структури файлової системи офлайн або використовувати інструменти, що читають на рівні блоків/кластерів.

За замовчуванням: адміністратори на серверах і контролерах домену.

## Сценарії зловживань

- Довільне читання файлів із обходом ACLs шляхом читання дискового пристрою (наприклад, exfiltrate sensitive system-protected material such as machine private keys under %ProgramData%\Microsoft\Crypto\RSA\MachineKeys and %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit via VSS, etc.).
- Обхід заблокованих/привілеєваних шляхів (C:\Windows\System32\…) шляхом прямого копіювання байтів з сирого пристрою.
- В середовищах AD CS — витягнути ключовий матеріал CA (machine key store) для випуску “Golden Certificates” і імітувати будь-який доменний об’єкт за допомогою PKINIT. Див. посилання нижче.

Примітка: Вам все одно потрібен парсер для NTFS structures якщо ви не покладаєтесь на допоміжні інструменти. Багато готових інструментів абстрагують сирий доступ.

## Практичні методи

- Відкрити дескриптор сирого тому та читати кластери:

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

- Використовуйте інструмент, що підтримує NTFS, щоб відновити конкретні файли з сирого тому:
- RawCopy/RawCopy64 (sector-level copy of in-use files)
- FTK Imager or The Sleuth Kit (read-only imaging, then carve files)
- vssadmin/diskshadow + shadow copy, then copy target file from the snapshot (if you can create VSS; often requires admin but commonly available to the same operators that hold SeManageVolumePrivilege)

Типові чутливі шляхи для цілей:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS tie‑in: Forging a Golden Certificate

Якщо ви можете прочитати приватний ключ Enterprise CA з сховища ключів машини, ви можете підробити сертифікати client‑auth для довільних принципалів і автентифікуватися через PKINIT/Schannel. Це часто називають Golden Certificate. Дивіться:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Розділ: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Виявлення та захист

- Суворо обмежте призначення SeManageVolumePrivilege (Perform volume maintenance tasks) лише довіреним адміністраторам.
- Моніторьте Sensitive Privilege Use та відкриття дескрипторів процесів до об'єктів пристроїв, таких як \\.\C:, \\.\PhysicalDrive0.
- Віддавайте перевагу CA-ключам, захищеним HSM/TPM, або DPAPI-NG, щоб читання сирих файлів не могло відновити ключовий матеріал у придатному для використання вигляді.
- Тримайте шляхи для завантажень, тимчасових файлів і вилучення не виконуваними та розділеними (захист у веб-контексті, що часто поєднується з цією ланцюжком post‑exploitation).

## Джерела

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
