# SeManageVolumePrivilege: Raw volume access for arbitrary file read

{{#include ../../banners/hacktricks-training.md}}

## Overview

Права користувача Windows: Виконувати завдання з обслуговування томів (constant: SeManageVolumePrivilege).

Тримачі цього права можуть виконувати низькорівневі операції з томами, такі як дефрагментація, створення/видалення томів та обслуговуючі IO. Критично для нападників, це право дозволяє відкривати raw-обробники пристроїв тома (наприклад, \\.\C:) і виконувати прямі дискові операції вводу/виводу, що обходять NTFS file ACLs. Маючи raw-доступ, ви можете скопіювати байти будь-якого файлу на томі навіть якщо DACL забороняє доступ, розбираючи структури файлової системи офлайн або використовуючи інструменти, що читають на рівні блоків/кластерів.

За замовчуванням: Administrators на серверах та контролерах домену.

## Abuse scenarios

- Читання довільних файлів з обходом ACLs шляхом читання пристрою диску (наприклад, ексфільтрація захищених системних матеріалів, таких як приватні ключі машини в %ProgramData%\Microsoft\Crypto\RSA\MachineKeys та %ProgramData%\Microsoft\Crypto\Keys, registry hives, DPAPI masterkeys, SAM, ntds.dit через VSS тощо).
- Обхід заблокованих/привілейованих шляхів (C:\Windows\System32\…) шляхом копіювання байтів безпосередньо з raw-пристрою.
- В середовищах AD CS — ексфільтрувати ключовий матеріал CA (machine key store), щоб випустити «Golden Certificates» і видати себе за будь-якого доменного суб’єкта через PKINIT. Див. посилання нижче.

Примітка: вам все ще потрібен парсер структур NTFS, якщо ви не покладаєтесь на допоміжні інструменти. Багато готових інструментів абстрагують raw-доступ.

## Practical techniques

- Open a raw volume handle and read clusters:

<details>
<summary>Клацніть, щоб розгорнути</summary>
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

- Використовуйте інструмент, що розуміє NTFS, щоб відновити конкретні файли з сирого тома:
- RawCopy/RawCopy64 (копіювання на рівні секторів активних файлів)
- FTK Imager or The Sleuth Kit (read-only imaging, then carve files)
- vssadmin/diskshadow + shadow copy, потім скопіюйте цільовий файл зі знімка (якщо ви можете створити VSS; часто вимагає прав адміністратора, але зазвичай доступне тим самим операторам, які мають SeManageVolumePrivilege)

Типові чутливі шляхи для цілей:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## Зв'язок з AD CS: Forging a Golden Certificate

Якщо ви можете прочитати приватний ключ Enterprise CA з machine key store, ви можете підробити client‑auth сертифікати для довільних суб’єктів і автентифікуватись через PKINIT/Schannel. Це часто називають Golden Certificate. Див.:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Розділ: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Виявлення та підвищення безпеки

- Суворо обмежте призначення SeManageVolumePrivilege (Perform volume maintenance tasks) лише довіреним адміністраторам.
- Моніторьте Sensitive Privilege Use та відкриття дескрипторів процесів до об'єктів пристроїв, наприклад \\.\C:, \\.\PhysicalDrive0.
- Віддавайте перевагу HSM/TPM-backed CA keys або DPAPI-NG, щоб читання сирих файлів не могло відновити матеріал ключа у придатному для використання вигляді.
- Тримайте шляхи для uploads, temp і extraction не виконуваними та розділеними (захист у веб-контексті, що часто поєднується з цим ланцюгом post‑exploitation).

## Посилання

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
