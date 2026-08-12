# SeManageVolumePrivilege: зловживання обслуговуванням томів і перевірка raw-доступу

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Права користувача Windows: виконання завдань з обслуговування томів (константа: SeManageVolumePrivilege).

Це право дозволяє виконувати операції з обслуговування томів, зокрема дефрагментацію та створення або видалення томів. Microsoft попереджає, що власник цього права може отримати можливість розширювати файли в сховище, яке містить інші дані, а потім читати або змінювати отримані байти.<sup>[[1]](#references)</sup>

Не слід ототожнювати наявність `SeManageVolumePrivilege` гарантованим доступом до raw-диска. Microsoft зазначає, що відкриття фізичного диска або тому через `CreateFile` для прямого доступу потребує адміністративних привілеїв, а стандартні перевірки доступу до об’єктів і пристроїв усе одно застосовуються. У конкретній збірці або продукті перевірте, чи дозволяють token, ACL пристрою, запитуваний доступ, прапорці спільного доступу та стан тому отримати raw handle, перш ніж заявляти про довільне читання файлів.<sup>[[3]](#references)</sup>

За замовчуванням: адміністратори на серверах і контролерах домену.<sup>[[1]](#references)</sup>

## Сценарії зловживання

- Якщо обліковий запис справді може отримати доступний для читання raw-volume handle, NTFS-aware parser може обійти ACL окремих файлів і відновити захищені або заблоковані файли з виділених кластерів.
- Потенційні цілі включають заблокований або захищений ACL вміст у `C:\Windows\System32`, registry hives, DPAPI master keys, SAM і — якщо окремо доступний через snapshot або offline volume — `ntds.dit`.
- На хостах certificate services корисні розташування software keys включають `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` і `%ProgramData%\Microsoft\Crypto\Keys`; відновлення файлу корисне лише тоді, коли його key material можна експортувати і також розшифрувати.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- На хості AD CS успішно відновлений **exportable/software-backed** CA private key може дозволити зловживання Golden Certificate. Конструкції з hardware-backed або non-exportable keys змінюють цей шлях.<sup>[[2]](#references)</sup>

Примітка: вам усе одно потрібен parser для структур NTFS, якщо ви не покладаєтеся на helper tools. Багато готових інструментів абстрагують raw-доступ.

## Практичні техніки

- Відкрити raw volume handle і прочитати кластери:

<details>
<summary>Натисніть, щоб розгорнути</summary>
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

- Використовуйте інструмент із підтримкою NTFS для відновлення певних файлів із raw volume:
- RawCopy/RawCopy64 (sector-level copy of in-use files)
- FTK Imager або The Sleuth Kit (read-only imaging, потім carve files)
- vssadmin/diskshadow + shadow copy, потім скопіюйте цільовий файл зі snapshot (якщо ви можете створити VSS; часто потрібні права адміністратора, але вони зазвичай доступні тим самим операторам, які мають SeManageVolumePrivilege)

Типові чутливі шляхи для цільового доступу:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (локальні secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – через shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certificates/CRLs; private keys зберігаються у вказаному вище machine key store)

## Зв’язок з AD CS: Forging a Golden Certificate

Якщо ви можете прочитати private key Enterprise CA із machine key store, ви можете підробити client-auth certificates для довільних principals і пройти authentication через PKINIT/Schannel. Це часто називають Golden Certificate.<sup>[[2]](#references)</sup> Дивіться:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Розділ: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## Виявлення та hardening

- Суворо обмежте призначення SeManageVolumePrivilege (Perform volume maintenance tasks) лише довіреними адміністраторами.
- Відстежуйте Sensitive Privilege Use і відкриття process handles до device objects, таких як \\.\C:, \\.\PhysicalDrive0.
- Надавайте перевагу належно налаштованим HSM- або TPM-backed, non-exportable CA keys, щоб скопійованого key-container file було недостатньо для відновлення придатного до використання private-key material.
- Для application secrets поза шляхом CA-key DPAPI або DPAPI-NG можуть зробити скопійований data file недостатнім, захистивши його для user, machine, group або іншого authorized principal. Це не захищає plaintext, до якого вже має доступ compromised principal.<sup>[[4]](#references)</sup>
- Зберігайте uploads, temp і extraction paths як non-executable та відокремленими (web context defense, яке часто доповнює цей ланцюжок post‑exploitation).

## References

- [1] [Microsoft – Виконання завдань з обслуговування томів (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege використано для читання CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` фізичних дисків і томів](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation і DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
