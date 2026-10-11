# SeManageVolumePrivilege: зловживання обслуговуванням томів і перевірка доступу до raw-даних

{{#include ../../banners/hacktricks-training.md}}

## Огляд

Право користувача Windows: виконувати завдання з обслуговування томів (константа: SeManageVolumePrivilege).

Це право дозволяє виконувати операції з обслуговування томів, як-от дефрагментація та створення або видалення томів. Microsoft попереджає, що власник цього права може розширити файли на ділянки сховища з іншими даними, а потім читати або змінювати отримані байти.<sup>[[1]](#references)</sup>

Не вважайте наявність `SeManageVolumePrivilege` гарантією доступу до raw-диска. За документацією Microsoft, для прямого доступу до фізичного диска або тому через `CreateFile` потрібні адміністративні привілеї, а також продовжують діяти звичайні перевірки доступу до об’єктів і пристроїв. Для конкретної збірки або продукту перевірте, чи дозволяють токен, ACL пристрою, запитаний рівень доступу, прапорці спільного доступу та стан тому відкрити raw-handle, перш ніж стверджувати, що можна довільно читати файли.<sup>[[3]](#references)</sup>

За замовчуванням: адміністратори на серверах і контролерах домену.<sup>[[1]](#references)</sup>

## Сценарії зловживання

- Якщо обліковий запис справді може отримати дескриптор raw-тома з правом читання, парсер із підтримкою NTFS може обійти ACL окремих файлів і відновити захищені або заблоковані файли з виділених кластерів.
- Серед можливих цілей — захищений або заблокований вміст у `C:\Windows\System32`, кущі реєстру, головні ключі DPAPI, SAM і — за наявності окремого доступу через знімок або офлайн-том — `ntds.dit`.
- На хостах служб сертифікації корисні розташування програмних ключів: `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` і `%ProgramData%\Microsoft\Crypto\Keys`; відновлення файла корисне лише тоді, коли матеріал ключа можна експортувати та розшифрувати.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- На хості AD CS успішно відновлений **приватний ключ CA, який можна експортувати й який зберігається програмно**, може уможливити зловживання Golden Certificate. Апаратне зберігання ключа або його неможливість експорту змінюють цей сценарій.<sup>[[2]](#references)</sup>
- Деякі засоби обслуговування томів використовують `FSCTL_SD_GLOBAL_CHANGE` для заміни записів ACL файлової системи, якщо ця операція дозволена. Це змінює контроль доступу, а не пасивно читає raw-блоки; може вплинути на значну частину тому, тому поведінку потрібно перевірити з фактичним токеном і пристроєм. [Вихідний код інструмента](https://github.com/CsEnox/SeManageVolumeExploit) демонструє саме цей механізм; наявність права сама по собі не гарантує його успішного виконання.
- Отримання доступу до файлів через зміну ACL не розшифровує файл, зашифрований EFS. Для отримання відкритого тексту потрібен відповідний приватний ключ користувача або ключ відновлення. Так само можливість експортувати програмний ключ CA за допомогою [`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) залежить від того, чи доступний ключ локально, чи можна його експортувати та чи є до нього доступ.

Примітка: якщо не використовуєте допоміжні інструменти, вам усе одно знадобиться парсер структур NTFS. Багато готових інструментів абстрагують raw-доступ.

## Практичні прийоми

- Відкрити дескриптор raw-тома й читати кластери:

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

- Використовуйте інструмент із підтримкою NTFS, щоб відновити конкретні файли з необробленого тому:
  - RawCopy/RawCopy64 (копіювання файлів, що використовуються, на рівні секторів)
  - FTK Imager або The Sleuth Kit (створення образу лише для читання, а потім пошук файлів)
  - vssadmin/diskshadow + тіньова копія, а потім скопіюйте потрібний файл зі знімка (якщо можна створити VSS; зазвичай для цього потрібні права адміністратора, але вони часто є в тих самих операторів, які мають SeManageVolumePrivilege)

Типові шляхи до цільових конфіденційних файлів:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (локальні секрети)
- C:\Windows\NTDS\ntds.dit (контролери домену — через тіньову копію)
- C:\Windows\System32\CertSrv\CertEnroll\ (сертифікати/CRL центру сертифікації; закриті ключі зберігаються у сховищі ключів комп’ютера, наведеному вище)

## Зв’язок з AD CS: створення підробленого Golden Certificate

Якщо ви можете прочитати закритий ключ корпоративного центру сертифікації зі сховища ключів комп’ютера, ви можете створити підроблені сертифікати автентифікації клієнта для будь-яких суб’єктів і автентифікуватися через PKINIT/Schannel. Це часто називають Golden Certificate.<sup>[[2]](#references)</sup> Див.:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Розділ: «Створення підроблених сертифікатів за допомогою викрадених сертифікатів CA (Golden Certificate) — DPERSIST1».)

## Виявлення та посилення захисту

- Суворо обмежте призначення SeManageVolumePrivilege (Perform volume maintenance tasks) лише довіреним адміністраторам.
- Відстежуйте використання чутливих привілеїв і відкриття дескрипторів процесами для таких об’єктів пристроїв, як \\.\C:, \\.\PhysicalDrive0.
- Надавайте перевагу належно налаштованим, захищеним HSM або TPM ключам CA, які не можна експортувати, щоб самого копіювання файлу-контейнера ключа було недостатньо для відновлення придатного до використання матеріалу закритого ключа.
- Для секретів застосунків поза шляхом ключа CA DPAPI або DPAPI-NG можуть зробити копіювання файлу даних недостатнім, захищаючи його для користувача, комп’ютера, групи або іншого уповноваженого суб’єкта. Це не захищає відкритий текст, уже доступний скомпрометованому суб’єкту.<sup>[[4]](#references)</sup>
- Зберігайте завантаження, тимчасові файли та шляхи розпакування в окремих каталогах, де заборонено виконання файлів (захист вебсередовища, який часто доповнює цей ланцюжок post‑exploitation).

## References

- [1] [Microsoft — Виконання завдань з обслуговування томів (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf — HTB: Certificate (SeManageVolumePrivilege використовується для читання ключа CA → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft — `CreateFile`: фізичні диски й томи](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft — Cryptography API: Next Generation і DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
