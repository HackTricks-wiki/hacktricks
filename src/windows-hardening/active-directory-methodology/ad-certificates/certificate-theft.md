# Крадіжка сертифікатів AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Це короткий підсумок розділів про крадіжку з чудового дослідження [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[1]](#references)</sup>

## Що можна робити із сертифікатом

Перш ніж перевіряти, як викрасти сертифікати, ознайомтеся з інформацією про те, для чого можна використовувати сертифікат:
```bash
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Експорт сертифікатів за допомогою Crypto APIs – THEFT1

В **інтерактивному сеансі робочого столу** вилучення сертифіката користувача або комп’ютера разом із приватним ключем можна легко виконати, особливо якщо **приватний ключ доступний для експорту**. Для цього потрібно перейти до сертифіката в `certmgr.msc`, клацнути його правою кнопкою миші та вибрати `All Tasks → Export`, щоб створити захищений паролем файл .pfx.<sup>[[1]](#references)</sup>

Для **програмного підходу** можна використовувати такі інструменти, як PowerShell cmdlet `ExportPfxCertificate`, або проєкти на кшталт [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer). Вони використовують **Microsoft CryptoAPI** (CAPI) або Cryptography API: Next Generation (CNG) для взаємодії зі сховищем сертифікатів. Ці API надають широкий набір криптографічних служб, зокрема необхідних для зберігання сертифікатів і автентифікації.

Однак якщо приватний ключ позначено як недоступний для експорту, CAPI і CNG зазвичай блокують вилучення таких сертифікатів. Щоб обійти це обмеження, можна використовувати такі інструменти, як **Mimikatz**. Mimikatz надає команди `crypto::capi` і `crypto::cng` для внесення патчів у відповідні API, що дозволяє експортувати приватні ключі. Зокрема, `crypto::capi` вносить патч у CAPI в межах поточного процесу, тоді як `crypto::cng` спрямований на пам’ять **lsass.exe** для внесення патча.

## Крадіжка сертифікатів користувача через DPAPI – THEFT2

Додаткова інформація про DPAPI:


{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

У Windows **приватні ключі сертифікатів захищені DPAPI**. Важливо враховувати, що **місця зберігання приватних ключів користувача та комп’ютера** відрізняються, а структури файлів залежать від криптографічного API, який використовується операційною системою. **SharpDPAPI** — це інструмент, який може автоматично враховувати ці відмінності під час розшифрування DPAPI blobs.<sup>[[1]](#references)</sup>

**Сертифікати користувача** переважно зберігаються в реєстрі за адресою `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, але деякі з них також можна знайти в каталозі `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Відповідні **приватні ключі** для цих сертифікатів зазвичай зберігаються в `%APPDATA%\Microsoft\Crypto\RSA\User SID\` для ключів **CAPI** і в `%APPDATA%\Microsoft\Crypto\Keys\` для ключів **CNG**.

Щоб **вилучити сертифікат і пов’язаний із ним приватний ключ**, потрібно виконати такі дії:

1. **Вибрати цільовий сертифікат** у сховищі користувача та отримати ім’я його сховища ключів.
2. **Знайти необхідний DPAPI masterkey** для розшифрування відповідного приватного ключа.
3. **Розшифрувати приватний ключ**, використовуючи DPAPI masterkey у відкритому вигляді.

Для **отримання DPAPI masterkey у відкритому вигляді** можна використовувати такі підходи:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Щоб спростити розшифрування файлів masterkey і файлів приватних ключів, корисною є команда `certificates` з [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI). Вона приймає `/pvk`, `/mkfile`, `/password` або `{GUID}:KEY` як аргументи для розшифрування приватних ключів і пов’язаних сертифікатів, після чого створює файл `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Крадіжка сертифікатів комп’ютера через DPAPI – THEFT3

Сертифікати комп’ютера, які Windows зберігає в реєстрі за адресою `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates`, і пов’язані з ними приватні ключі, розташовані в `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (для CAPI) та `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (для CNG), зашифровані за допомогою головних ключів DPAPI комп’ютера. Ці ключі не можна розшифрувати за допомогою резервного ключа DPAPI домену; натомість потрібен **DPAPI_SYSTEM LSA secret**, доступ до якого має лише користувач SYSTEM.<sup>[[1]](#references)</sup>

Ручне розшифрування можна виконати, запустивши команду `lsadump::secrets` у **Mimikatz**, щоб отримати DPAPI_SYSTEM LSA secret, а потім використати цей ключ для розшифрування головних ключів комп’ютера. Як альтернативу можна використати команду Mimikatz `crypto::certificates /export /systemstore:LOCAL_MACHINE` після patching CAPI/CNG, як описано раніше.

**SharpDPAPI** пропонує більш автоматизований підхід за допомогою своєї команди certificates. Якщо використовувати прапорець `/machine` з підвищеними привілеями, він підвищує привілеї до SYSTEM, витягує DPAPI_SYSTEM LSA secret, використовує його для розшифрування головних ключів DPAPI комп’ютера, а потім застосовує ці розшифровані ключі як lookup table для розшифрування будь-яких приватних ключів сертифікатів комп’ютера.

## Пошук файлів сертифікатів – THEFT4

Сертифікати іноді знаходяться безпосередньо у файловій системі, наприклад у file shares або папці Downloads. Найпоширенішими типами файлів сертифікатів, орієнтованих на середовища Windows, є файли `.pfx` і `.p12`. Рідше трапляються файли з розширеннями `.pkcs12` і `.pem`. До інших важливих розширень файлів, пов’язаних із сертифікатами, належать:<sup>[[1]](#references)</sup>

- `.key` для приватних ключів,
- `.crt`/`.cer` лише для сертифікатів,
- `.csr` для Certificate Signing Requests, які не містять сертифікатів або приватних ключів,
- `.jks`/`.keystore`/`.keys` для Java Keystores, які можуть містити сертифікати разом із приватними ключами, що використовуються Java applications.

Ці файли можна шукати за допомогою PowerShell або командного рядка, перевіряючи наявність згаданих розширень.

Якщо знайдено файл сертифіката PKCS#12, захищений паролем, з нього можна отримати hash за допомогою `pfx2john.py`, доступного на [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Після цього JohnTheRipper можна використати для спроби crack пароля.
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## Крадіжка облікових даних NTLM через PKINIT – THEFT5 (UnPAC the hash)

Наведений матеріал описує метод крадіжки облікових даних NTLM через PKINIT, зокрема метод крадіжки під назвою THEFT5. Нижче наведено переказ у пасивному стані, із знеособленням і стислим узагальненням окремих частин:<sup>[[1]](#references)</sup>

Для підтримки NTLM-аутентифікації `MS-NLMP` у застосунках, які не підтримують Kerberos-аутентифікацію, KDC налаштовано повертати односторонню функцію (OWF) NTLM користувача в сертифікаті атрибутів привілеїв (PAC), зокрема в буфері `PAC_CREDENTIAL_INFO`, коли використовується PKCA. Отже, якщо обліковий запис проходить автентифікацію та отримує Ticket-Granting Ticket (TGT) через PKINIT, автоматично надається механізм, за допомогою якого поточний хост може отримати хеш NTLM із TGT для підтримки застарілих протоколів автентифікації. Цей процес передбачає розшифрування структури `PAC_CREDENTIAL_DATA`, яка фактично є NDR-серіалізованим представленням NTLM plaintext.

Зазначається, що утиліта **Kekeo**, доступна за адресою [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), може запитувати TGT, що містить ці дані, у такий спосіб отримуючи NTLM користувача. Для цього використовується така команда:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** також може отримати цю інформацію за допомогою опції **`asktgt [...] /getcredentials`**.

Крім того, зазначається, що Kekeo може обробляти сертифікати, захищені smartcard, якщо вдається отримати pin; як посилання наведено [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Вказується, що таку саму можливість підтримує **Rubeus**, доступний за адресою [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Це пояснення охоплює процес та інструменти, задіяні у викраденні облікових даних NTLM через PKINIT, зосереджуючись на отриманні NTLM-хешів через TGT, отриманий за допомогою PKINIT, а також на утилітах, які спрощують цей процес.

## Посилання

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
