# AD CS Certificate Theft

{{#include ../../../banners/hacktricks-training.md}}

**Це невеликий підсумок розділів про крадіжку з чудового дослідження з [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Що я можу зробити з сертифікатом

Перед тим, як перевірити, як вкрасти сертифікати, тут є деяка інформація про те, для чого може бути корисний сертифікат:
```powershell
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

В **інтерактивній сесії робочого столу** витягти сертифікат користувача або машини разом з приватним ключем можна досить легко, особливо якщо **приватний ключ є експортованим**. Це можна зробити, перейшовши до сертифіката в `certmgr.msc`, клацнувши правою кнопкою миші на ньому та вибравши `Усі завдання → Експорт`, щоб згенерувати файл .pfx з паролем.

Для **програмного підходу** доступні такі інструменти, як PowerShell `ExportPfxCertificate` cmdlet або проекти, такі як [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer). Вони використовують **Microsoft CryptoAPI** (CAPI) або Cryptography API: Next Generation (CNG) для взаємодії з магазином сертифікатів. Ці API надають ряд криптографічних послуг, включаючи ті, що необхідні для зберігання та аутентифікації сертифікатів.

Однак, якщо приватний ключ встановлено як неекспортований, як CAPI, так і CNG зазвичай блокують витяг таких сертифікатів. Щоб обійти це обмеження, можна використовувати такі інструменти, як **Mimikatz**. Mimikatz пропонує команди `crypto::capi` та `crypto::cng` для патчування відповідних API, що дозволяє експортувати приватні ключі. Зокрема, `crypto::capi` патчує CAPI в поточному процесі, тоді як `crypto::cng` націлюється на пам'ять **lsass.exe** для патчування.

## Викрадення сертифікатів користувача через DPAPI – THEFT2

Більше інформації про DPAPI в:

{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

У Windows **приватні ключі сертифікатів захищені DPAPI**. Важливо усвідомлювати, що **місця зберігання приватних ключів користувача та машини** відрізняються, а файлові структури варіюються в залежності від криптографічного API, що використовується операційною системою. **SharpDPAPI** — це інструмент, який може автоматично орієнтуватися в цих відмінностях під час розшифровки DPAPI blobs.

**Сертифікати користувачів** переважно зберігаються в реєстрі під `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, але деякі також можна знайти в каталозі `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Відповідні **приватні ключі** для цих сертифікатів зазвичай зберігаються в `%APPDATA%\Microsoft\Crypto\RSA\User SID\` для **CAPI** ключів та `%APPDATA%\Microsoft\Crypto\Keys\` для **CNG** ключів.

Щоб **витягти сертифікат та його асоційований приватний ключ**, процес включає:

1. **Вибір цільового сертифіката** з магазину користувача та отримання його імені ключа.
2. **Знаходження необхідного DPAPI masterkey** для розшифровки відповідного приватного ключа.
3. **Розшифровка приватного ключа** за допомогою відкритого DPAPI masterkey.

Для **отримання відкритого DPAPI masterkey** можна використовувати такі підходи:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Щоб спростити розшифрування файлів masterkey та приватних ключів, команда `certificates` з [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) є корисною. Вона приймає `/pvk`, `/mkfile`, `/password` або `{GUID}:KEY` як аргументи для розшифрування приватних ключів та пов'язаних сертифікатів, після чого генерує файл `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Викрадення сертифікатів машини через DPAPI – THEFT3

Сертифікати машин, збережені Windows у реєстрі за адресою `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates`, та відповідні приватні ключі, розташовані в `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (для CAPI) та `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (для CNG), шифруються за допомогою майстер-ключів DPAPI машини. Ці ключі не можуть бути розшифровані за допомогою резервного ключа DPAPI домену; натомість потрібен **секрет DPAPI_SYSTEM LSA**, до якого може отримати доступ лише користувач SYSTEM.

Ручна розшифровка може бути досягнута шляхом виконання команди `lsadump::secrets` у **Mimikatz** для витягнення секрету DPAPI_SYSTEM LSA, а потім використання цього ключа для розшифровки майстер-ключів машини. Альтернативно, команду `crypto::certificates /export /systemstore:LOCAL_MACHINE` у Mimikatz можна використовувати після патчування CAPI/CNG, як було описано раніше.

**SharpDPAPI** пропонує більш автоматизований підхід з його командою сертифікатів. Коли використовується прапорець `/machine` з підвищеними правами, він ескалюється до SYSTEM, вивантажує секрет DPAPI_SYSTEM LSA, використовує його для розшифровки майстер-ключів DPAPI машини, а потім використовує ці відкриті ключі як таблицю для розшифровки будь-яких приватних ключів сертифікатів машини.

## Пошук файлів сертифікатів – THEFT4

Сертифікати іноді знаходяться безпосередньо у файловій системі, наприклад, у загальних папках або папці Завантаження. Найбільш поширеними типами файлів сертифікатів, націлених на Windows-середовища, є файли `.pfx` та `.p12`. Хоча рідше, також з'являються файли з розширеннями `.pkcs12` та `.pem`. Додаткові помітні розширення файлів, пов'язаних із сертифікатами, включають:

- `.key` для приватних ключів,
- `.crt`/`.cer` лише для сертифікатів,
- `.csr` для запитів на підписання сертифікатів, які не містять сертифікатів або приватних ключів,
- `.jks`/`.keystore`/`.keys` для Java Keystores, які можуть містити сертифікати разом із приватними ключами, що використовуються Java-додатками.

Ці файли можна шукати за допомогою PowerShell або командного рядка, шукаючи згадані розширення.

У випадках, коли знайдено файл сертифіката PKCS#12, і він захищений паролем, витягнення хешу можливе за допомогою `pfx2john.py`, доступного на [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Після цього можна використовувати JohnTheRipper для спроби зламати пароль.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5

Наведений контент пояснює метод крадіжки облікових даних NTLM через PKINIT, зокрема через метод крадіжки, позначений як THEFT5. Ось повторне пояснення в пасивному голосі, з анонімізацією та узагальненням контенту, де це доречно:

Щоб підтримувати NTLM аутентифікацію [MS-NLMP] для додатків, які не забезпечують аутентифікацію Kerberos, KDC розроблений для повернення односторонньої функції NTLM (OWF) користувача в сертифікаті атрибутів привілеїв (PAC), зокрема в буфері `PAC_CREDENTIAL_INFO`, коли використовується PKCA. Відповідно, якщо обліковий запис аутентифікується та отримує квиток на отримання квитків (TGT) через PKINIT, механізм, який дозволяє поточному хосту витягувати NTLM хеш з TGT для підтримки застарілих протоколів аутентифікації, надається за замовчуванням. Цей процес передбачає розшифровку структури `PAC_CREDENTIAL_DATA`, яка є по суті NDR серіалізованим зображенням NTLM у відкритому вигляді.

Утиліта **Kekeo**, доступна за [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), згадується як така, що здатна запитувати TGT, що містить ці специфічні дані, тим самим полегшуючи отримання NTLM користувача. Команда, що використовується для цієї мети, є такою:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Додатково зазначено, що Kekeo може обробляти сертифікати, захищені смарт-картами, якщо пін-код можна отримати, з посиланням на [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Така ж можливість підтримується **Rubeus**, доступним за [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Це пояснення охоплює процес і інструменти, що беруть участь у крадіжці облікових даних NTLM через PKINIT, зосереджуючи увагу на отриманні хешів NTLM через TGT, отриманий за допомогою PKINIT, та утиліти, які полегшують цей процес.

{{#include ../../../banners/hacktricks-training.md}}
