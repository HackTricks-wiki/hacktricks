# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Основні Keychain

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), який використовується для зберігання **облікових даних користувача**, таких як паролі застосунків, інтернет-паролі, сертифікати, створені користувачем, мережеві паролі та відкриті/приватні ключі, створені користувачем.
- **System Keychain** (`/Library/Keychains/System.keychain`), який зберігає **загальносистемні облікові дані**, як-от паролі WiFi, системні кореневі сертифікати, системні приватні ключі та паролі системних застосунків.<sup>[[1]](#references)</sup>
- Інші компоненти, як-от сертифікати, можна знайти в `/System/Library/Keychains/*`
- В **iOS** є лише один **Keychain**, розташований у `/private/var/Keychains/`. Ця папка також містить бази даних для `TrustStore`, центрів сертифікації (`caissuercache`) і записів OSCP (`ocspache`).
- Доступ застосунків до Keychain обмежується лише їхньою приватною областю на основі ідентифікатора застосунку.

### Доступ до Keychain за паролем

Ці файли, хоча й не мають вбудованого захисту та можуть бути **завантажені**, зашифровані й потребують **пароля користувача у відкритому вигляді для розшифрування**. Для розшифрування можна використати такий інструмент, як [**Chainbreaker**](https://github.com/n0fate/chainbreaker).<sup>[[1]](#references)</sup>

## Захист записів Keychain

### ACL

Кожен запис у Keychain регулюється **списками контролю доступу (ACL)**, які визначають, хто може виконувати різні дії над записом Keychain, зокрема:<sup>[[1]](#references)</sup>

- **ACLAuthorizationExportClear**: дозволяє власнику отримати секрет у відкритому вигляді.
- **ACLAuthorizationExportWrapped**: дозволяє власнику отримати секрет у відкритому вигляді, зашифрований за допомогою іншого наданого пароля.
- **ACLAuthorizationAny**: дозволяє власнику виконувати будь-які дії.

ACL також супроводжується **списком довірених застосунків**, які можуть виконувати ці дії без запиту. Це може бути:<sup>[[1]](#references)</sup>

- **N`il`** (авторизація не потрібна, **усі є довіреними**)
- **Порожній** список (**ніхто** не є довіреним)
- **Список** конкретних **застосунків**.

Запис також може містити ключ **`ACLAuthorizationPartitionID`,** який використовується для ідентифікації **teamid, apple** і **cdhash**.<sup>[[1]](#references)</sup>

- Якщо вказано **teamid**, застосунок повинен мати **такий самий teamid**, щоб **отримати доступ до** значення запису **без** **запиту**.
- Якщо вказано **apple**, застосунок має бути **підписаний** **Apple**.
- Якщо вказано **cdhash**, **застосунок** повинен мати конкретний **cdhash**.

### Створення запису Keychain

Коли за допомогою **`Keychain Access.app`** створюється **новий** **запис**, застосовуються такі правила:<sup>[[1]](#references)</sup>

- Усі застосунки можуть шифрувати.
- **Жоден застосунок** не може експортувати/розшифровувати (без запиту до користувача).
- Усі застосунки можуть бачити перевірку цілісності.
- Жоден застосунок не може змінювати ACL.
- **partitionID** встановлюється в **`apple`**.

Коли **застосунок створює запис у Keychain**, правила дещо відрізняються:<sup>[[1]](#references)</sup>

- Усі застосунки можуть шифрувати.
- Лише **застосунок, який створив запис** (або будь-які інші явно додані застосунки) може експортувати/розшифровувати (без запиту до користувача).
- Усі застосунки можуть бачити перевірку цілісності.
- Жоден застосунок не може змінювати ACL.
- **partitionID** встановлюється в **`teamid:[teamID here]`**.

## Доступ до Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entry's PartitionID value
security set-generic-password-partition-list -s "test service" -a "test account" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> **Перерахування та дампінг секретів у keychain**, які **не створюють prompt**, можна виконати за допомогою інструмента [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Інші API endpoints можна знайти у вихідному коді [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Перелічіть і отримайте **інформацію** про кожен запис keychain за допомогою **Security Framework** або перевірте open source cli tool від Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Деякі приклади API:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** надає інформацію про кожен запис, і під час його використання можна встановити такі атрибути:
- **`kSecReturnData`**: Якщо true, буде виконано спробу розшифрувати дані (встановіть false, щоб уникнути потенційних pop-up)
- **`kSecReturnRef`**: Також отримати reference на елемент keychain (встановіть true, якщо пізніше ви побачите, що можете розшифрувати його без pop-up)
- **`kSecReturnAttributes`**: Отримати metadata про записи
- **`kSecMatchLimit`**: Кількість результатів для повернення
- **`kSecClass`**: Тип запису keychain

Отримання **ACLs** кожного запису:<sup>[[1]](#references)</sup>

- За допомогою API **`SecAccessCopyACLList`** можна отримати **ACL для елемента keychain**. Він повертає список ACLs (наприклад, `ACLAuthorizationExportClear` та інші згадані раніше), де кожен запис містить:
- Опис
- **Trusted Application List**. Це може бути:
- Застосунок: /Applications/Slack.app
- Бінарний файл: /usr/libexec/airportd
- Група: group://AirPort

Експорт даних:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** отримує plaintext
- API **`SecItemExport`** експортує ключі та сертифікати, але для експорту зашифрованого вмісту може знадобитися встановити passwords

Ось вимоги, за яких можна **експортувати секрет без prompt**:<sup>[[1]](#references)</sup>

- Якщо вказано 1+ trusted apps:
- Потрібні відповідні **authorizations** (**`Nil`** або необхідно бути **частиною** дозволеного списку apps в authorization для доступу до інформації про секрет)
- Code signature має відповідати **PartitionID**
- Code signature має відповідати code signature одного **trusted app** (або необхідно бути членом відповідного KeychainAccessGroup)
- Якщо **all applications trusted**:
- Потрібні відповідні **authorizations**
- Code signature має відповідати **PartitionID**
- Якщо **немає PartitionID**, це не потрібно

> [!CAUTION]
> Отже, якщо **вказано 1 application**, потрібно **інжектити code в цей application**.
>
> Якщо в **partitionID** вказано **apple**, до нього можна отримати доступ за допомогою **`osascript`**, тобто це стосується всього, що довіряє всім applications з apple у partitionID. Для цього також можна використовувати **`Python`**.

### Two additional attributes

- **Invisible**: Це boolean flag, який **приховує** запис від **UI**-застосунку Keychain<sup>[[1]](#references)</sup>
- **General**: Використовується для зберігання **metadata** (тому воно НЕ ЗАШИФРОВАНЕ)<sup>[[1]](#references)</sup>
- Microsoft зберігала у відкритому тексті всі refresh tokens для доступу до чутливого endpoint.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Злам macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
{{#include ../../banners/hacktricks-training.md}}
