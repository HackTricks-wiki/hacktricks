# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Основні Keychain

- **Користувацький Keychain** (`~/Library/Keychains/login.keychain-db`), який використовується для зберігання **облікових даних користувача**, таких як паролі застосунків, інтернет-паролі, створені користувачем сертифікати, мережеві паролі та створені користувачем відкриті/приватні ключі.
- **Системний Keychain** (`/Library/Keychains/System.keychain`), у якому зберігаються **загальносистемні облікові дані**, зокрема паролі WiFi, системні кореневі сертифікати, системні приватні ключі та паролі системних застосунків.<sup>[[1]](#references)</sup>
- В `/System/Library/Keychains/*` можна знайти інші компоненти, наприклад сертифікати.
- У **iOS** є лише один **Keychain**, розташований у `/private/var/Keychains/`. Ця папка також містить бази даних для `TrustStore`, центрів сертифікації (`caissuercache`) і записів OSCP (`ocspache`).
- Доступ застосунків до Keychain обмежений лише їхньою приватною областю на основі ідентифікатора застосунку.

### Доступ до Password Keychain

Ці файли, хоча й не мають вбудованого захисту та можуть бути **завантажені**, зашифровані й потребують **пароля користувача у відкритому вигляді для розшифрування**. Для розшифрування можна використати такий інструмент, як [**Chainbreaker**](https://github.com/n0fate/chainbreaker).<sup>[[1]](#references)</sup>

## Захист записів Keychain

### ACL

Кожен запис у Keychain регулюється **списками контролю доступу (ACL)**, які визначають, хто може виконувати різні дії над записом Keychain, зокрема:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: Дозволяє власнику отримати секрет у відкритому вигляді.
- **ACLAuhtorizationExportWrapped**: Дозволяє власнику отримати секрет у відкритому вигляді, зашифрований за допомогою іншого наданого пароля.
- **ACLAuhtorizationAny**: Дозволяє власнику виконувати будь-які дії.

ACL також супроводжуються **списком довірених застосунків**, які можуть виконувати ці дії без запиту. Це може бути:<sup>[[1]](#references)</sup>

- **N`il`** (авторизація не потрібна, **усі є довіреними**)
- **Порожній** список (**ніхто** не є довіреним)
- **Список** конкретних **застосунків**.

Запис також може містити ключ **`ACLAuthorizationPartitionID`,** який використовується для ідентифікації **teamid, apple** і **cdhash**.<sup>[[1]](#references)</sup>

- Якщо вказано **teamid**, то для **доступу до значення запису** **без** **запиту** використаний застосунок повинен мати **той самий teamid**.
- Якщо вказано **apple**, застосунок має бути **підписаний** **Apple**.
- Якщо вказано **cdhash**, **застосунок** повинен мати конкретний **cdhash**.

### Створення запису Keychain

Коли за допомогою **`Keychain Access.app`** створюється **новий** **запис**, застосовуються такі правила:<sup>[[1]](#references)</sup>

- Усі застосунки можуть шифрувати.
- **Жоден застосунок** не може експортувати/розшифровувати (без запиту до користувача).
- Усі застосунки можуть бачити перевірку цілісності.
- Жоден застосунок не може змінювати ACL.
- Значення **partitionID** встановлюється як **`apple`**.

Коли **застосунок створює запис у Keychain**, правила дещо відрізняються:<sup>[[1]](#references)</sup>

- Усі застосунки можуть шифрувати.
- Лише **застосунок, який створив запис** (або будь-які інші явно додані застосунки) може експортувати/розшифровувати (без запиту до користувача).
- Усі застосунки можуть бачити перевірку цілісності.
- Жоден застосунок не може змінювати ACL.
- Значення **partitionID** встановлюється як **`teamid:[teamID here]`**.

## Доступ до Keychain

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> **Перерахування та дамп** секретів **keychain**, які **не генерують prompt**, можна виконати за допомогою інструмента [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Інші API endpoints можна знайти у вихідному коді [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Перераховуйте та отримуйте **info** про кожен запис keychain за допомогою **Security Framework** або перевірте cli-інструмент Apple з відкритим вихідним кодом [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Деякі приклади API:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** надає info про кожен запис, і під час його використання можна встановити такі атрибути:
- **`kSecReturnData`**: Якщо true, буде виконано спробу розшифрувати дані (встановіть false, щоб уникнути потенційних pop-up)
- **`kSecReturnRef`**: Також отримати reference на елемент keychain (встановіть true, якщо пізніше ви побачите, що його можна розшифрувати без pop-up)
- **`kSecReturnAttributes`**: Отримати metadata про записи
- **`kSecMatchLimit`**: Кількість результатів для повернення
- **`kSecClass`**: Тип запису keychain

Отримання **ACL** кожного запису:<sup>[[1]](#references)</sup>

- За допомогою API **`SecAccessCopyACLList`** можна отримати **ACL для елемента keychain**; він поверне список ACL (наприклад, `ACLAuhtorizationExportClear` та інші згадані раніше), де кожен список містить:
- Опис
- **Список Trusted Application**. Це може бути:
- App: /Applications/Slack.app
- Binary: /usr/libexec/airportd
- Group: group://AirPort

Експорт даних:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** отримує plaintext
- API **`SecItemExport`** експортує ключі та сертифікати, але для експорту зашифрованого вмісту може знадобитися встановити passwords

А це **вимоги**, необхідні для **експорту секрету без prompt**:<sup>[[1]](#references)</sup>

- Якщо вказано **1+ trusted** app:
- Потрібні відповідні **authorizations** (**`Nil`** або бути **частиною** дозволеного списку app в authorization для доступу до інформації про секрет)
- Code signature має відповідати **PartitionID**
- Code signature має відповідати code signature одного **trusted app** (або потрібно бути членом відповідного KeychainAccessGroup)
- Якщо **всі applications trusted**:
- Потрібні відповідні **authorizations**
- Code signature має відповідати **PartitionID**
- Якщо **PartitionID** відсутній, це не потрібно

> [!CAUTION]
> Отже, якщо вказано **1 application**, потрібно **інжектувати code в цю application**.
>
> Якщо в **partitionID** зазначено **apple**, до нього можна отримати доступ за допомогою **`osascript`**; це стосується всього, що довіряє всім applications із apple у partitionID. Для цього також можна використати **`Python`**.

### Two additional attributes

- **Invisible**: Boolean flag, що **приховує** запис від **UI**-застосунку Keychain<sup>[[1]](#references)</sup>
- **General**: Використовується для зберігання **metadata** (тому воно НЕ ЗАШИФРОВАНЕ)<sup>[[1]](#references)</sup>
- Microsoft зберігала у plain text усі refresh tokens для доступу до sensitive endpoint.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
