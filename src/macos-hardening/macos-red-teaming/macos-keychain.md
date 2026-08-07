# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Основні Keychain

- **User Keychain** (`~/Library/Keychains/login.keychain-db`), який використовується для зберігання **облікових даних користувача**, таких як паролі застосунків, інтернет-паролі, сертифікати, створені користувачем, мережеві паролі та відкриті/приватні ключі, створені користувачем.
- **System Keychain** (`/Library/Keychains/System.keychain`), який зберігає **загальносистемні облікові дані**, такі як паролі WiFi, кореневі сертифікати системи, системні приватні ключі та паролі системних застосунків.<sup>[[1]](#references)</sup>
- Інші компоненти, наприклад сертифікати, можна знайти в `/System/Library/Keychains/*`
- В **iOS** існує лише один **Keychain**, розташований у `/private/var/Keychains/`. Ця папка також містить бази даних для `TrustStore`, центрів сертифікації (`caissuercache`) і записів OSCP (`ocspache`).
- Доступ застосунків у keychain обмежується їхньою приватною областю на основі ідентифікатора застосунку.

### Доступ до Password Keychain

Ці файли, хоча й не мають вбудованого захисту та можуть бути **завантажені**, зашифровані й потребують **пароля користувача у відкритому вигляді для розшифрування**. Для розшифрування можна використати інструмент на кшталт [**Chainbreaker**](https://github.com/n0fate/chainbreaker).<sup>[[1]](#references)</sup>

## Захист записів Keychain

### ACL

Кожен запис у keychain контролюється **Access Control Lists (ACLs)**, які визначають, хто може виконувати різні дії над записом keychain, зокрема:<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear**: Дозволяє власнику отримати секрет у відкритому вигляді.
- **ACLAuhtorizationExportWrapped**: Дозволяє власнику отримати секрет у відкритому вигляді, зашифрований за допомогою іншого наданого пароля.
- **ACLAuhtorizationAny**: Дозволяє власнику виконувати будь-яку дію.

ACL також супроводжується **списком довірених застосунків**, які можуть виконувати ці дії без запиту. Це може бути:<sup>[[1]](#references)</sup>

- **N`il`** (авторизація не потрібна, **довірено всім**)
- **Порожній** список (**нікому** не довірено)
- **Список** конкретних **застосунків**.

Запис також може містити ключ **`ACLAuthorizationPartitionID`,** який використовується для ідентифікації **teamid, apple** і **cdhash**.<sup>[[1]](#references)</sup>

- Якщо вказано **teamid**, то для **доступу до значення запису** **без запиту** використаний застосунок повинен мати **той самий teamid**.
- Якщо вказано **apple**, застосунок має бути **підписаний** **Apple**.
- Якщо вказано **cdhash**, **застосунок** повинен мати відповідний **cdhash**.

### Створення запису Keychain

Коли **новий** **запис** створюється за допомогою **`Keychain Access.app`**, застосовуються такі правила:<sup>[[1]](#references)</sup>

- Усі застосунки можуть шифрувати.
- **Жоден застосунок** не може експортувати/розшифровувати (без запиту користувачу).
- Усі застосунки можуть бачити перевірку цілісності.
- Жоден застосунок не може змінювати ACL.
- **partitionID** встановлюється в **`apple`**.

Коли **застосунок створює запис у keychain**, правила дещо відрізняються:<sup>[[1]](#references)</sup>

- Усі застосунки можуть шифрувати.
- Лише **застосунок, який створив запис** (або будь-які інші явно додані застосунки) може експортувати/розшифровувати (без запиту користувачу).
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

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> **Перерахування та dumping** секретів із **keychain**, які **не генерують prompt**, можна виконувати за допомогою tool [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Інші API endpoints можна знайти у вихідному коді [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Перераховуйте та отримуйте **інформацію** про кожен запис keychain за допомогою **Security Framework** або перевірте cli tool Apple з відкритим вихідним кодом [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Деякі приклади API:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** надає інформацію про кожен запис, і під час його використання можна встановити такі атрибути:
- **`kSecReturnData`**: Якщо має значення true, API спробує розшифрувати дані (встановіть false, щоб уникнути потенційних pop-up)
- **`kSecReturnRef`**: Також отримати reference на елемент keychain (встановіть true, якщо пізніше стане можливо розшифрувати його без pop-up)
- **`kSecReturnAttributes`**: Отримати metadata про записи
- **`kSecMatchLimit`**: Кількість результатів для повернення
- **`kSecClass`**: Тип запису keychain

Отримання **ACL** кожного запису:<sup>[[1]](#references)</sup>

- За допомогою API **`SecAccessCopyACLList`** можна отримати **ACL для елемента keychain**. API поверне список ACL (наприклад, `ACLAuhtorizationExportClear` та інші згадані раніше), де кожен список містить:
- Опис
- **Список Trusted Application**. Це може бути:
- App: /Applications/Slack.app
- Binary: /usr/libexec/airportd
- Group: group://AirPort

Експорт даних:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** отримує plaintext
- API **`SecItemExport`** експортує keys і certificates, але для експорту зашифрованого вмісту може знадобитися встановити passwords

Ось вимоги, за яких можна **експортувати секрет без prompt**:<sup>[[1]](#references)</sup>

- Якщо вказано 1+ **trusted** apps:
- Потрібні відповідні **authorizations** (**`Nil`** або необхідно бути **частиною** дозволеного списку apps в authorization для доступу до інформації про секрет)
- Code signature має відповідати **PartitionID**
- Code signature має відповідати code signature одного **trusted app** (або потрібно бути учасником правильного KeychainAccessGroup)
- Якщо **всі applications trusted**:
- Потрібні відповідні **authorizations**
- Code signature має відповідати **PartitionID**
- Якщо **PartitionID** відсутній, це не потрібно

> [!CAUTION]
> Тому, якщо **вказано 1 application**, необхідно **інжектувати code в цю application**.
>
> Якщо в **partitionID** вказано **apple**, до нього можна отримати доступ за допомогою **`osascript`**. Це стосується всього, що довіряє всім applications із apple у partitionID. Для цього також можна використовувати **`Python`**.

### Два додаткові атрибути

- **Invisible**: Це boolean flag, який **приховує** запис від **UI** Keychain app<sup>[[1]](#references)</sup>
- **General**: Використовується для зберігання **metadata** (тому воно НЕ ЗАШИФРОВАНЕ)<sup>[[1]](#references)</sup>
- Microsoft зберігала у plain text усі refresh tokens для доступу до sensitive endpoint.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
