# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Основні зв'язки ключів

- **Зв'язка ключів користувача** (`~/Library/Keychains/login.keychain-db`) використовується для зберігання **облікових даних користувача**, як-от паролів програм, інтернет-паролів, створених користувачем сертифікатів, мережевих паролів і створених користувачем відкритих/закритих ключів.
- **Системна зв'язка ключів** (`/Library/Keychains/System.keychain`) зберігає **загальносистемні облікові дані**, як-от паролі WiFi, системні кореневі сертифікати, системні закриті ключі та паролі системних програм.<sup>[[1]](#references)</sup>
  - Інші компоненти, як-от сертифікати, можна знайти в `/System/Library/Keychains/*`
- **Зв'язка ключів захисту даних** для кожного користувача відображається в Keychain Access як **Local Items** або **iCloud**. Вона відокремлена від `login.keychain-db` і містить як локальні, так і синхронізовані елементи; `security` — це насамперед інструмент для файлових зв'язок ключів, тому короткий результат `dump-keychain` не виключає наявності тут облікових даних.<sup>[[5]](#references)</sup>
- В **iOS** є лише одна **зв'язка ключів**, розташована в `/private/var/Keychains/`. Ця папка також містить бази даних для `TrustStore`, центрів сертифікації (`caissuercache`) і записів OSCP (`ocspache`).
  - Доступ програм у зв'язці ключів обмежений їхньою приватною областю на основі ідентифікатора програми.

### Доступ до паролів у зв'язці ключів

Скопійована **файлова** зв'язка ключів не зберігається у відкритому тексті. Для офлайн-розшифрування захищених елементів потрібен пароль зв'язки ключів або еквівалентний ключовий матеріал; [**Chainbreaker**](https://github.com/n0fate/chainbreaker) призначений для роботи з цим форматом.<sup>[[1]](#references)</sup> Це відрізняється від читання під час активного сеансу розблокованого користувача, коли засоби контролю доступу до елементів можуть дозволити читання або викликати запит без повторного введення пароля для входу. Зв'язка ключів захисту даних має іншу модель захисту та груп доступу.<sup>[[5]](#references)</sup>

## Захист записів зв'язки ключів

### ACL файлової зв'язки ключів

Наведені нижче правила ACL `SecAccess` і списку розділів описують **файлові** зв'язки ключів. Для елементів зв'язки ключів захисту даних натомість використовуються групи доступу для підписування коду та необов'язкові умови `SecAccessControl`; не робіть висновків про їхню доступність на основі дампу ACL файлової зв'язки ключів.<sup>[[5]](#references)</sup>

Кожен запис у файловій зв'язці ключів регулюється **списками контролю доступу (ACL)**, які визначають, хто може виконувати різні дії із записом зв'язки ключів, зокрема:<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`**: Дозволяє власнику отримати секрет у відкритому тексті.
- **`kSecACLAuthorizationExportWrapped`**: Дозволяє власнику отримати секрет у відкритому тексті, зашифрований за допомогою іншого наданого пароля.
- **`kSecACLAuthorizationAny`**: Дозволяє власнику виконувати будь-які дії.

ACL також містять **список довірених програм**, які можуть виконувати ці дії без запиту. Це може бути:<sup>[[1]](#references)</sup>

- **N`il`** (авторизація не потрібна, **довірені всі**)
- **Порожній** список (**нікому** не довірено)
- **Список** певних **програм**.

Запис також може містити ключ **`kSecACLAuthorizationPartitionID`,** який використовується для ідентифікації **teamid, apple** і **cdhash**.<sup>[[1]](#references)[[2]](#references)</sup>

- Якщо вказано **teamid**, програма має мати **той самий teamid**, щоб **отримати доступ до значення запису** **без** **запиту**.
- Якщо вказано **apple**, програма має бути **підписана** **Apple**.
- Якщо вказано **cdhash**, **програма** має мати відповідний **cdhash**.

### Створення запису у файловій зв'язці ключів

Під час створення **нового** **запису** за допомогою **`Keychain Access.app`** застосовуються такі правила:<sup>[[1]](#references)</sup>

- Усі програми можуть шифрувати.
- **Жодна програма** не може експортувати/розшифровувати (без запиту користувачеві).
- Усі програми можуть переглядати перевірку цілісності.
- Жодна програма не може змінювати ACL.
- **partitionID** встановлюється в **`apple`**.

Коли **програма створює запис у зв'язці ключів**, правила дещо відрізняються:<sup>[[1]](#references)</sup>

- Усі програми можуть шифрувати.
- Лише **програма, що створила запис** (або інші явно додані програми) можуть експортувати/розшифровувати (без запиту користувачеві).
- Усі програми можуть переглядати перевірку цілісності.
- Жодна програма не може змінювати ACL.
- **partitionID** встановлюється в **`teamid:[teamID here]`**.

## Доступ до зв'язки ключів

### `security`

```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entry's PartitionID value
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` задає список розділів елемента, а `-k` передає поточний пароль Keychain, потрібний для внесення цієї зміни; прапорець для передавання пароля застарів.<sup>[[4]](#references)</sup> Успішне оновлення не доводить, що під час подальшого читання не з’явиться запит: один спостережуваний вимкнений прототип усе одно показував запит на підтвердження, коли запитував елемент через `Security.framework`. Відповідний ідентифікатор розділу — лише одна частина перевірок ACL і довірених програм, описаних вище, тому перевірте фактичний шлях читання.<sup>[[3]](#references)</sup>

### APIs

> [!TIP]
> **Перелік елементів Keychain і дамп** секретів, що **не викликає запиту**, можна виконати за допомогою інструмента [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> Інші кінцеві точки API можна знайти у вихідному коді [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Перелічіть і отримайте **відомості** про кожен запис Keychain за допомогою **Security Framework** або скористайтеся клієнтським інструментом Apple з відкритим кодом [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Приклади API:<sup>[[1]](#references)</sup>

- API **`SecItemCopyMatching`** надає відомості про кожен запис. Під час його використання можна задати кілька атрибутів:
  - **`kSecReturnData`**: якщо значення `true`, API спробує розшифрувати дані (задайте `false`, щоб уникнути потенційних спливних вікон)
  - **`kSecReturnRef`**: отримати посилання на об’єкт ключа, сертифіката або ідентифікаційних даних; елементи паролів не мають такого об’єктного представлення. Використовуйте `kSecReturnPersistentRef`, щоб ідентифікувати пароль для подальшого цільового запиту.<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`**: отримати метадані записів
  - **`kSecMatchLimit`**: кількість результатів, які потрібно повернути
  - **`kSecClass`**: тип запису Keychain

Отримайте **ACL** кожного запису:<sup>[[1]](#references)</sup>

- За допомогою API **`SecAccessCopyACLList`** можна отримати **ACL елемента Keychain**. Він повертає список ACL (наприклад, `kSecACLAuthorizationExportClear` та інші згадані раніше), де кожен запис містить:<sup>[[1]](#references)[[2]](#references)</sup>
  - Опис
  - **Список довірених програм**. Це може бути:
    - Програма: /Applications/Slack.app
    - Бінарний файл: /usr/libexec/airportd
    - Група: group://AirPort

Експортуйте дані:<sup>[[1]](#references)</sup>

- API **`SecKeychainItemCopyContent`** отримує дані у відкритому вигляді
- API **`SecItemExport`** експортує ключі та сертифікати, але для експорту зашифрованого вмісту може знадобитися задати паролі

А ось **вимоги**, щоб **експортувати секрет без запиту**:<sup>[[1]](#references)</sup>

- Якщо в списку є **одна або більше довірених** програм:
  - Потрібні відповідні **авторизації** (**`Nil`** або наявність у списку дозволених програм в авторизації на доступ до інформації про секрет)
  - Підпис коду має відповідати **PartitionID**
  - Підпис коду має відповідати підпису однієї з **довірених програм** (або програма має бути членом відповідної KeychainAccessGroup)
- Якщо **всі програми довірені**:
  - Потрібні відповідні **авторизації**
  - Підпис коду має відповідати **PartitionID**
    - Якщо **PartitionID відсутній**, це не потрібно

> [!CAUTION]
> Отже, якщо **вказано одну програму**, потрібно **впровадити код у цю програму**.
>
> Якщо в **partitionID** вказано **apple**, можна отримати доступ за допомогою **`osascript`** — так, якщо довіряти всім програмам, у яких у partitionID є apple. Також для цього можна використати **`Python`**.

### Два додаткові атрибути

- **Invisible**: булевий прапорець, що **приховує** запис у програмі Keychain з **UI**<sup>[[1]](#references)</sup>
- **General**: використовується для зберігання **метаданих** (тобто вони НЕ ЗАШИФРОВАНІ)<sup>[[1]](#references)</sup>
  - Microsoft зберігала у відкритому вигляді всі refresh-токени для доступу до конфіденційної кінцевої точки.<sup>[[1]](#references)</sup>

### Data protection keychain: перелік елементів, а потім запит одного елемента

Викликайте `SecItemCopyMatching` із **підписаної програми в контексті входу цільового користувача**, задавши `kSecUseDataProtectionKeychain: true`; не припускайте, що `security dump-keychain` або стандартний запит SecItem виконував пошук у цьому сховищі. Викликач бачить лише ті групи доступу, до яких має авторизований доступ.<sup>[[5]](#references)</sup>

Якщо тестовий код працює всередині іншого процесу, доступ до його data protection keychain визначається entitlements виконуваного файла-хоста. Перевірте фактичні підписані entitlements за допомогою `codesign -d --entitlements - /path/to/Target.app` і перегляньте [macOS code-signing entitlements](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md), щоб дізнатися про пов’язані перевірки.<sup>[[7]](#references)</sup>

Спершу запитайте **лише атрибути** для одного класу елементів. `kSecAttrSynchronizableAny` охоплює збіги як локальних елементів, так і елементів, синхронізованих з iCloud; якщо не вказати цей атрибут, синхронізовані елементи не включатимуться.<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip` запобігає появі інтерфейсу автентифікації під час широкого переліку, але захищені збіги буде пропущено.<sup>[[9]](#references)</sup> За потреби повторіть запит із `kSecClassInternetPassword`.

```swift
import Security
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
print(status)
if status == errSecSuccess, let items = result as? [[String: Any]] {
    for item in items { print(item) }
}
```

Для дозволеного читання секрету створіть **новий**, вузький запит для вибраного елемента (наприклад, клас, сервіс і обліковий запис), задайте `kSecReturnData: true` і `kSecMatchLimit: kSecMatchLimitOne` та очікуйте автентифікацію для конкретного елемента або помилку. **Не** поєднуйте `kSecReturnData` з `kSecMatchLimitAll` для елементів із паролями.<sup>[[10]](#references)</sup> Результат `errSecItemNotFound` також може означати неправильне сховище, фільтр синхронізації або відсутнє право доступу до групи доступу, а не відсутність облікових даних.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0: «Зламування замка macOS Keychain» — Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist — Нова версія викрадача даних MacSync для macOS націлена на криптоентузіастів і розробників](https://securelist.com/macsync-new-version/121383/)
- [4] [Дзеркало сторінки посібника Apple security(1)](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — Про API та реалізації Keychain на Mac](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Форуми розробників Apple — SecItem: основи](https://developer.apple.com/forums/thread/724023)
- [7] [Форуми розробників Apple — SecItem: підводні камені та найкращі практики](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Доступ до елементів Keychain за допомогою Face ID або Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
