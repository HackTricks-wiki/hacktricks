# БД авторизацій macOS та Authd

{{#include ../../../banners/hacktricks-training.md}}

## **БД авторизацій**

База даних, розташована в `/var/db/auth.db`, використовується для зберігання дозволів на виконання чутливих операцій. Ці операції повністю виконуються в **user space** і зазвичай використовуються **XPC services**, яким потрібно перевірити, **чи авторизований клієнт, що викликає сервіс**, на виконання певної дії, перевіряючи цю базу даних.

Спочатку ця база даних створюється на основі вмісту `/System/Library/Security/authorization.plist`. Потім деякі сервіси можуть додавати або змінювати цю базу даних, додаючи до неї інші дозволи.

Правила зберігаються в таблиці `rules` усередині бази даних і містять такі стовпці:

- **id**: Унікальний ідентифікатор кожного правила, який автоматично збільшується та використовується як первинний ключ.
- **name**: Унікальне ім’я правила, що використовується для його ідентифікації та посилання на нього в системі авторизації.
- **type**: Визначає тип правила; допустимими є значення 1 або 2, які визначають його логіку авторизації.
- **class**: Відносить правило до певного класу, який має бути додатним цілим числом.
- "allow" для дозволу, "deny" для заборони, "user", якщо властивість group вказує на групу, членство в якій дозволяє доступ, "rule" вказує на масив із правилом, яке потрібно виконати, "evaluate-mechanisms" супроводжується масивом `mechanisms`, елементами якого є або вбудовані механізми, або назва bundle всередині `/System/Library/CoreServices/SecurityAgentPlugins/` чи `/Library/Security//SecurityAgentPlugins`
- **group**: Вказує групу користувачів, пов’язану з правилом для авторизації на основі групи.
- **kofn**: Представляє параметр "k-of-n", який визначає, скільки підправил із загальної кількості має бути виконано.
- **timeout**: Визначає тривалість у секундах, після якої авторизація, надана правилом, втрачає чинність.
- **flags**: Містить різні прапорці, що змінюють поведінку та характеристики правила.
- **tries**: Обмежує кількість дозволених спроб авторизації для підвищення безпеки.
- **version**: Відстежує версію правила для контролю версій і оновлень.
- **created**: Зберігає часову мітку створення правила для цілей аудиту.
- **modified**: Зберігає часову мітку останньої зміни правила.
- **hash**: Містить хеш-значення правила для забезпечення його цілісності та виявлення підробки.
- **identifier**: Надає унікальний рядковий ідентифікатор, наприклад UUID, для зовнішніх посилань на правило.
- **requirement**: Містить серіалізовані дані, що визначають конкретні вимоги та механізми авторизації правила.
- **comment**: Містить зрозумілий для людини опис або коментар до правила для документування та ясності.

### Приклад
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
Крім того, у [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/) можна побачити значення `authenticate-admin-nonshared`:<sup>[[1]](#references)</sup>
```json
{
"allow-root": "false",
"authenticate-user": "true",
"class": "user",
"comment": "Authenticate as an administrator.",
"group": "admin",
"session-owner": "false",
"shared": "false",
"timeout": "30",
"tries": "10000",
"version": "1"
}
```
## Authd

Це daemon, який отримує запити на авторизацію клієнтів для виконання чутливих дій. Він працює як XPC service, визначений у теці `XPCServices/`, і записує свої логи до `/var/log/authd.log`.

Крім того, за допомогою security tool можна тестувати багато API з `Security.framework`. Наприклад, запуск `AuthorizationExecuteWithPrivileges`: `security execute-with-privileges /bin/ls`

Це виконає fork і exec `/usr/libexec/security_authtrampoline /bin/ls` від імені root, після чого буде запитано дозвіл у prompt для виконання ls від імені root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Overview of the macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)


{{#include ../../../banners/hacktricks-training.md}}
