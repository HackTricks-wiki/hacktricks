# macOS Authorizations DB і Authd

{{#include ../../../banners/hacktricks-training.md}}

## База даних авторизації

Security framework's Authorization Services дають змогу privileged helpers та іншим компонентам оцінювати іменовані права авторизації. У поточних версіях macOS багато таких правил зберігаються в `/var/db/auth.db` і оцінюються `authd`; цей файл і його SQLite schema є деталями реалізації та можуть змінюватися між випусками.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Системні default-налаштування історично завантажувалися з `/System/Library/Security/authorization.plist`, а installers або privileged services можуть додавати іменовані права. Надавайте перевагу підтримуваному інтерфейсу `security authorizationdb read|write|remove`, а не прямому редагуванню бази даних.<sup>[[3]](#references)</sup>

Таблиця `rules`, яку спостерігали в документованій збірці, містить такі колонки. Розглядайте це як forensic map, а не стабільну public schema:

- **id**: Унікальний ідентифікатор для кожного правила, який автоматично збільшується та використовується як primary key.
- **name**: Унікальне ім'я правила, що використовується для його ідентифікації та посилання на нього в authorization system.
- **type**: Визначає тип правила; обмежений значеннями 1 або 2 для визначення його authorization logic.
- **class**: Відносить правило до певного класу; має бути додатним integer.
- До поширених класів правил належать `allow`, `deny`, `user`, `rule` та `evaluate-mechanisms`. Mechanisms можуть бути вбудованими або plug-ins Security Agent у `/System/Library/CoreServices/SecurityAgentPlugins/` чи `/Library/Security/SecurityAgentPlugins/`.<sup>[[2]](#references)</sup>
- **group**: Вказує user group, пов'язану з правилом для group-based authorization.
- **kofn**: Представляє параметр "k-of-n", який визначає, скільки subrules із загальної кількості мають бути виконані.
- **timeout**: Визначає тривалість у секундах, після якої authorization, надана правилом, спливає.
- **flags**: Містить різні flags, що змінюють поведінку та характеристики правила.
- **tries**: Обмежує кількість дозволених authorization attempts для підвищення security.
- **version**: Відстежує версію правила для контролю версій та оновлень.
- **created**: Записує timestamp створення правила для auditing.
- **modified**: Зберігає timestamp останньої зміни правила.
- **hash**: Містить hash-значення правила для забезпечення його цілісності та виявлення tampering.
- **identifier**: Надає унікальний string identifier, наприклад UUID, для зовнішніх посилань на правило.
- **requirement**: Містить serialized data, що визначає конкретні authorization requirements і mechanisms правила.
- **comment**: Надає зрозумілий людині опис або comment про правило для документації та ясності.

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
Наведене нижче декодоване правило ілюструє `authenticate-admin-nonshared` у задокументованій версії macOS:<sup>[[1]](#references)</sup>
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

`authd` — це XPC-сервіс, який обробляє запити Authorization Services. У поточних збірках macOS його bundle можна перевірити за шляхом `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc`; цей шлях є деталлю реалізації та може відрізнятися в різних релізах. У старіших релізах записи велися у `/var/log/authd.log`; поточні релізи переважно використовують unified logging system, яку можна запитувати за допомогою `log show`/`log stream`, використовуючи предикат процесу `authd`.<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

Інструмент `security` надає кілька операцій Authorization Services. Історичний приклад викликає `AuthorizationExecuteWithPrivileges` за допомогою `security execute-with-privileges /bin/ls`. Apple оголосила цей API застарілим у macOS 10.7; сучасні privileged helpers мають використовувати helper, керований launchd, і XPC authorization.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

У релізах, які все ще це підтримують, використовується `/usr/libexec/security_authtrampoline`, і перед запуском команди від імені root відображається запит авторизації:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Огляд права авторизації macOS](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Посібник Apple з програмування Authorization Services (архів)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [Сторінка посібника macOS для `security(1)`](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Посібник з програмування Daemons and Services: створення завдань launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Проєкт Security з відкритим кодом Apple - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)
{{#include ../../../banners/hacktricks-training.md}}
