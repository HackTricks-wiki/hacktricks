# AGENTS.md

Рекомендації для майбутніх агентів, які працюють у цьому репозиторії.

## Контекст репозиторію

Це основний репозиторій HackTricks mdBook. Пов'язана cloud-книга знаходиться за адресою:

`/Users/carlospolop/git/hacktricks-cloud`

Зміни до спільної поведінки theme/search часто потрібно застосовувати в обох репозиторіях.

## Контракт завантаження пошукового індексу

Користувацький search UI знаходиться у:

`theme/ht_searcher.js`

Також може існувати згенерована копія:

`book/theme/ht_searcher.js`

Якщо production розгортає вже зібраний каталог `book/`, оновіть обидві копії або перебудуйте
книгу перед розгортанням.

Політика джерела search index важлива та чутлива до витрат:

- На public hosts завантажуйте всі language-specific і fallback-кандидати лише з
`HackTricks-wiki/hacktricks-searchindex`. Ніколи не використовуйте mdBook output того самого origin як fallback;
  розміщення великого індексу на `hacktricks.wiki` у production є дорогим.
- На localhost, `.local`/`.internal` hosts, loopback, RFC1918, carrier-grade NAT, link-local або
  private IPv6 addresses завантажуйте лише mdBook output того самого origin, щоб local/container deployments
  залишалися self-contained. Для non-English page спочатку спробуйте language-prefixed local path
  (наприклад `/es/searchindex.js`), а root English index використовуйте лише як fallback.

Для цього репозиторію очікуваним local fallback є:

`/searchindex.js`

На private hosts cloud index недоступний із цього origin і не повинен ініціювати remote
download. На public hosts слід використовувати remote `searchindex-cloud-<lang>.js.gz` files.

## Публікація пошукового індексу

Workflows, які публікують encrypted compressed search indexes у
`HackTricks-wiki/hacktricks-searchindex`, такі:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Згенерований source file:

`book/searchindex.js`

Назви опублікованих remote artifacts:

- `searchindex-v2-en.json.gz` (preferred compact index)
- `searchindex-v2-<lang>.json.gz` (preferred compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Browser loader надає перевагу compact v2 artifact і зберігає `.js.gz` artifact як legacy
fallback. Обидва є XOR-encrypted gzip payloads із ключем, визначеним у `theme/ht_searcher.js`.

Loader має залишатися lazy: звичайна навігація сторінками не повинна створювати search worker або завантажувати index,
доки відвідувач не відкриє або не використає search. Remote compressed responses зберігаються в Cache
Storage протягом 24 годин для кожного origin, щоб наступні сторінки могли повторно їх використовувати. Збережіть stale-cache
fallback, коли оновлення expired entry не вдається.

## Збірка та перевірка

Поширені local checks:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Якщо `mdbook build` завершується з помилкою, перевірте:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Примітки щодо редагування

- Для пошуку перевагу надавайте `rg`.
- Не включайте згенерований `book/` output у commits, якщо це явно не requested. Винятком є виправлення
  search loader, коли вже зібрані сторінки потрібно негайно виправити.
- Якщо змінюєте shared theme behavior, порівняйте та оновіть відповідний файл у
  `/Users/carlospolop/git/hacktricks-cloud`.
- Не скасовуйте unrelated local changes.
