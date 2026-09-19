# AGENTS.md

Настанови для майбутніх agents, які працюють у цьому repository.

## Контекст repository

Це основний mdBook repository HackTricks. Пов’язана cloud book розташована за адресою:

`/Users/carlospolop/git/hacktricks-cloud`

Зміни до спільної theme/search behavior часто потрібно застосовувати в обох repositories.

## Контракт завантаження Search Index

Користувацький search UI розташований у:

`theme/ht_searcher.js`

Також може існувати згенерована копія за адресою:

`book/theme/ht_searcher.js`

Якщо production розгортає вже зібрану директорію `book/`, оновіть обидві копії або перебудуйте
book перед deployment.

Політика джерел search index є важливою та чутливою до витрат:

- На public hosts завантажуйте кожен language-specific і fallback candidate лише з
`HackTricks-wiki/hacktricks-searchindex`. Ніколи не використовуйте fallback на mdBook output того самого origin;
  розміщення великого index на `hacktricks.wiki` у production є дорогим.
- На localhost, `.local`/`.internal` hosts, loopback, RFC1918, carrier-grade NAT, link-local або
  private IPv6 addresses завантажуйте лише same-origin mdBook output, щоб local/container deployments
  залишалися self-contained.

Для цього repo очікуваним local fallback є:

`/searchindex.js`

На private hosts cloud index недоступний із цього origin і не повинен ініціювати remote download. На public hosts він
має використовувати remote `searchindex-cloud-<lang>.js.gz` files.

## Публікація Search Index

Workflows, які публікують encrypted compressed search indexes до
`HackTricks-wiki/hacktricks-searchindex`:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Згенерований source file: `book/searchindex.js`. Назви опублікованих remote artifacts:

- `searchindex-v2-en.json.gz` (preferred compact index)
- `searchindex-v2-<lang>.json.gz` (preferred compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Browser loader надає перевагу compact v2 artifact і зберігає `.js.gz` artifact як legacy
fallback. Обидва є XOR-encrypted gzip payloads із використанням key, визначеного в `theme/ht_searcher.js`.

Loader має залишатися lazy: звичайна навігація сторінками не повинна створювати search worker або завантажувати
index, доки відвідувач не відкриє або не використає search. Remote compressed responses зберігаються в Cache
Storage протягом 24 годин для кожного origin, щоб наступні сторінки могли повторно їх використовувати. Збережіть stale-cache
fallback, коли оновлення expired entry завершується помилкою.

## Build And Validation

Поширені local checks:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Якщо `mdbook build` завершується помилкою, перевірте:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Нотатки щодо редагування

- Для пошуку надавайте перевагу `rg`.
- Не включайте згенерований `book/` output до commits, якщо це явно не запитано. Виправлення search loader
є винятком, коли вже зібрані pages потрібно негайно виправити.
- Якщо змінюєте shared theme behavior, порівняйте та оновіть відповідний file у
`/Users/carlospolop/git/hacktricks-cloud`.
- Не скасовуйте unrelated local changes.
