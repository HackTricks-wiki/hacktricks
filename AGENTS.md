# AGENTS.md

Настанови для майбутніх agents, які працюють у цьому repository.

## Контекст repository

Це основний mdBook repository HackTricks. Пов’язана cloud book розташована за адресою:

`/Users/carlospolop/git/hacktricks-cloud`

Зміни до спільної поведінки theme/search часто потрібно застосовувати в обох repositories.

## Контракт завантаження search index

Користувацький search UI розташований у:

`theme/ht_searcher.js`

Також може існувати згенерована копія:

`book/theme/ht_searcher.js`

Якщо production розгортає вже зібраний каталог `book/`, оновіть обидві копії або перебудуйте
book перед deployment.

Порядок завантаження search index є важливим і чутливим до витрат:

1. Завантажуйте кожен language-specific і fallback search index із GitHub repository:
`HackTricks-wiki/hacktricks-searchindex`
2. Лише якщо всі hosted on GitHub кандидати завершилися помилкою, використовуйте fallback до mdBook output із того самого origin.

Не розміщуйте локальний `/searchindex.js` fallback перед будь-яким hosted on GitHub fallback, наприклад
`searchindex-en.js.gz`. Обслуговування `searchindex.js` із `hacktricks.wiki` у production є дорогим.

Для цього repo очікуваним локальним fallback є:

`/searchindex.js`

Cloud index не повинен використовувати локальний fallback із цього origin. Він має покладатися на віддалені
файли `searchindex-cloud-<lang>.js.gz`.

## Публікація search index

Workflows, які публікують зашифровані стиснені search indexes у
`HackTricks-wiki/hacktricks-searchindex`, це:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Згенерований source file:

`book/searchindex.js`. Опубліковані назви remote artifacts:

- `searchindex-v2-en.json.gz` (preferred compact index)
- `searchindex-v2-<lang>.json.gz` (preferred compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Browser loader надає перевагу compact v2 artifact і зберігає `.js.gz` artifact як legacy
fallback. Обидва є XOR-encrypted gzip payloads і використовують key, визначений у
`theme/ht_searcher.js`.

Loader має залишатися lazy: звичайна навігація сторінками не повинна створювати search worker або
завантажувати index, доки visitor не відкриє або не використає search. Remote compressed responses
зберігаються в Cache Storage протягом 24 годин для кожного origin, щоб наступні сторінки могли
повторно їх використовувати. Зберігайте stale-cache fallback, якщо оновлення простроченого entry
завершується помилкою.

## Build And Validation

Поширені локальні перевірки:

- `node --check theme/ht_searcher.js`
- `mdbook build`

Якщо `mdbook build` завершується помилкою, перевірте:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- Надавайте перевагу `rg` для пошуку.
- Не додавайте згенерований output `book/` до commits, якщо це явно не запитано. Виправлення search loader
є винятком, коли вже зібрані pages потрібно негайно виправити.
- Якщо змінюєте спільну поведінку theme, порівняйте й оновіть відповідний file у
`/Users/carlospolop/git/hacktricks-cloud`.
- Не скасовуйте unrelated local changes.
