# GitHub Issues і файли репозиторію як канал C2

{{#include ../banners/hacktricks-training.md}}

Приватний репозиторій може розділяти **стан сесії** та **передавання payload**: issues зберігають дані про кожен хост і стан його handshake, а файли репозиторію передають зашифровані дані в обох напрямках. Це більше, ніж просте опитування тіла issue на наявність команд. У спостереженій реалізації для доступу до обох API використовується персональний токен доступу GitHub (PAT).<sup>[[1]](#references)</sup> Для fine-grained PAT створення або оновлення issues потребує дозволу Issues write, а завантаження файлів — дозволу Contents write. Натомість для classic PAT потрібен scope `repo`. Будь-хто, хто отримає токен із достатніми правами, зможе отримати доступ до того самого каналу.<sup>[[2]](#references)[[3]](#references)</sup>

## Handshake через issue і файл

В одному зі спостережених сценаріїв використовується короткий шістнадцятковий ID хоста та така машина станів. Точний діапазон ID, рядки й префікси є маркерами протоколу, а не вимогами GitHub API.<sup>[[1]](#references)</sup>

1. Під час запуску перевірте відкриті й закриті issues за допомогою `GET /repos/{owner}/{repo}/issues?state=open` (і `state=closed`), щоб знайти стан попередньої сесії. Створіть відкритий issue із заголовком `1[ID]` і тілом `hel`, виконавши `POST /repos/{owner}/{repo}/issues`.
2. Прочитайте файл репозиторію, ім’я якого починається з `2[ID]`; у ньому міститься відкритий ключ RSA сервера. Згенеруйте новий 16-байтовий ключ сесії, зашифруйте його за допомогою RSA й завантажте результат у файл із префіксом `1[ID]`.
3. Отримайте наступний IV, виконавши XOR між вбудованим IV і цим ключем сесії. Для кожного файла, яким обмінюються, використовуйте випадковий 16-байтовий ключ із його імені, щоб зашифрувати або розшифрувати вміст за допомогою AES. Префікс `2` позначає дані від сервера до хоста, а префікс `1` — дані від хоста до сервера. Отже, ім’я файла містить дані для маршрутизації та ключовий матеріал для окремого файла, а issue зберігає стан.
4. Прочитайте наступний файл із префіксом `2` і переконайтеся, що його розшифрований вміст дорівнює `hel`. Завантажте зашифровану інформацію про хост, а потім змініть тіло issue на `hey` за допомогою `PATCH /repos/{owner}/{repo}/issues/{issue_number}`. Лише після цього починайте опитування команд.

Contents API GitHub дає змогу прочитати файл через `GET /repos/{owner}/{repo}/contents/{path}` і створити або замінити його через `PUT` за цим шляхом. Для файлів розміром до 1 MB відповідь JSON за замовчуванням містить вміст у форматі Base64; для отримання вмісту файлів розміром від 1 до 100 MB потрібен raw media type. Тіло запиту на завантаження має містити повідомлення коміту й вміст файла, закодований у Base64; для заміни наявного файла також потрібен поточний blob SHA. Ці деталі API не залежать від описаного вище протоколу шифрування.<sup>[[2]](#references)[[3]](#references)</sup>

У тестовому репозиторії, на використання якого є дозвіл, керування issues можна перевірити через REST API (підставте тестовий репозиторій і тестовий PAT). Не додавайте чинний токен до URL, тіла issue чи файла, що комітиться.<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

Механізм **не** потребує назви issue, маркерів `hel`/`hey` чи конкретних варіантів шифрування, показаних тут; вони лише ідентифікують одну реалізацію. Ідея, яку можна повторно використовувати, — відокремити змінюваний стан хоста від двонапрямлених зашифрованих об’єктів і прив’язати обидва до ID хоста.<sup>[[1]](#references)</sup> Інший спосіб передавання через GitHub issue описано в [нотатках щодо користувацького listener AdaptixC2](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema). Запасний варіант через коментар до issue, який змінює облікові дані репозиторію замість передавання стану сеансу, описано в розділі [Вебсервіси та dead-drop-резолвери](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers).

## References

- [1] [Kaspersky Securelist – Операція FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [GitHub Docs – Кінцеві точки REST API для issues](https://docs.github.com/en/rest/issues/issues)
- [3] [GitHub Docs – Кінцеві точки REST API для вмісту репозиторію](https://docs.github.com/en/rest/repos/contents)
