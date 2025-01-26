# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

Мета цієї сторінки - перерахувати **платформи, які дозволяють шукати код** (літерний або regex) у тисячах/мільйонах репозиторіїв на одній або кількох платформах.

Це допомагає в кількох випадках **шукати витоку інформації** або **вразливості**.

- [**Sourcebot**](https://www.sourcebot.dev/): Інструмент для пошуку коду з відкритим вихідним кодом. Індексуйте та шукайте у тисячах ваших репозиторіїв через сучасний веб-інтерфейс.
- [**SourceGraph**](https://sourcegraph.com/search): Пошук у мільйонах репозиторіїв. Є безкоштовна версія та версія для підприємств (з 15 днями безкоштовно). Підтримує regex.
- [**Github Search**](https://github.com/search): Пошук на Github. Підтримує regex.
- Можливо, також корисно перевірити [**Github Code Search**](https://cs.github.com/).
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Пошук у проектах Gitlab. Підтримує regex.
- [**SearchCode**](https://searchcode.com/): Пошук коду у мільйонах проектів.

> [!WARNING]
> Коли ви шукаєте витоки в репозиторії та запускаєте щось на зразок `git log -p`, не забувайте, що можуть бути **інші гілки з іншими комітами**, що містять секрети!

{{#include ../../banners/hacktricks-training.md}}
