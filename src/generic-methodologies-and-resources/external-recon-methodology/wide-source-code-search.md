# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

Мета цієї сторінки - перерахувати **платформи, які дозволяють шукати код** (літерний або regex) у тисячах/мільйонах репозиторіїв на одній або кількох платформах.

Це допомагає в кількох випадках **шукати витоку інформації** або **вразливості**.

- [**SourceGraph**](https://sourcegraph.com/search): Пошук у мільйонах репозиторіїв. Є безкоштовна версія та версія для підприємств (з 15 днями безкоштовно). Підтримує regex.
- [**Github Search**](https://github.com/search): Пошук по Github. Підтримує regex.
- Можливо, також корисно перевірити [**Github Code Search**](https://cs.github.com/).
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Пошук по проектам Gitlab. Підтримує regex.
- [**SearchCode**](https://searchcode.com/): Пошук коду у мільйонах проектів.

> [!WARNING]
> Коли ви шукаєте витоки в репозиторії та запускаєте щось на кшталт `git log -p`, не забувайте, що можуть бути **інші гілки з іншими комітами**, що містять секрети!

{{#include ../../banners/hacktricks-training.md}}
