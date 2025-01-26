# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

Celem tej strony jest enumeracja **platform, które pozwalają na wyszukiwanie kodu** (literalnego lub regex) w tysiącach/milionach repozytoriów na jednej lub więcej platformach.

Pomaga to w kilku sytuacjach w **wyszukiwaniu wycieków informacji** lub wzorców **vulnerabilities**.

- [**Sourcebot**](https://www.sourcebot.dev/): Narzędzie do wyszukiwania kodu open source. Indeksuj i wyszukuj w tysiącach swoich repozytoriów za pomocą nowoczesnego interfejsu webowego.
- [**SourceGraph**](https://sourcegraph.com/search): Wyszukiwanie w milionach repozytoriów. Istnieje wersja darmowa i wersja enterprise (z 15 dniami za darmo). Obsługuje regexy.
- [**Github Search**](https://github.com/search): Wyszukiwanie w Githubie. Obsługuje regexy.
- Może warto również sprawdzić [**Github Code Search**](https://cs.github.com/).
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Wyszukiwanie w projektach Gitlab. Obsługuje regexy.
- [**SearchCode**](https://searchcode.com/): Wyszukiwanie kodu w milionach projektów.

> [!WARNING]
> Kiedy szukasz wycieków w repozytorium i uruchamiasz coś takiego jak `git log -p`, nie zapomnij, że mogą istnieć **inne gałęzie z innymi commitami** zawierającymi sekrety!

{{#include ../../banners/hacktricks-training.md}}
