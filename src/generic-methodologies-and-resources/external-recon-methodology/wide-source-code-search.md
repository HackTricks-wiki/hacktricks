# Weite Quellcode-Suche

{{#include ../../banners/hacktricks-training.md}}

Das Ziel dieser Seite ist es, **Plattformen aufzulisten, die das Suchen nach Code** (literal oder regex) in Tausenden/Millionen von Repos auf einer oder mehreren Plattformen ermöglichen.

Dies hilft in mehreren Fällen, **nach geleakten Informationen** oder nach **Muster von Schwachstellen** zu suchen.

- [**SourceGraph**](https://sourcegraph.com/search): Suchen in Millionen von Repos. Es gibt eine kostenlose Version und eine Unternehmensversion (mit 15 Tagen kostenlos). Es unterstützt Regex.
- [**Github Search**](https://github.com/search): Suchen auf Github. Es unterstützt Regex.
- Vielleicht ist es auch nützlich, [**Github Code Search**](https://cs.github.com/) zu überprüfen.
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Suchen in Gitlab-Projekten. Unterstützt Regex.
- [**SearchCode**](https://searchcode.com/): Suchen nach Code in Millionen von Projekten.

> [!WARNING]
> Wenn Sie nach Leaks in einem Repo suchen und etwas wie `git log -p` ausführen, vergessen Sie nicht, dass es **andere Branches mit anderen Commits** geben könnte, die Geheimnisse enthalten!

{{#include ../../banners/hacktricks-training.md}}
