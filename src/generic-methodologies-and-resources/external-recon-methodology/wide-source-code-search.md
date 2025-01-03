# Wide Source Code Search

{{#include ../../banners/hacktricks-training.md}}

O objetivo desta página é enumerar **plataformas que permitem buscar por código** (literal ou regex) em milhares/milhões de repositórios em uma ou mais plataformas.

Isso ajuda em várias ocasiões a **procurar por informações vazadas** ou por padrões de **vulnerabilidades**.

- [**SourceGraph**](https://sourcegraph.com/search): Pesquisar em milhões de repositórios. Há uma versão gratuita e uma versão empresarial (com 15 dias gratuitos). Suporta regexes.
- [**Github Search**](https://github.com/search): Pesquisar no Github. Suporta regexes.
- Talvez também seja útil verificar [**Github Code Search**](https://cs.github.com/).
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Pesquisar em projetos do Gitlab. Suporta regexes.
- [**SearchCode**](https://searchcode.com/): Pesquisar código em milhões de projetos.

> [!WARNING]
> Quando você procura por vazamentos em um repositório e executa algo como `git log -p`, não se esqueça de que pode haver **outras branches com outros commits** contendo segredos!

{{#include ../../banners/hacktricks-training.md}}
