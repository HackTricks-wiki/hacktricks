# Large Recherche de Code Source

{{#include ../../banners/hacktricks-training.md}}

L'objectif de cette page est d'énumérer **les plateformes qui permettent de rechercher du code** (littéral ou regex) à travers des milliers/millions de dépôts sur une ou plusieurs plateformes.

Cela aide dans plusieurs occasions à **rechercher des informations divulguées** ou des **modèles de vulnérabilités**.

- [**Sourcebot**](https://www.sourcebot.dev/): Outil de recherche de code open source. Indexez et recherchez à travers des milliers de vos dépôts via une interface web moderne.
- [**SourceGraph**](https://sourcegraph.com/search): Recherchez dans des millions de dépôts. Il existe une version gratuite et une version entreprise (avec 15 jours gratuits). Il prend en charge les regex.
- [**Github Search**](https://github.com/search): Recherchez sur Github. Il prend en charge les regex.
- Peut-être qu'il est également utile de vérifier [**Github Code Search**](https://cs.github.com/).
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Recherchez à travers les projets Gitlab. Prend en charge les regex.
- [**SearchCode**](https://searchcode.com/): Recherchez du code dans des millions de projets.

> [!WARNING]
> Lorsque vous recherchez des fuites dans un dépôt et exécutez quelque chose comme `git log -p`, n'oubliez pas qu'il pourrait y avoir **d'autres branches avec d'autres commits** contenant des secrets !

{{#include ../../banners/hacktricks-training.md}}
