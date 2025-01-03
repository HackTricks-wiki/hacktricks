# Búsqueda Amplia de Código Fuente

{{#include ../../banners/hacktricks-training.md}}

El objetivo de esta página es enumerar **plataformas que permiten buscar código** (literal o regex) en miles/millones de repos en una o más plataformas.

Esto ayuda en varias ocasiones a **buscar información filtrada** o patrones de **vulnerabilidades**.

- [**SourceGraph**](https://sourcegraph.com/search): Busca en millones de repos. Hay una versión gratuita y una versión empresarial (con 15 días gratis). Soporta regex.
- [**Github Search**](https://github.com/search): Busca en Github. Soporta regex.
- Tal vez también sea útil revisar [**Github Code Search**](https://cs.github.com/).
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Busca en proyectos de Gitlab. Soporta regex.
- [**SearchCode**](https://searchcode.com/): Busca código en millones de proyectos.

> [!WARNING]
> Cuando busques filtraciones en un repo y ejecutes algo como `git log -p`, ¡no olvides que puede haber **otras ramas con otros commits** que contengan secretos!

{{#include ../../banners/hacktricks-training.md}}
