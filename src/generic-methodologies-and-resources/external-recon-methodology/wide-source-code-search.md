# Búsqueda Amplia de Código Fuente

{{#include ../../banners/hacktricks-training.md}}

El objetivo de esta página es enumerar **plataformas que permiten buscar código** (literal o regex) en miles/millones de repos en una o más plataformas.

Esto ayuda en varias ocasiones a **buscar información filtrada** o patrones de **vulnerabilidades**.

- [**Sourcebot**](https://www.sourcebot.dev/): Herramienta de búsqueda de código de código abierto. Indexa y busca en miles de tus repos a través de una interfaz web moderna.
- [**SourceGraph**](https://sourcegraph.com/search): Busca en millones de repos. Hay una versión gratuita y una versión empresarial (con 15 días gratis). Soporta regexes.
- [**Github Search**](https://github.com/search): Busca en Github. Soporta regexes.
- Quizás también sea útil revisar [**Github Code Search**](https://cs.github.com/).
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Busca en proyectos de Gitlab. Soporta regexes.
- [**SearchCode**](https://searchcode.com/): Busca código en millones de proyectos.

> [!WARNING]
> Cuando busques filtraciones en un repo y ejecutes algo como `git log -p`, ¡no olvides que puede haber **otras ramas con otros commits** que contengan secretos!

{{#include ../../banners/hacktricks-training.md}}
