# Geniş Kaynak Kodu Arama

{{#include ../../banners/hacktricks-training.md}}

Bu sayfanın amacı, bir veya daha fazla platformda binlerce/milyonlarca repo içinde **kod aramaya izin veren platformları** listelemektir (literal veya regex).

Bu, **sızdırılmış bilgileri** veya **zafiyet** kalıplarını aramak için birkaç durumda yardımcı olur.

- [**Sourcebot**](https://www.sourcebot.dev/): Açık kaynak kod arama aracı. Modern bir web arayüzü aracılığıyla binlerce reposu arasında indeksleme ve arama yapar.
- [**SourceGraph**](https://sourcegraph.com/search): Milyonlarca repo içinde arama yapar. Ücretsiz bir versiyonu ve 15 gün ücretsiz olan bir kurumsal versiyonu vardır. Regex destekler.
- [**Github Search**](https://github.com/search): Github üzerinde arama yapar. Regex destekler.
- Belki [**Github Code Search**](https://cs.github.com/) kontrol etmek de faydalı olabilir.
- [**Gitlab Advanced Search**](https://docs.gitlab.com/ee/user/search/advanced_search.html): Gitlab projeleri arasında arama yapar. Regex destekler.
- [**SearchCode**](https://searchcode.com/): Milyonlarca projede kod arar.

> [!WARNING]
> Bir repoda sızıntılar ararken ve `git log -p` gibi bir şey çalıştırırken, **gizli bilgileri içeren diğer commit'lere sahip diğer dallar** olabileceğini unutmayın!

{{#include ../../banners/hacktricks-training.md}}
