# Kanıt Asistanı ve Biçimsel Doğrulama Güvenliği

{{#include ../banners/hacktricks-training.md}}

Kanıt asistanları aynı terimi birkaç farklı yoldan çalıştırabilir: kernel indirgemesi, yorumlayıcı, üretilen kod, runtime primitive'leri veya harici bir checker. Bir kanıt, yalnızca güvenilir sonuçlara katkıda bulunmasına izin verilen tüm bileşenler kadar güçlüdür. Lean'de native karar prosedürleri, daha hızlı değerlendirme karşılığında daha büyük bir güvenilir hesaplama tabanı (TCB) gerektirir: derleyici ve native implementasyonlara sahip tanımlar, kanıt bütünlüğü açısından önem kazanır.<sup>[[3]](#references)</sup>

## Mantıksal/native diferansiyel değerlendirme

Çalıştırılabilir implementasyonu mantıksal modelinden farklı olan primitive'lere öncelik verin (örneğin derleyici intrinsic'leri, foreign-function interface'ler, runtime override'ları ve `@[implemented_by]` ile işaretlenmiş tanımlar). **Aynı kapalı terimi** mantıksal ve derlenmiş yollardan diferansiyel olarak değerlendirin ve değer, istisna veya sonlanma konusundaki her türlü uyumsuzluğu bir güvenlik bulgusu olarak ele alın.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Faydalı sınır değeri sınıfları şunlardır:<sup>[[1]](#references)[[4]](#references)</sup>

- `0`, girdi uzunluğu, machine-word sınırı ve `2^63` veya daha büyük değerler çevresindeki indeksler;
- sıfır/tek baytlık aralıklar, `start = end`, `start > end` ve nesnenin çok ötesindeki konumlar;
- boş ve boş olmayan girdiler, çok baytlı dizeler, geçersiz sınırlar ve derlendiğinde kesilebilecek aritmetik işlemler;
- native primitive'in mantıksal modelde bulunmayan sahiplik veya ödünç alma davranışına sahip olduğu heap destekli değerler.

Aşağıdaki sadeleştirilmiş Lean örüntüsü, `String.Pos.Raw.extract` içinde bulunan sorunu gösterir: savunmasız native kod, çok büyük tek baytlık bir aralık için özgün dizeyi döndürürken tanımsal indirgeme boş dizeyi döndürüyordu. Bu anlamsal uyumsuzluk, ilişkili bellek güvenliği kusurundan ayrı olarak giderildi.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>

```lean
def value : String := "non-empty"
def startPos : String.Pos.Raw := ⟨2^63⟩
def endPos : String.Pos.Raw := ⟨2^63 + 1⟩

example : False := by
  have logical : String.Pos.Raw.extract value startPos endPos = "" := rfl
  have native : String.Pos.Raw.extract value startPos endPos = value := by
    native_decide
  exact (by decide) (logical.symm.trans native)
```

Bu örüntü dizelerin ötesine de genellenir: Mantıksal değerlendirme `E = A` olduğunu, güvenilir native değerlendirme ise `E = B` olduğunu kanıtlarsa, geçişlilik `A = B` sonucunu verir. `A` ve `B` gözlemlenebilir biçimde farklı olduğunda bu, `False` sonucunu doğurur; ardından `False.elim` (çelişkiden her önermenin çıkarılabilmesi ilkesi) herhangi bir hedef önermeyi kanıtlayabilir. Kernel'ın hatalı bir indirgeme kuralına sahip olması gerekmez; bütünlük ihlali, compiler destekli bir sonucun bir aksiyom aracılığıyla mantığa girmesi nedeniyle oluşur.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

## Lean'de genişletilmiş TCB'yi denetleme

Güvenilmeyen bir kanıtı doğrulamak için yalnızca editör onay işaretlerine veya başarılı bir derlemeye güvenmeyin. Güvenlik açısından kritik her teoremin tam bağımlılık kapanımını `#print axioms` ile inceleyin; Lean'ın doğrulama kılavuzu `_native` adlarının native değerlendirme bağımlılıklarını, `sorryAx`'ın tamamlanmamış bir kanıtı ve diğer standart dışı adların özel aksiyomları belirttiğini açıklar.<sup>[[3]](#references)</sup>

```lean
#print axioms targetTheorem
```

Örneğin, aşağıdakine benzeyen üretilmiş bir bağımlılık, derlenmiş yürütmenin yalnızca kernel indirgemesinden türetilmiş bir kanıt yerine varsayılan bir sonuca katkıda bulunduğu anlamına gelir:<sup>[[1]](#references)[[4]](#references)</sup>

```text
targetTheorem._native.native_decide.ax_1_1
```

Kaynak incelemesi sırasında yerel karar prosedürlerini ve açık kaçış yollarını arayın; ancak bağımlılıklar dolaylı veya oluşturulmuş olabileceğinden sonucu `#print axioms` ile doğrulayın:<sup>[[3]](#references)</sup>

```bash
rg -n 'native_decide|decide\s+\+native|bv_decide|sorry|axiom' .
```

Finding’i değerlendirirken katmanları birbirinden ayırın:<sup>[[3]](#references)</sup>

1. **İfade bütünlüğü:** Notasyonun, type-class instance’larının, import’ların ve tanımların amaçlanan iddiayı ifade ettiğini doğrulayın.
2. **İspat bağımlılıkları:** Beklenmedik aksiyomları, özellikle üretilen native-evaluation aksiyomlarını reddedin veya açıkça inceleyin.
3. **Kernel yeniden oynatımı:** `lake build` komutundan sonra, `.olean` dosyalarındaki bildirimleri yeniden oynatmak için `lean4checker --fresh <Module>` çalıştırın.
4. **Kötü niyetli ispat doğrulaması:** Güvenilmeyen kodu sandbox’ta derleyin ve ifadeyi güvenilir bir challenge ile karşılaştıran harici checker’larla `lake comparator` kullanın.

`lean4checker` savunmaya derinlik katar ancak `.olean` dosyalarının yapısal doğruluğuna güvenir; ayrıca güvenilmeyen Lean meta-code çalıştırmak, denetleme ortamının kendisini tehlikeye atabilir. Yüksek riskli ispatlarda comparator, ispatı sandbox dışına aktarır, ifadeyi güvenilir challenge ile karşılaştırır ve bağımsız olarak uygulanmış checker’lar üzerinden yeniden oynatabilir; uygulama çeşitliliği, tek bir compiler, runtime veya kernel kusurunun aynı yanlış sonucu her yerde doğrulaması ihtimalini azaltır.<sup>[[3]](#references)</sup>

## References

- [1] [`String.Pos.Raw.extract` model/runtime uyumsuzluğu ve use-after-free - Lean issue #14684](https://github.com/leanprover/lean4/issues/14684)
- [2] [`String.Pos.Raw.extract` model/runtime uyumsuzluğunun düzeltilmesi - Lean PR #14717](https://github.com/leanprover/lean4/pull/14717)
- [3] [Lean Dil Referansı: Bir Lean İspatını Doğrulama](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [4] [Kenar Boşluğuna Sığan Bir Fermat’nın Son Teoremi “İspatı”](https://blog.trailofbits.com/2026/09/09/a-proof-of-fermats-last-theorem-that-fits-the-margin/)
{{#include ../banners/hacktricks-training.md}}
