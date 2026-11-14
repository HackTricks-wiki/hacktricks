# Node.js/V8 Önbelleğe Alınmış Bytecode'un Statik Deobfuscation'ı

{{#include ../../banners/hacktricks-training.md}}

V8 cached data, JavaScript source veya geleneksel bir native executable değil, **sürüme bağlı ve kayıplı bir temsildir**. Bu nedenle kullanışlı bir statik iş akışı şöyledir: dış paketlemeyi kaldırın, cache'i eşleşen V8 build'iyle disassemble edin, ara bir pseudocode modeline dönüştürün ve örneği çalıştırmadan bağımlılıkları dikkate alan dönüşümler uygulayın. [View8](https://github.com/suleram/View8) ve [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator), `javascript-obfuscator` ile korunan Node.js payload'ları için bu yaklaşımı uygular.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Cache'i edinme ve disassemble etme

Her `.jsc` dosyasının aynı wrapper'a sahip olduğunu varsaymak yerine önce preload/launcher'ı inceleyin. Örneğin, `node.exe -r preflight.js app.jsc` gibi bir launcher, ana modülden önce `preflight.js` dosyasını çalıştırır; analiz edilen ailede preload, bir Brotli katmanını kaldırıyordu. Unpack işleminden sonra, paketlenmiş runtime'dan tam Node.js/V8 neslini belirleyin. Bir V8 sürümüyle üretilen cache başka bir sürüm tarafından reddedilebilir veya yanlış decode edilebilir. Bu nedenle tam olarak o V8 tag'i için bir `v8dasm` derleyin veya edinin ve gerekli View8 ile string-printing patch'lerini uygulayın.<sup>[[1]](#references)[[2]](#references)</sup>

Toolkit'in çalıştırma gerektirmeyen iş akışı şöyledir:<sup>[[2]](#references)</sup>

```bash
brotli -d app.jsc -o app.decompressed.jsc
/path/to/matching-v8dasm app.decompressed.jsc > app.jsc.disasm.txt
mkdir -p decompiled deobfuscated
python3 View8/view8.py --input_format disassembled \
  --inp app.jsc.disasm.txt --normalize \
  --out decompiled/app.dec.txt \
  --export_format decompiled serialized
python3 deobf_all.py --inp decompiled/app.dec.pkl \
  --out deobfuscated/app.deobf.txt \
  --export_format decompiled serialized
```

`--normalize`, oluşturulan fonksiyonlara çalıştırmalar arasında kararlı tanımlayıcılar verir. Metin çıktısı inceleme içindir; serileştirilmiş nesne grafiği, bağımsız geçişlerin fonksiyon, tanımlayıcı, kapsam ve metadata ilişkilerini korumasını sağlar. Bu, **yeniden oluşturulmuş veya çalıştırılabilir JavaScript değildir**.<sup>[[1]](#references)[[2]](#references)</sup>

### V8 oluşturmadan bir cache'i triyaj edin

Ham veya Brotli ile sarılmış bir cache için `jscd`, örneği Node.js'te yüklemeden başlığı belirleyebilir ve sabitlerle fonksiyonları listeleyebilir. Sürüm tablolarının dosyayı destekleyip desteklemediğini kontrol etmek ve daha özelleşmiş View8 deobfuscation geçişlerinden önce fonksiyonlara öncelik vermek için önce bunu kullanın.<sup>[[4]](#references)</sup>

Sürüm hash'i bir tanımlama ipucudur; tek başına bağımsız bir disassembler'ın üreticidekiyle aynı flag'lere veya salt okunur snapshot'a sahip olduğunu kanıtlamaz.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm`, View8 uyumlu bir listeleme üretir; bu nedenle önbellek desteklendiğinde yukarıdaki View8 komutu, `v8dasm` yerine bu çıktıyı kullanabilir. Decoder çağrılarını ve olası giriş noktalarını bulmak için işlev ağacının yanı sıra dizeleri de inceleyin; `jscd`'nin yaklaşık JavaScript çıktısını özgün kaynak olarak değerlendirmeyin. Araç sürümü reddederse veya salt okunur heap yer tutucuları bırakırsa, tahminde bulunmak yerine eşleşen bir V8 derlemesine dönün ya da aynı derlemeden bir ad eşlemesi sağlayın.<sup>[[4]](#references)</sup>

Electron uygulamasındaki bir önbellek için önce [ASAR'ı çıkarın ve main ile preload giriş noktalarını inceleyin](../../desktop-application-security/electron-desktop-apps/). V8 sürüm dizeleri eşleşse bile Electron ve Node önbelleklerinin snapshot ve pointer-compression düzenleri farklı olabilir.<sup>[[4]](#references)</sup>

### View8 pseudocode'unu bir IR olarak okuyun

Yaygın adlandırma biçimleri `func_<name>_0x<address>` şeklindedir; argümanlar `a0...aN`, sanal register'lar `r0...rN` biçimindedir ve `ACCU`, V8'in accumulator'ıdır. `start` kök tanımlayıcıdır; `Scope[...]`, globals ve dictionaries ise iç içe işlevler tarafından yakalanan veya paylaşılan değerleri modeller. Her ifadeyi JavaScript sözdizimi olarak ayrıştırmayın: örneğin, View8'deki `!r6 === "0"`, karşılaştırmanın tamamının olumsuzlanmasını ifade eder (`r6 !== "0"`); dalları yeniden oluştururken bu önemlidir.<sup>[[1]](#references)[[3]](#references)</sup>

## Bağımlılıkları dikkate alan deobfuscation

Sonraki geçiş için gereken girdileri ortaya çıkaracak sırayla dönüşümler uygulayın ve çıktı kararlı hâle gelene kadar yayılımı tekrarlayın. Uygulanabilir bir sıra şöyledir:<sup>[[1]](#references)[[2]](#references)</sup>

1. Tanımlayıcı hiyerarşisini dolaşın ve globals, register'lar, dictionaries ve `Scope[...]` referanslarındaki değerleri yayılım yoluyla aktarın.
2. String decoder argümanlarını bulun ve şifrelenmiş çağrıları düz metinle değiştirin.
3. Bitişik string parçalarını birleştirin; ortaya çıkan property adları ve dispatcher sırasını belirten string'ler sonraki geçişlerin önünü açar.
4. Control flow'u düzleştirmeyi geri alın, call proxy'lerini ve atomic-operation wrapper'larını inline edin ve dictionary'lerde tutulan function referanslarını çözümleyin.
5. Her çözülmüş string, key veya proxy başka bir dolaylılık katmanını ortaya çıkarabileceğinden yayılımı yeniden uygulayın.
6. Tanınan tek seferlik initialization thunk'larını birleştirin ve dead helper'ları yalnızca çağrı noktaları çözümlendikten sonra kaldırın.

### Kaydırılmış RC4 string dizilerini black box olarak kurtarın

Yaygın bir `javascript-obfuscator` düzeninde, Base64 ile kodlanmış RC4 parçaları tek bir dizide saklanır. Decoder wrapper'ları sayısal bir offset ve kısa bir key sağlar; bazen argüman sırası tersine çevrilir ve ardından closure scope'larında yakalanan sabitler eklenir veya çıkarılır. Kök decoder aşırı derecede obfuscate edilmişse, işlevin tamamını yeniden oluşturmaya çalışmak yerine bilinmeyen dizi indeks kaymasını deneysel olarak bulun.<sup>[[1]](#references)</sup>

`N` parçalı bir dizi ve aynı decoder'a yapılan birkaç çağrı için:<sup>[[1]](#references)</sup>

```text
for each observed (numeric_argument, rc4_key):
    candidates = {}
    for shift in 0 .. N-1:
        index = apply_observed_sign(numeric_argument, shift)
        plaintext = RC4(Base64Decode(chunks[index]), rc4_key)
        if plaintext passes encoding/printability checks:
            candidates.add(shift)
root_shift = intersection(candidate_sets)
```

Tek bir yazdırılabilir çözüme bakarak kaydırmayı kabul etmeyin: yanlış ciphertext tesadüfen yazdırılabilir görünebilir. En az üç farklı gözlem kullanın ve yalnızca hepsi için makul metin üreten tekil bir kaydırmayı kabul edin. Ardından wrapper/declarer grafiğini dolaşın; her toplama veya çıkarmayı biriktirin ve sayısal argümanın önce gelip gelmediğini kaydedin. Bu metadata'yı her örnek için önbelleğe alın, decoder çağrılarını değiştirin, bitişik düz metin parçalarını birleştirin ve triage için dizeleri ayrı olarak dışa aktarın.<sup>[[1]](#references)[[2]](#references)</sup>

### Unflattening sırasında semantiği koruyun

`3|2|1|0|4` gibi dizelerle yönlendirilen dispatcher döngülerinde sıra dizesini çözün, her durum karşılaştırmasını ilgili bloğa eşleyin, View8'in olumsuz koşul gösterimini hesaba katın ve ardından blokları dispatcher sırasına göre çıkarın. İç içe bir `continue`, sıradan bir fall-through yerine dispatcher'a geri dönüşü temsil ediyor olabilir. Döngüyü kaldırırken bu `continue` ifadesini silin ve onu kapsayan `if` ifadesinden sonra gelen deyimleri oluşturulan bir `else` dalına taşıyın; yalnızca dispatcher'ı silmek davranışı değiştirir.<sup>[[1]](#references)</sup>

### Proxy'leri, işlemleri ve lazy thunk'ları inline edin

Çağrı noktalarını doğrudan çağrılarla değiştirmeden önce `return a0(a1, a2)` gibi yönlendirme yardımcılarını normalize edin. Çıkarma, bölme, karşılaştırma, üyelik testi veya çağırma işlemlerine yönelik wrapper'lara da aynı şekilde yaklaşın. Yardımcıya yapılan başvurunun kendisi şifresi çözülmüş bir sözlük anahtarının veya closure değerinin arkasında saklanıyor olabileceğinden, inline etme işleminden önce ve sonra dize ve yapı yayılımını çalıştırın.<sup>[[1]](#references)</sup>

Saklanan bir işlevi bir kez çağıran, başvurusunu temizleyen, sonucu önbelleğe alan ve sonraki çağrılarda bu önbelleği döndüren closure'ları da tanıyın. Böyle bir thunk'ı başlatma noktasında açığa çıkarmak, alttaki dispatcher'ı veya capability function'ı görünür kılar; ancak özgün yürütmenin her çağrıda yeni bir çağrı değil, **tek seferlik ve önbelleğe alınmış** olduğunu not edin.<sup>[[1]](#references)</sup>

## Güvenlik ve doğrulama notları

- Python `pickle` yükleme işlemi kod çalıştırabilir. Yalnızca güvenilir View8 çalıştırmasının yerel olarak oluşturduğu `.pkl` dosyalarını yükleyin; örneğin sağladığı bir pickle dosyasını asla veri olarak kabul etmeyin.<sup>[[2]](#references)</sup>
- Bir işlev gövdesinin eksik olması, kaynağın bu işlevi içermediğini kanıtlamaz: V8, lazy function'ları ilk çağrıda derlenene kadar metadata olarak serileştirebilir. Statik triage sırasında bu tür işlevleri çözümlenmemiş olarak işaretli tutun.<sup>[[6]](#references)</sup>
- Desen odaklı geçişler genel amaçlı bir JavaScript decompiler değildir. Çözümlenmemiş ifadeleri koruyun ve belirsiz dispatcher varyantlarını yeniden yazmaya zorlamak yerine elle inceleyin.<sup>[[1]](#references)[[2]](#references)</sup>
- LLM yardımıyla oluşturulan işlev adları kanıt değil, gezinme ipuçlarıdır. Bunları kullanıyorsanız bağımlılıkları yapraklardan başlayarak işleyin; ancak her etiketi gövde, argümanlar, dizeler, veri akışı, API'ler ve yan etkilerle doğrulayın.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Mührü Kırmak: JSCeal'in Derlenmiş V8 Bytecode'unun Statik Olarak Gizliliğini Kaldırma](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [V8 SerializedCodeData başlığı](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Node.js vm.Script kod önbelleği](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
