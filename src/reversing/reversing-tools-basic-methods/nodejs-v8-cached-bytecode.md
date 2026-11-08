# Node.js/V8 Önbelleğe Alınmış Bytecode'un Statik Gizleme Açma İşlemi

{{#include ../../banners/hacktricks-training.md}}

V8 önbelleğe alınmış verisi, JavaScript kaynak kodu ya da geleneksel bir yerel çalıştırılabilir dosya değil, **sürüme bağlı ve bilgi kayıplı bir gösterimdir**. Bu nedenle yararlı bir statik iş akışı şöyledir: dış paketlemeyi kaldırın, önbelleği eşleşen V8 derlemesiyle disassemble edin, ara düzey bir sözde kod modeline dönüştürün ve örneği çalıştırmadan bağımlılıkları dikkate alan dönüşümler uygulayın. [View8](https://github.com/suleram/View8) ve [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator), `javascript-obfuscator` ile korunmuş Node.js payload'ları için bu yaklaşımı uygular.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Önbelleği edinme ve disassemble etme

Her `.jsc` dosyasının aynı sarmalayıcıya sahip olduğunu varsaymak yerine önce preload/launcher'ı inceleyin. Örneğin `node.exe -r preflight.js app.jsc` gibi bir launcher, ana modülden önce `preflight.js` dosyasını çalıştırır; analiz edilen ailede preload, Brotli katmanını kaldırıyordu. Paketi açtıktan sonra, birlikte sunulan runtime'dan tam Node.js/V8 sürümünü belirleyin. Bir V8 sürümüyle oluşturulan önbellek, başka bir sürüm tarafından reddedilebilir veya yanlış çözümlenebilir. Bu nedenle ilgili V8 etiketi için bir `v8dasm` derleyin ya da edinin ve gerekli View8 ile string yazdırma yamalarını uygulayın.<sup>[[1]](#references)[[2]](#references)</sup>

Araç takımının çalıştırma gerektirmeyen iş akışı şöyledir:<sup>[[2]](#references)</sup>

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

`--normalize`, oluşturulan fonksiyonlara çalıştırmalar arasında kararlı tanımlayıcılar verir. Metin çıktısı inceleme içindir; serileştirilmiş nesne grafiği, bağımsız geçişlerin fonksiyon, bildirici, kapsam ve metadata ilişkilerini korumasını sağlar. Bu, **yeniden oluşturulmuş veya çalıştırılabilir JavaScript değildir**.<sup>[[1]](#references)[[2]](#references)</sup>

### V8'i derlemeden ön inceleme

Ham veya Brotli ile sarılmış bir cache için `jscd`, örneği Node.js'te yüklemeden başlığı belirleyebilir ve sabitlerle fonksiyonları listeleyebilir. Dosyanın sürüm tabloları tarafından desteklenip desteklenmediğini kontrol etmek ve daha özelleşmiş View8 deobfuscation geçişlerinden önce fonksiyonlara öncelik vermek için önce bunu kullanın.<sup>[[4]](#references)</sup>

Sürüm hash'i bir tanımlama ipucudur; tek başına, bağımsız bir disassembler'ın üreticiyle aynı flag'lere veya salt okunur snapshot'a sahip olduğunu kanıtlamaz.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm`, View8 ile uyumlu bir listeleme üretir; bu nedenle cache desteklendiğinde yukarıdaki View8 komutu `v8dasm` yerine bu çıktıyı kullanabilir. Decoder çağrılarını ve olası giriş noktalarını bulmak için string’leri işlev ağacıyla birlikte inceleyin; `jscd`'nin yaklaşık JavaScript çıktısını orijinal kaynak olarak kabul etmeyin. Araç sürümü reddederse veya salt okunur yığın yer tutucularını çözümlenmeden bırakırsa, tahmin ederek özellik adları atamak yerine eşleşen bir V8 build’ine dönün ya da aynı build’den bir ad eşleme dosyası sağlayın.<sup>[[4]](#references)</sup>

Bir Electron uygulamasının içindeki cache için önce [ASAR'ı çıkarın ve main ile preload giriş noktalarını inceleyin](../../network-services-pentesting/pentesting-web/electron-desktop-apps/). V8 sürüm dizeleri aynı olsa bile Electron ve Node cache’lerinin snapshot ve pointer-compression düzenleri farklı olabilir.<sup>[[4]](#references)</sup>

### View8 pseudocode'unu IR olarak okuma

Tipik adlandırma biçimi `func_<name>_0x<address>` şeklindedir; argümanlar `a0...aN`, sanal register’lar `r0...rN`, `ACCU` ise V8'in accumulator'ıdır. `start` kök bildiricidir; `Scope[...]`, global'ler ve sözlükler iç içe işlevler tarafından yakalanan veya paylaşılan değerleri modeller. Her ifadeyi JavaScript sözdizimi olarak yorumlamayın: örneğin, View8'deki `!r6 === "0"` ifadesi karşılaştırmanın tamamının olumsuzlanmasını (`r6 !== "0"`) temsil eder; bu, dalları yeniden oluştururken önemlidir.<sup>[[1]](#references)[[3]](#references)</sup>

## Bağımlılıkları gözeten deobfuscation

Bir sonraki geçiş için gereken girdileri ortaya çıkaracak sırayla dönüşümler uygulayın ve çıktı sabitlenene kadar değer yayılımını tekrarlayın. Uygulanabilir bir sıra şöyledir:<sup>[[1]](#references)[[2]](#references)</sup>

1. Bildirici hiyerarşisini izleyin ve global'lerden, register’lardan, sözlüklerden ve `Scope[...]` başvurularından değerleri yayın.
2. String decoder argümanlarını bulun ve şifrelenmiş çağrıları açık metinle değiştirin.
3. Bitişik string parçalarını birleştirin; ortaya çıkan özellik adları ve dispatcher sıralama string’leri sonraki geçişlerin önünü açar.
4. Kontrol akışını düzleştirmeyi geri alın, çağrı proxy'lerini ve atomik işlem sarmalayıcılarını satır içine alın, sözlüklerde tutulan işlev başvurularını çözümleyin.
5. Her çözümlenen string, anahtar veya proxy başka bir dolaylılık katmanını ortaya çıkarabileceğinden değerleri yeniden yayın.
6. Tanınan tek kullanımlık başlatma thunk'larını birleştirin ve kullanılmayan yardımcıları yalnızca çağrı noktaları çözümlendikten sonra kaldırın.

### Kaydırılmış RC4 string dizilerini black box olarak kurtarma

Yaygın bir `javascript-obfuscator` düzeninde, tek bir dizide Base64 ile kodlanmış RC4 parçaları bulunur. Decoder sarmalayıcıları sayısal bir offset ve kısa bir key sağlar; bunlar bazen ters argüman sırasındadır. Ardından closure scope'larında yakalanan sabitleri ekler veya çıkarırlar. Kök decoder aşırı derecede obfuscation uygulanmışsa, işlevin tamamını yeniden oluşturmaya çalışmak yerine bilinmeyen dizi indeks kaymasını deneysel olarak bulun.<sup>[[1]](#references)</sup>

`N` parça içeren bir dizi ve aynı decoder'a yapılan birkaç çağrı için:<sup>[[1]](#references)</sup>

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

Tek bir yazdırılabilir çözümlemeye bakarak shift değerini kabul etmeyin: yanlış ciphertext, tesadüfen yazdırılabilir görünebilir. En az üç farklı gözlem kullanın ve yalnızca hepsi için makul metin üreten benzersiz bir shift değerini kabul edin. Ardından wrapper/declarer grafiğini izleyin; her toplama veya çıkarma işlemini biriktirin ve sayısal argümanın önce gelip gelmediğini kaydedin. Bu metadata'yı her örnek için önbelleğe alın, decoder çağrılarını değiştirin, bitişik plaintext parçalarını birleştirin ve triage için string'leri ayrı olarak dışa aktarın.<sup>[[1]](#references)[[2]](#references)</sup>

### Unflatten işlemi sırasında semantiği koruyun

`3|2|1|0|4` gibi string'lerle yönlendirilen dispatcher döngülerinde, sıralama string'ini decode edin, her state karşılaştırmasını ilgili bloğa eşleyin, View8'in olumsuz koşul gösterimini hesaba katın, ardından blokları dispatcher sırasına göre çıkarın. İç içe bir `continue`, olağan akışta devam etmek yerine dispatcher'a geri dönen erken bir atlama olabilir. Döngüyü kaldırırken bu `continue` ifadesini silin ve onu kapsayan `if` ifadesinden sonra gelen deyimleri oluşturulan bir `else` dalına taşıyın; yalnızca dispatcher'ı silmek davranışı değiştirir.<sup>[[1]](#references)</sup>

### Proxy'leri, işlemleri ve lazy thunk'ları inline edin

Çağrı noktalarını doğrudan çağrılarla değiştirmeden önce `return a0(a1, a2)` gibi yönlendirme yardımcılarını normalize edin. Çıkarma, bölme, karşılaştırma, üyelik testi veya çağrı wrapper'larına da aynı şekilde yaklaşın. Yardımcıya yapılan başvurunun kendisi, çözülmüş bir sözlük anahtarının veya closure değerinin arkasında saklanıyor olabileceğinden, inline işleminden önce ve sonra string ve yapı yayılımı çalıştırın.<sup>[[1]](#references)</sup>

Ayrıca saklanan bir işlevi bir kez çağıran, başvurusunu temizleyen, sonucu önbelleğe alan ve sonraki çağrılarda bu önbelleği döndüren closure'ları da tanıyın. Böyle bir thunk'ı başlatma noktasında daraltmak, alttaki dispatcher'ı veya capability işlevini ortaya çıkarır; ancak özgün çalıştırmanın her çağrıda yeniden çağırma değil, **tek seferlik ve önbelleğe alınmış** olduğunu belirtin.<sup>[[1]](#references)</sup>

## Güvenlik ve doğrulama notları

- Python `pickle` yükleme işlemi kod çalıştırabilir. Yalnızca güvenilir View8 çalıştırmasının yerel olarak oluşturduğu `.pkl` dosyalarını yükleyin; örneğin sağladığı bir pickle'ı asla veri olarak değerlendirmeyin.<sup>[[2]](#references)</sup>
- Bir işlev gövdesinin eksik olması, kaynakta bu işlevin bulunmadığını kanıtlamaz: V8, lazy bir işlevi ilk çağrıda derlenene kadar metadata olarak serileştirebilir. Statik triage sırasında bu tür işlevleri çözümlenmemiş olarak işaretli tutun.<sup>[[6]](#references)</sup>
- Pattern odaklı geçişler genel amaçlı bir JavaScript decompiler değildir. Çözümlenmemiş ifadeleri koruyun ve belirsiz dispatcher varyantlarını yeniden yazmaya zorlamak yerine elle inceleyin.<sup>[[1]](#references)[[2]](#references)</sup>
- LLM destekli işlev adları, kanıt değil gezinme ipuçlarıdır. Bunları kullanıyorsanız bağımlılıkları yapraklardan başlayarak işleyin; ancak her etiketi gövdeye, argümanlara, string'lere, veri akışına, API'lere ve yan etkilere göre doğrulayın.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Mührü Kırmak: JSCeal'ın Derlenmiş V8 Bytecode'unun Statik Gizleme Kaldırma İşlemi](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [V8 SerializedCodeData başlığı](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Node.js vm.Script kod önbelleği](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
