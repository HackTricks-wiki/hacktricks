# Node.js/V8 Cached Bytecode'un Statik Deobfuscation'ı

{{#include ../../banners/hacktricks-training.md}}

V8 cached data, JavaScript source veya geleneksel bir native executable değil, **sürüme bağlı, kayıplı bir gösterimdir**. Bu nedenle kullanışlı bir statik workflow şu şekildedir: dış paketlemeyi kaldırın, cache'i eşleşen V8 build'i ile disassemble edin, bir intermediate pseudocode modeline aktarın ve sample'ı çalıştırmadan dependency-aware transformations uygulayın. [View8](https://github.com/suleram/View8) ve [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator), `javascript-obfuscator` ile korunan Node.js payload'ları için bu yaklaşımı uygular.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Cache'i edinme ve disassemble etme

İlk olarak her `.jsc` dosyasının aynı wrapper'a sahip olduğunu varsaymak yerine preload/launcher'ı inceleyin. Örneğin `node.exe -r preflight.js app.jsc` gibi bir launcher, ana modülden önce `preflight.js` dosyasını çalıştırır; analiz edilen ailede preload, bir Brotli katmanını kaldırıyordu. Unpacking işleminden sonra, bundled runtime'dan Node.js/V8 generation'ını kesin olarak belirleyin. Bir V8 sürümünde üretilen cache, başka bir V8 sürümü tarafından reddedilebilir veya yanlış decode edilebilir. Bu nedenle tam V8 tag'i için bir `v8dasm` build edin veya edinin ve gerekli View8 ile string-printing patch'lerini uygulayın.<sup>[[1]](#references)[[2]](#references)</sup>

Toolkit'in çalıştırma gerektirmeyen workflow'u şöyledir:<sup>[[2]](#references)</sup>
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
`--normalize`, oluşturulan functions için çalıştırmalar arasında kararlı identifiers sağlar. Metin çıktısı inceleme içindir; serialized object graph, bağımsız pass'lerin function, declarer, scope ve metadata ilişkilerini korumasını sağlar. Bu, **yeniden oluşturulmuş veya çalıştırılabilir JavaScript değildir**.<sup>[[1]](#references)[[2]](#references)</sup>

### View8 pseudocode'u bir IR olarak okuyun

Tipik isimler `func_<name>_0x<address>` biçimindedir, arguments `a0...aN`, virtual registers `r0...rN` ve `ACCU`, V8'in accumulator'ıdır. `start` root declarer'dır; `Scope[...]`, globals ve dictionaries, nested functions tarafından capture edilen veya paylaşılan değerleri modeller. Her expression'ı JavaScript syntax'ı olarak parse etmeyin: örneğin View8'in `!r6 === "0"` ifadesi, karşılaştırmanın tamamının negation'ını (`r6 !== "0"`) temsil eder; bu, branch'leri yeniden oluştururken önemlidir.<sup>[[1]](#references)[[3]](#references)</sup>

## Dependency-aware deobfuscation

Bir sonraki pass'in ihtiyaç duyduğu input'ları açığa çıkaracak sırayla transformations uygulayın ve output stabilize olana kadar propagation'ı tekrarlayın. Pratik bir sıra şöyledir:<sup>[[1]](#references)[[2]](#references)</sup>

1. Declarer hierarchy'yi dolaşın ve globals, registers, dictionaries ve `Scope[...]` references içindeki değerleri propagate edin.
2. String-decoder arguments'larını recover edin ve encrypted calls'ları plaintext ile değiştirin.
3. Ardışık string chunks'larını fold edin; ortaya çıkan property names ve dispatcher-order strings, sonraki pass'lerin kilidini açar.
4. Control flow'u unflatten edin, call proxies ve atomic-operation wrappers'ları inline edin ve dictionary'lerde tutulan function references'larını resolve edin.
5. Tekrar propagate edin; çünkü her çözümlenen string, key veya proxy başka bir indirection katmanını açığa çıkarabilir.
6. Tanınan one-shot initialization thunks'larını collapse edin ve dead helpers'ları ancak call sites çözümlendikten sonra kaldırın.

### Shift edilmiş RC4 string arrays'larını black box olarak recover edin

Yaygın bir `javascript-obfuscator` layout'u, Base64 ile encode edilmiş RC4 chunks'larını tek bir array'de depolar. Decoder wrappers sayısal bir offset ve kısa bir key sağlar; bazen arguments sırası ters çevrilir, ardından closure scopes içinde capture edilen constants eklenir veya çıkarılır. Root decoder fazla obfuscated olduğunda, tüm function'ı yeniden oluşturmak yerine bilinmeyen array-index shift'ini ampirik olarak recover edin.<sup>[[1]](#references)</sup>

`N` adet chunk'tan oluşan bir array ve aynı decoder'a yapılan birkaç call için:<sup>[[1]](#references)</sup>
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
Tek bir printable decryption sonucundan shift kabul etmeyin: yanlış ciphertext tesadüfen printable görünebilir. En az üç farklı gözlem kullanın ve yalnızca hepsi için makul metin üreten benzersiz bir shift'i kabul edin. Ardından wrapper/declarer graph'ını dolaşarak her addition veya subtraction işlemini biriktirin ve numeric argument'ın önce gelip gelmediğini kaydedin. Bu metadata'yı her sample için cache'leyin, decoder çağrılarını değiştirin, bitişik plaintext parçalarını birleştirin ve triage için string'leri ayrı olarak export edin.<sup>[[1]](#references)[[2]](#references)</sup>

### Unflattening sırasında semantics'i koruyun

`3|2|1|0|4` gibi string'lerle yönlendirilen dispatcher loop'larında order string'i decode edin, her state comparison'ı ilgili block'uyla eşleyin, ardından View8'in negated-condition notation'ını hesaba katıp block'ları dispatcher sırasına göre üretin. İç içe bir `continue`, sıradan bir fall-through yerine dispatcher'a geri dönen erken bir jump'ı temsil edebilir. Loop'u kaldırırken bu `continue`'ı silin ve başlangıçta onu kapsayan `if` ifadesinden sonra gelen statement'ları oluşturulan bir `else` branch'ine taşıyın; yalnızca dispatcher'ı silmek behavior'ı değiştirir.<sup>[[1]](#references)</sup>

### Proxy'leri, operation'ları ve lazy thunk'ları inline edin

Call site'larını direct call'larla değiştirmeden önce `return a0(a1, a2)` gibi forwarding helper'larını normalize edin. Subtraction, division, comparison, membership test veya invocation için kullanılan wrapper'ları da benzer şekilde ele alın. Helper reference'ın kendisi decrypted dictionary key veya closure value arkasında tutuluyor olabileceğinden, string ve structure propagation'ı inlining işleminden önce ve sonra çalıştırın.<sup>[[1]](#references)</sup>

Ayrıca stored function'ı bir kez çağıran, reference'ını temizleyen, sonucu cache'leyen ve sonraki çağrılarda bu cache'i döndüren closure'ları da tanıyın. Böyle bir thunk'ı initialization site'ında collapse etmek, underlying dispatcher veya capability function'ı açığa çıkarır; ancak original execution'ın her çağrıyı fresh invocation olarak modellemek yerine **one-shot ve cached** olduğunu belirtin.<sup>[[1]](#references)</sup>

## Safety ve validation notları

- Python `pickle` loading code çalıştırabilir. Yalnızca trusted View8 run tarafından local olarak oluşturulan `.pkl` dosyalarını load edin; sample-supplied pickle'ı asla data olarak değerlendirmeyin.<sup>[[2]](#references)</sup>
- Pattern-driven pass'ler genel amaçlı bir JavaScript decompiler değildir. Çözümlenmemiş expression'ları koruyun ve belirsiz dispatcher variant'larını rewrite etmeye zorlamak yerine manuel olarak inceleyin.<sup>[[1]](#references)[[2]](#references)</sup>
- LLM-assisted function name'leri navigation hint'leridir, evidence değildir. Bunları kullanıyorsanız dependency'leri leaf-first işleyin; ancak her label'ı body, argument'lar, string'ler, data flow, API'ler ve side effect'lere göre doğrulayın.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Breaking the Seal: Static Deobfuscation of JSCeal's Compiled V8 Bytecode](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}
