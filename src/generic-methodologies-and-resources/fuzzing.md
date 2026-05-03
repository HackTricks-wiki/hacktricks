# Fuzzing Methodology

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**Mutational grammar fuzzing** içinde, girdiler **grammar-valid** kalacak şekilde mutate edilir. Coverage-guided modda, yalnızca **new coverage** tetikleyen örnekler corpus seed olarak kaydedilir. **Language targets** (parsers, interpreters, engines) için bu, bir yapının çıktısının başka bir yapının girdisi olduğu **semantic/dataflow chains** gerektiren bug’ları kaçırabilir.

**Failure mode:** fuzzer, tek tek `document()` ve `generate-id()` (veya benzeri primitives) çalışan seed’leri bulur, ancak **chained dataflow**’yu korumaz; bu yüzden “bug’a daha yakın” örnek, coverage eklemediği için elenir. **3+ dependent steps** olduğunda, rastgele yeniden birleştirme maliyetli hale gelir ve coverage feedback aramayı yönlendirmez.

**Implication:** dependency-heavy grammars için, **mutational** ve **generative** phase’leri **hybridize** etmeyi veya üretimi **function chaining** kalıplarına (sadece coverage’a değil) doğru önyargılamayı düşünün.

## Corpus Diversity Pitfalls

Coverage-guided mutation **greedy**’dir: new-coverage bir örnek hemen kaydedilir ve çoğu zaman büyük değişmemiş bölgeleri korur. Zamanla corpus, düşük structural diversity’ye sahip **near-duplicates** haline gelir. Aggressive minimization yararlı context’i kaldırabilir; bu yüzden pratik bir denge, **minimum token threshold** sonrasında duran **grammar-aware minimization** kullanmaktır (mutation-friendly kalacak kadar çevresel structure’ı korurken gürültüyü azaltmak).

Mutational fuzzing için pratik bir corpus kuralı: büyük bir near-duplicates yığını yerine **coverage’ı maksimize eden, yapısal olarak farklı küçük bir seed seti** tercih edin. Pratikte bu genellikle şunlar demektir:

- **Gerçek dünya örnekleri** ile başlayın (public corpora, crawling, captured traffic, target ecosystem’den file set’ler).
- Her geçerli örneği tutmak yerine, bunları **coverage-based corpus minimization** ile ayıklayın.
- Seed’leri, mutation’ların çoğu zamanı irrelevant bytes yerine meaningful fields üzerinde gerçekleşeceği kadar **küçük** tutun.
- Büyük harness/instrumentation değişikliklerinden sonra corpus minimization’ı yeniden çalıştırın, çünkü reachability değiştiğinde “en iyi” corpus da değişir.

## Comparison-Aware Mutation For Magic Values

Fuzzer’ların tıkanmasının yaygın bir nedeni syntax değil, **hard comparisons**’dır: magic bytes, length checks, enum strings, checksums veya `memcmp`, switch tables ya da cascaded comparisons ile korunan parser dispatch values. Saf random mutation, bu değerleri byte-byte tahmin etmeye çalışırken döngüleri boşa harcar.

Bu hedeflerde, fuzzer’ın başarısız comparisons’tan operand’ları gözlemleyip onları karşılayan değerlere doğru mutation’ı eğebilmesi için **comparison tracing** kullanın (örneğin AFL++ `CMPLOG` / Redqueen-style workflows).
```bash
./configure --cc=afl-clang-fast
make
cp ./target ./target.afl

make clean
AFL_LLVM_CMPLOG=1 ./configure --cc=afl-clang-fast
make
cp ./target ./target.cmplog

afl-fuzz -i in -o out -c ./target.cmplog -- ./target.afl @@
```
**Pratik notlar:**

- Bu, hedef **file signatures**, **protocol verbs**, **type tags** veya **version-dependent feature bits** arkasına derin logic gizlediğinde özellikle kullanışlıdır.
- Bunu gerçek örneklerden, protocol specs’lerden veya debug log’lardan çıkarılan **dictionaries** ile eşleştirin. Grammar token’ları, chunk adları, verbs ve delimiters içeren küçük bir dictionary, çoğu zaman devasa bir genel wordlist’ten daha değerlidir.
- Hedef birçok ardışık kontrol yapıyorsa, önce en erken “magic” karşılaştırmaları çözün ve sonra oluşan corpus’u tekrar minimize edin; böylece sonraki aşamalar zaten geçerli prefix’lerle başlar.

## Stateful Fuzzing: Sequences Are Seeds

**protocols**, **authenticated workflows** ve **multi-stage parsers** için ilginç birim çoğu zaman tek bir blob değil, bir **message sequence**’tir. Tüm transcript’i tek bir dosyada birleştirip körü körüne mutasyona uğratmak genellikle verimsizdir; çünkü fuzzer, yalnızca sonraki mesaj kırılgan state’e ulaştığında bile her adımı eşit şekilde mutasyona uğratır.

Daha etkili bir yaklaşım, **sequence**’ın kendisini seed olarak ele almak ve **observable state**’i (response codes, protocol states, parser phases, returned object types) ek feedback olarak kullanmaktır:

- **Valid prefix messages**’ları sabit tutun ve mutasyonları **transition-driving** mesaj üzerinde yoğunlaştırın.
- Sonraki adım bunlara bağlıysa, önceki response’lardan identifier’ları ve server-generated value’ları önbelleğe alın.
- Opaque bir blob olarak tüm serialized transcript’i mutasyona uğratmak yerine, mesaj bazında mutation/splicing yapmayı tercih edin.
- Protocol anlamlı response codes sunuyorsa, bunları daha derin ilerleyen sequence’leri önceliklendirmek için ucuz bir **state oracle** olarak kullanın.

Authenticated bugs, hidden transitions veya “only-after-handshake” parser bugs’ların vanilla file-style fuzzing ile sıkça kaçırılmasının nedeni de budur: fuzzer’ın yalnızca structure’ı değil, **order, state ve dependencies**’i de koruması gerekir.

## Single-Machine Diversity Trick (Jackalope-Style)

**Generative novelty** ile **coverage reuse**’u hibrit hale getirmenin pratik bir yolu, kalıcı bir server’a karşı kısa ömürlü worker’ları yeniden başlatmaktır. Her worker boş bir corpus ile başlar, `T` saniye sonra sync olur, birleşik corpus üzerinde bir `T` saniye daha çalışır, tekrar sync olur, ardından çıkar. Bu, bir yandan birikmiş coverage’dan yararlanırken diğer yandan her generation’da **fresh structures** üretir.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sıralı workers (örnek loop):**

<details>
<summary>Jackalope worker yeniden başlatma loop</summary>
```python
import subprocess
import time

T = 3600

while True:
subprocess.run(["rm", "-rf", "workerout"])
p = subprocess.Popen([
"/path/to/fuzzer",
"-grammar", "grammar.txt",
"-instrumentation", "sancov",
"-in", "empty",
"-out", "workerout",
"-t", "1000",
"-delivery", "shmem",
"-iterations", "10000",
"-mute_child",
"-nthreads", "6",
"-server", "127.0.0.1:8337",
"-server_update_interval", str(T),
"--", "./harness", "-m", "@@",
])
time.sleep(T * 2)
p.kill()
```
</details>

**Notlar:**

- `-in empty` her üretimde **yeni bir corpus** zorlar.
- `-server_update_interval T` **gecikmeli sync** davranışını yaklaşık olarak taklit eder (önce yenilik, sonra yeniden kullanım).
- grammar fuzzing modunda, **ilk server sync varsayılan olarak atlanır** (`-skip_initial_server_sync` gerekmez).
- En uygun `T` **hedefe bağlıdır**; worker çoğu “kolay” coverage’ı bulduktan sonra değiştirmek genelde en iyi sonucu verir.

## Erişimi Zor Hedefler İçin Snapshot Fuzzing

Test etmek istediğiniz code ancak **büyük bir hazırlık maliyetinden** sonra erişilebilir hale geliyorsa (VM boot etmek, bir login tamamlamak, bir packet almak, bir container parse etmek, bir service initialize etmek), kullanışlı bir alternatif **snapshot fuzzing**'dir:

1. Hedefi ilginç durum hazır olana kadar çalıştırın.
2. O noktada **memory + registers** snapshot alın.
3. Her test case için, mutasyona uğramış input'u doğrudan ilgili guest/process buffer içine yazın.
4. crash/timeout/reset olana kadar execute edin.
5. Sadece **dirty pages**'i geri yükleyin ve tekrarlayın.

Bu, her iterasyonda tam hazırlık maliyetini ödemeyi önler ve özellikle **network services**, **firmware**, **post-auth attack surfaces** ve klasik in-process harness'e yeniden düzenlemesi zahmetli olan **binary-only targets** için çok faydalıdır.

Pratik bir numara, bir `recv`/`read`/packet-deserialization noktasından hemen sonra break etmek, input buffer address'ini not etmek, orada snapshot almak ve sonra her iterasyonda bu buffer'ı doğrudan mutate etmektir. Bu, tüm handshake'i her seferinde yeniden kurmadan derin parsing logic'i fuzz etmenizi sağlar.

## Harness Introspection: Sığ Fuzzer'ları Erken Bulun

Bir campaign durduğunda, sorun çoğu zaman mutator değil **harness**'tir. Fuzz target'ınızdan statik olarak erişilebilir ama dinamik olarak nadiren ya da hiç cover edilmeyen function'ları bulmak için **reachability/coverage introspection** kullanın. Bu function'lar genellikle üç sorundan birine işaret eder:

- Harness hedefe çok geç ya da çok erken giriyor.
- Seed corpus, bütün bir feature family'si eksik.
- Hedefin gerçekten bir tane aşırı büyük “her şeyi yap” harness yerine **ikinci bir harness**'e ihtiyacı var.

OSS-Fuzz / ClusterFuzz tarzı workflow'lar kullanıyorsanız, Fuzz Introspector bu triage için faydalıdır:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Kullanılmamış bir parser yolu için yeni bir harness ekleyip eklememeye, belirli bir özellik için corpus’u genişletip genişletmemeye veya monolitik bir harness’i daha küçük entry point’lere bölüp bölmemeye karar vermek için raporu kullanın.

## Graph-First Fuzz Target Selection And Mutation Triage

Eğer zaten **static-analysis findings**, **mutation-testing survivors** ve **coverage reports** varsa, bunları bağımsız listeler olarak triage etmeyin. Önce bir **call graph** oluşturun, düğümleri **cyclomatic complexity**, **entrypoint/untrusted-input reachability** ve varsa dış bulgular ile etiketleyin, sonra grafik soruları sorun:

- Hangi yüksek-complexity fonksiyonlar untrusted input’tan erişilebilir?
- Hangi mutation survivors, parser/handler’lardan security-critical code’a giden path’ler üzerinde duruyor?
- Hangi fonksiyonlar alışılmadık derecede yüksek **blast radius**’a sahip architectural choke point’lerdir?

Bu yaklaşım, genellikle yalnızca "en düşük coverage" değerine bakmaktan daha iyi fuzz target’lar ortaya çıkarır. Yüksek complexity’ye ve doğrulanmış external reachability’ye sahip bir parser/decoder, zayıf coverage’a sahip ama attacker-controlled path’i olmayan izole bir internal helper’dan daha güçlü bir harness adayıdır.

### Pratik triage workflow

1. Codebase’den bir **code graph** oluşturun ve fonksiyon başına complexity/branch metriklerini çıkarın.
2. Attacker-controlled input kabul eden **entrypoint**’leri listeleyin: request handlers, decoders, importers, protocol parsers, CLI/file readers.
3. Bu entrypoint’lerden candidate fonksiyonlara **path queries** çalıştırarak reachable attack surface’i dead/internal-only code’dan ayırın.
4. Şu özellikleri birleştiren düğümleri önceliklendirin:
- yüksek **cyclomatic complexity**
- untrusted input’tan doğrulanmış **reachability**
- yüksek **blast radius** veya çok sayıda downstream dependent
- **SARIF** bulguları, audit notları veya mutation survivors gibi destekleyici kanıtlar
5. En yüksek skorlu düğümler için önce odaklanmış harness’ler yazın; özellikle hex/Base64/IP/message decoders gibi **parsers/codecs**.

### Mutation survivors: equivalent vs actionable

Mutation testing çoğu zaman gürültülü bir survivor listesi üretir. Her survivor’ı security gap olarak görmeden önce, graph’i kullanarak şunları sorun:

- Mutated function, attacker-controlled bir entrypoint’ten erişilebilir mi?
- Tüm call path’ler, mutated check’ten daha güçlü invariants ile mi kısıtlanıyor?
- Node dead code’da mı, yalnızca formatting logic’te mi, yoksa yüksek etkili bir arithmetic/parser path’inde mi?

Ulaşılamayan ya da yapısal olarak kısıtlanmış survivor’lar çoğu zaman **equivalent mutant**’tır. **Reachable** kalan ve **boundary conditions**, **overflow/carry paths** veya **security-critical arithmetic/parsing** ile temas eden survivor’lar ise şunlara dönüştürülmelidir:

- yeni fuzz harness’ler
- doğrudan property/invariant testleri
- hedeflenmiş edge-case vector’leri

### External findings’i graph üzerine korele edin

Eğer SAST pipeline’ınız **SARIF** çıkarıyorsa, bulguları **file + line range** ile graph düğümlerine projelendirin ve graph’i impact’i genişletmek için kullanın:

- işaretlenen fonksiyonun **blast radius**’unu hesaplayın
- bulgunun bir entrypoint’ten gelen herhangi bir path üzerinde olup olmadığını kontrol edin
- aynı choke point’e birleşen yakın bulguları kümeleyin

Bu, belirli bir fonksiyon için fuzzing zamanına değip değmeyeceğine karar verirken faydalıdır: **reachable**, **complex** ve zaten **SAST hits**’i olan bir node, saldırgan path’i olmayan sadece kompleks bir node’dan genellikle daha iyi bir hedeftir.

Trailmark ile örnek workflow:
```bash
uv pip install trailmark
trailmark analyze --complexity 10 path/to/project
```

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("path/to/project", language="c")
engine.preanalysis()
engine.complexity_hotspots(10)
engine.paths_between("handle_request", "parse_ipv6")
```
Önemli metodoloji kesişimdir: **complexity x exposure x impact**. En yüksek beklenen security value’a sahip fuzz target’ları seçmek için graph’ı kullanın, ardından mutation survivor’ları kullanarak harness’inizin hangi boundary ve invariant’ları zorlaması gerektiğine karar verin.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)
- [Trailmark turns code into graphs](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [trailofbits/trailmark](https://github.com/trailofbits/trailmark)

{{#include ../banners/hacktricks-training.md}}
