# Fuzzing Metodolojisi

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

**Mutational grammar fuzzing** içinde, girdiler **grammar-valid** kalırken mutate edilir. Coverage-guided modda, yalnızca **new coverage** tetikleyen örnekler corpus seeds olarak kaydedilir. **Language targets** (parsers, interpreters, engines) için bu, bir yapının çıktısının başka bir yapının girdisi olduğu **semantic/dataflow chains** gerektiren bug’ları kaçırabilir.

**Failure mode:** fuzzer, tek tek `document()` ve `generate-id()` (veya benzer primitives) çalıştıran seeds bulur, ancak **zincirlenmiş dataflow**’u korumaz; bu yüzden “bug’a daha yakın” örnek, coverage eklemediği için düşürülür. **3+ dependent steps** ile random recombination pahalı hale gelir ve coverage feedback aramayı yönlendirmez.

**Implication:** dependency-heavy grammars için, **mutational** ve **generative** fazları **hybridizing** etmeyi veya üretimi yalnızca coverage’a değil **function chaining** pattern’lerine doğru bias etmeyi düşünün.

## Corpus Diversity Pitfalls

Coverage-guided mutation **greedy**’dir: yeni coverage üreten örnek hemen kaydedilir ve çoğu zaman büyük değişmeden kalan bölgeler korunur. Zamanla corpora, düşük yapısal çeşitliliğe sahip **near-duplicates** haline gelir. Agresif minimization faydalı bağlamı kaldırabilir; bu yüzden pratik bir uzlaşma, **minimum token threshold** sonrasında duran **grammar-aware minimization** kullanmaktır (mutasyona uygun kalacak kadar çevresel yapıyı korurken gürültüyü azaltmak).

Mutational fuzzing için pratik corpus kuralı şudur: büyük bir near-duplicates yığını yerine coverage’ı maksimize eden yapısal olarak farklı küçük bir seed seti tercih edin. Pratikte bu genelde şunları ifade eder:

- **Real-world samples** ile başlayın (public corpora, crawling, captured traffic, target ecosystem’den file sets).
- Her geçerli örneği saklamak yerine **coverage-based corpus minimization** ile bunları damıtın.
- Seeds’i, mutasyonların önemsiz byte’lar yerine anlamlı alanlara düşecek kadar **small** tutun.
- Büyük harness/instrumentation değişikliklerinden sonra corpus minimization’ı yeniden çalıştırın; çünkü reachability değiştiğinde “en iyi” corpus da değişir.

## Comparison-Aware Mutation For Magic Values

Fuzzer’ların tıkanmasının yaygın bir nedeni syntax değil, **hard comparisons**’dır: magic bytes, length checks, enum strings, checksums veya `memcmp`, switch tables ya da cascaded comparisons ile korunan parser dispatch values. Saf random mutation, bu değerleri byte-byte tahmin etmeye çalışırken döngüleri boşa harcar.

Bu hedefler için, fuzzer’ın başarısız comparisons’tan operands gözlemleyip mutations’ı onları sağlayan değerlere doğru bias edebilmesi için **comparison tracing** kullanın (örneğin AFL++ `CMPLOG` / Redqueen-style workflows).
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

- Bu, hedefin derin mantığı **file signatures**, **protocol verbs**, **type tags** veya **version-dependent feature bits** arkasına gizlediği durumlarda özellikle kullanışlıdır.
- Bunu, gerçek örneklerden, protocol spesifikasyonlarından veya debug log’lardan çıkarılmış **dictionaries** ile eşleştirin. Grammar token’ları, chunk adları, verb’ler ve delimiters içeren küçük bir dictionary, çoğu zaman devasa bir genel wordlist’ten daha değerlidir.
- Hedef birçok ardışık kontrol yapıyorsa, önce en erken “magic” karşılaştırmaları çözün ve sonra oluşan corpus’u tekrar küçültün; böylece sonraki aşamalar zaten geçerli prefix’lerle başlar.

## Stateful Fuzzing: Sequences Are Seeds

**protocols**, **authenticated workflows** ve **multi-stage parsers** için ilginç birim çoğu zaman tek bir blob değil, bir **message sequence**’tir. Tüm transcript’i tek bir file’a birleştirip körlemesine mutate etmek genellikle verimsizdir; çünkü fuzzer her adımı eşit biçimde mutate eder, oysa kırılgan state’e yalnızca sonraki message ulaşır.

Daha etkili bir yaklaşım, **sequence**’ü seed olarak ele almak ve **observable state**’i (response kodları, protocol states, parser phases, dönen object type’ları) ek feedback olarak kullanmaktır:

- **Valid prefix messages**’ı stabil tutun ve mutasyonları **transition-driving** message’a odaklayın.
- Sonraki adım bunlara bağlıysa, önceki response’lardan identifier’ları ve server-generated value’ları cache’leyin.
- Tüm serialized transcript’i opak bir blob olarak mutate etmek yerine, message başına mutation/splicing’i tercih edin.
- Protocol anlamlı response kodları sunuyorsa, bunları daha derin ilerleyen sequence’leri önceliklendirmek için **cheap state oracle** olarak kullanın.

Bu yüzden authenticated bug’lar, gizli transition’lar veya “only-after-handshake” parser bug’ları, sıradan file-style fuzzing ile çoğu zaman kaçırılır: fuzzer’ın yalnızca structure’ı değil, **order, state ve dependencies**’i de koruması gerekir.

## Single-Machine Diversity Trick (Jackalope-Style)

**generative novelty** ile **coverage reuse**’u hibritleştirmenin pratik bir yolu, kalıcı bir server’a karşı **short-lived workers**’ı yeniden başlatmaktır. Her worker boş bir corpus ile başlar, `T` saniye sonra senkronize olur, birleşik corpus üzerinde bir `T` saniye daha çalışır, tekrar senkronize olur, ardından çıkar. Bu, bir yandan birikmiş coverage’dan yararlanırken her generation’da **fresh structures** üretir.

**Server:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Sıralı workers (örnek döngü):**

<details>
<summary>Jackalope worker yeniden başlatma döngüsü</summary>
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
- `-server_update_interval T` **gecikmeli sync**'i yaklaşıklar (önce yenilik, sonra yeniden kullanım).
- Grammar fuzzing modunda, **ilk server sync varsayılan olarak atlanır** (`-skip_initial_server_sync` gerekmez).
- En uygun `T` **hedefe bağlıdır**; worker “kolay” coverage’ın çoğunu bulduktan sonra geçiş yapmak genelde en iyi sonucu verir.

## Zor Harness Edilen Hedefler İçin Snapshot Fuzzing

Test etmek istediğiniz kod ancak **büyük bir hazırlık maliyetinden** sonra erişilebilir hale geliyorsa (bir VM başlatmak, login tamamlamak, bir packet almak, bir container parse etmek, bir service initialize etmek), kullanışlı bir alternatif **snapshot fuzzing**'dir:

1. Hedefi ilginç durum hazır olana kadar çalıştırın.
2. O noktada **memory + registers** snapshot alın.
3. Her test case için, değiştirilmiş girdi verisini doğrudan ilgili guest/process buffer'ına yazın.
4. Crash/timeout/reset olana kadar execute edin.
5. Yalnızca **dirty pages**'i geri yükleyin ve tekrarlayın.

Bu, her iterasyonda tam hazırlık maliyetini ödemekten kaçınır ve özellikle **network services**, **firmware**, **post-auth attack surfaces** ve klasik in-process harness'e yeniden düzenlenmesi zor olan **binary-only targets** için çok kullanışlıdır.

Pratik bir yöntem, bir `recv`/`read`/packet-deserialization noktasından hemen sonra break etmek, input buffer adresini not etmek, orada snapshot almak ve ardından her iterasyonda o buffer'ı doğrudan mutate etmektir. Bu, tüm handshake'i her seferinde yeniden oluşturmadan derin parsing logic'i fuzz etmenizi sağlar.

## Harness Introspection: Sığ Fuzzer'ları Erken Bulun

Bir campaign takıldığında, sorun çoğu zaman mutator değil **harness**'tir. Fuzz target'ınızdan statik olarak erişilebilir ama dinamik olarak nadiren ya da hiç cover edilmeyen function'ları bulmak için **reachability/coverage introspection** kullanın. Bu function'lar genellikle üç sorundan birine işaret eder:

- Harness target'a çok geç veya çok erken giriyor.
- Seed corpus, tüm bir feature family'sini eksik bırakıyor.
- Target gerçekten tek bir aşırı büyük “her şeyi yap” harness yerine **ikinci bir harness** gerektiriyor.

OSS-Fuzz / ClusterFuzz tarzı workflows kullanıyorsanız, Fuzz Introspector bu triage için kullanışlıdır:
```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```
Raporu kullanarak test edilmemiş bir parser path için yeni bir harness ekleyip eklemeyeceğine, belirli bir özellik için corpus’u genişletip genişletmeyeceğine veya tek parça bir harness’i daha küçük entry point’lere bölüp bölmeyeceğine karar ver.

## References

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [AFL++ Fuzzing in Depth](https://aflplus.plus/docs/fuzzing_in_depth/)
- [AFLNet Five Years Later: On Coverage-Guided Protocol Fuzzing](https://arxiv.org/abs/2412.20324)

{{#include ../banners/hacktricks-training.md}}
