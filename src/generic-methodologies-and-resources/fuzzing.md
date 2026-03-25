# Fuzzing Metodolojisi

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantics

In **mutational grammar fuzzing**, girdiler **grammar-valid** kalırken değiştirilir. coverage-guided modda, yalnızca **new coverage** tetikleyen örnekler corpus seeds olarak kaydedilir. **language targets** (parsers, interpreters, engines) için, bir yapının çıktısının başka bir yapının girdisi haline geldiği **semantic/dataflow chains** gerektiren hatalar gözden kaçabilir.

**Başarısızlık modu:** fuzzer, tek tek `document()` ve `generate-id()` (veya benzeri primitifleri) çalıştıran seed'ler bulur, ancak **zincirlenmiş veri akışını korumaz**, bu yüzden “hataya-daha-yakın” örnek coverage eklemediği için atılır. **3+ dependent steps** ile rasgele yeniden kombinasyon pahalı hale gelir ve coverage geri bildirimi aramayı yönlendirmez.

**Çıkarım:** bağımlılık-ağır gramerler için, **hybridizing mutational and generative phases** düşünün veya üretimi sadece coverage değil, **function chaining** desenlerine yönelik önyargılı hale getirmeyi tercih edin (not just coverage).

## Corpus Diversity Pitfalls

Coverage-guided mutation **greedy** davranır: bir **new-coverage** örneği hemen kaydedilir ve genellikle büyük değişmemiş bölgeleri korur. Zamanla corpus'lar düşük yapısal çeşitliliğe sahip **near-duplicates** haline gelir. Agresif minimizasyon yararlı bağlamı kaldırabilir; pratik bir uzlaşma, gürültüyü azaltırken mutasyona elverişli olmak için yeterli çevresel yapıyı koruyan **grammar-aware minimization** ile **stops after a minimum token threshold** uygulamaktır (gürültüyü azaltırken mutasyona elverişli kalmak için yeterli çevresel yapıyı korur).

## Single-Machine Diversity Trick (Jackalope-Style)

Generative yeniliği (**generative novelty**) ile kapsam yeniden kullanımını (**coverage reuse**) hibritleştirmenin pratik bir yolu, kalıcı bir sunucuya karşı **restart short-lived workers** düzenlemektir. Her worker boş bir corpus ile başlar, `T` saniye sonra sync yapar, birleşik corpus üzerinde başka `T` saniye çalışır, tekrar sync yapar ve sonra çıkar. Bu, biriktirilmiş coverage'dan yararlanırken her jenerasyonda **taze yapılar** üretir.

**Sunucu:**
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

- `-in empty` her jenerasyonda **yeni bir corpus** zorunlu kılar.
- `-server_update_interval T` yaklaşık olarak **gecikmeli senkronizasyon** sağlar (önce yenilik, sonra yeniden kullanım).
- grammar fuzzing modunda, **başlangıç server senkronizasyonu varsayılan olarak atlanır** ( `-skip_initial_server_sync` gerekmez ).
- Optimal `T` **hedefe bağlıdır**; worker'ın çoğu “kolay” coverage'i bulduktan sonra geçiş yapmak genellikle en iyi sonucu verir.

## Referanslar

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
