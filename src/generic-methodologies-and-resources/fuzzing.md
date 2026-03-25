# Fuzzing Metodologie

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Dekking vs. Semantiek

In **mutational grammar fuzzing**, insette word gemuteer terwyl hulle **grammatika-geldig** bly. In 'n dekking-gestuurde modus word slegs monsters wat **nuwe dekking** veroorsaak as korpus-sade gestoor. Vir **taaldoelwitte** (parsers, interpreters, engines) kan dit foute mis wat **semantiese/datavloei-kettings** vereis waar die uitset van een konstruk die inset van 'n ander word.

**Foutmodus:** die fuzzer vind sade wat op hul eie `document()` en `generate-id()` (of soortgelyke primitives) oefen, maar **bewaar nie die gekoppelde datavloei nie**, sodat die voorbeeld wat nader aan die fout lê verwerp word omdat dit nie dekking byvoeg nie. Met **3+ afhanklike stappe** word ewekansige rekombinasie duur en dekking-terugvoer lei die soektog nie.

**Gevolg:** vir grammatika's met baie afhanklikhede, oorweeg om mutasie- en generatiewe fases te combineer of die generering te bevoordeel in rigting van funksiekettingpatrone (nie net dekking nie).

## Korpus Diversiteitsvalstrikke

Dekking-gestuurde mutasie is **gulsig**: 'n monster wat nuwe dekking bied word onmiddellik gestoor, dikwels met groot ongewijzigde gebiede. Oor tyd word korpora **byna-duplikaat** met lae strukturele diversiteit. Agressiewe minimalisering kan nuttige konteks verwyder, dus 'n praktiese kompromie is **grammatika-bewuste minimalisering** wat **stop nadat 'n minimum token-drempel bereik is** (verminder geraas terwyl genoeg omliggende struktuur behou word om mutasie-vriendelik te bly).

## Enkel-Masjien Diversiteitstruk (Jackalope-Style)

'n Praktiese manier om **generatiewe nuutheid** te kombineer met **dekking-hergebruik** is om **kortlewende werkers te herbegin** teen 'n volhoubare bediener. Elke werker begin met 'n leë korpus, sinkroniseer na `T` sekondes, hardloop nog `T` sekondes op die gekombineerde korpus, sinkroniseer weer, en sluit dan af. Dit lewer **vars strukture elke generasie** terwyl dit steeds die opgelope dekking benut.

**Bediener:**
```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```
**Opeenvolgende workers (voorbeeld loop):**

<details>
<summary>Jackalope worker restart loop</summary>
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

**Aantekeninge:**

- `-in empty` dwing 'n **vars korpus** elke generasie af.
- `-server_update_interval T` benader **vertraagde sinkronisering** (nuutheid eers, hergebruik later).
- In grammar fuzzing mode word die **aanvanklike server-sinkronisering standaard oorgeslaan** (geen behoefte aan `-skip_initial_server_sync`).
- Optimale `T` is **teiken-afhanklik**; omskakeling nadat die worker die meeste “maklike” coverage gevind het, werk gewoonlik die beste.

## Verwysings

- [Mutational grammar fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [Jackalope](https://github.com/googleprojectzero/Jackalope)

{{#include ../banners/hacktricks-training.md}}
