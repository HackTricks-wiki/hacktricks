# Abuso dei Kernel Modules e di modprobe

{{#include ../../banners/hacktricks-training.md}}

## Misconfigurazioni dei Kernel modules e del caricamento dei moduli

Il supporto ai Kernel modules è un'area ad alto impatto durante la review di privilege escalation su Linux. Non considerare ogni messaggio relativo a un modulo non firmato come sfruttabile di per sé, ma usalo per rispondere a domande pratiche:

- L'utente corrente può caricare moduli tramite `sudo`, capabilities o un helper path scrivibile?
- Il caricamento dei moduli è ancora abilitato?
- L'enforcement della firma dei moduli è disabilitato?
- Le directory dei moduli o i file dei moduli sono scrivibili?
- È possibile leggere i kernel logs per confermare cosa è successo?

Triage rapido:
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
cat /proc/sys/kernel/module_sig_enforce 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Interpretazione:

- `modules_disabled=1` significa che non è possibile caricare nuovi moduli fino al riavvio.
- `module_sig_enforce=1` di solito blocca i moduli non firmati.
- `dmesg_restrict=0` consente agli utenti non privilegiati di leggere i log del kernel su molti sistemi.
- I percorsi scrivibili sotto `/lib/modules/$(uname -r)/` sono pericolosi perché la ricerca e il caricamento automatico dei moduli possono considerare attendibile quella struttura.

### Caricamento di un modulo e lettura dell'output del kernel

Se disponi dell'autorizzazione legittima per caricare un modulo locale, `insmod` inserisce l'esatto file `.ko` fornito. La funzione init del modulo viene eseguita immediatamente e i messaggi scritti con `printk()` vengono visualizzati nei log del kernel.

Workflow minimo per ambienti di revisione o laboratorio:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Se `sudo -l` consente di eseguire `insmod`, `modprobe` o un wrapper che li utilizza, consideralo critico:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` consentito da sudo

Una regola sudo che consente a un utente di eseguire `insmod` non è paragonabile alla possibilità di eseguire un normale helper amministrativo. Il codice di inizializzazione del modulo viene eseguito nel contesto del kernel non appena il file `.ko` viene inserito, quindi la domanda pratica durante la revisione è: "questo utente può scegliere o modificare il modulo che viene caricato?"

Flusso di revisione generico:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Se l'utente può fornire un file `.ko` arbitrario, in un assessment autorizzato la regola dovrebbe essere considerata come una compromissione completa del sistema. Un approccio operativo più sicuro consiste nell'evitare di delegare il caricamento dei moduli tramite sudo; se è inevitabile, limitare il percorso esatto, la proprietà, i permessi, la policy di firma e il workflow di rimozione.

Per un pattern innocuo di compilazione dei moduli in un laboratorio controllato, un sorgente minimo e un Makefile possono essere strutturati come segue:
```c
#include <linux/module.h>
#include <linux/kernel.h>

static int __init demo_init(void) {
printk(KERN_INFO "demo module loaded\n");
return 0;
}

static void __exit demo_exit(void) {
printk(KERN_INFO "demo module unloaded\n");
}

module_init(demo_init);
module_exit(demo_exit);
MODULE_LICENSE("GPL");
```

```makefile
obj-m += demo.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
Compila e carica solo in un laboratorio autorizzato:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Controlli sull'abuso di `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` controlla l'helper userspace invocato dal kernel quando necessita di assistenza per il caricamento dei moduli. Se un attacker può modificarlo impostandolo su un percorso di un eseguibile scrivibile e attivare un formato binario sconosciuto o un altro percorso di richiesta di moduli, può diventare una modalità per ottenere code execution come root.

Controlla l'helper corrente:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Verifica se puoi influenzarlo:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Pattern generico esclusivamente per laboratorio:
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger an unknown executable format so the kernel attempts helper logic
printf '\\xff\\xff\\xff\\xff' > /tmp/unknown
chmod +x /tmp/unknown
/tmp/unknown 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Sui sistemi hardened, questo dovrebbe fallire perché gli utenti non privilegiati non possono scrivere in `kernel.modprobe`, il percorso dell'helper non è scrivibile oppure i percorsi di caricamento dei moduli sono bloccati.

### Verifica di `/lib/modules` scrivibile

Le directory dei moduli scrivibili possono consentire la sostituzione dei moduli, il posizionamento di moduli malevoli o l'abuso dell'auto-load, a seconda di come viene successivamente invocato `modprobe`.

Esamina le posizioni scrivibili:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Se trovi contenuto di moduli scrivibile, verifica come vengono individuati i moduli:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Note difensive:

- Mantieni `/lib/modules` di proprietà di `root:root` e non scrivibile dagli utenti.
- Imposta `kernel.modules_disabled=1` dopo l'avvio, quando possibile dal punto di vista operativo.
- Imposta la verifica delle firme dei moduli sui sistemi che richiedono moduli caricabili.
- Monitora le scritture su `/proc/sys/kernel/modprobe`, `/lib/modules` e l'esecuzione imprevista di `insmod`/`modprobe`.
{{#include ../../banners/hacktricks-training.md}}
