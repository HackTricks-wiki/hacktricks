# Abuso dei moduli del kernel e di modprobe

{{#include ../../banners/hacktricks-training.md}}

## Errori di configurazione del kernel module e del caricamento dei moduli

Il supporto ai moduli del kernel è un'area ad alto impatto durante la revisione per l'escalation dei privilegi Linux. Non considerare ogni messaggio relativo a un modulo non firmato come sfruttabile di per sé, ma usalo per rispondere a domande pratiche.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- L'utente attuale può caricare moduli tramite `sudo`, capabilities o un percorso helper scrivibile?
- Il caricamento dei moduli è ancora abilitato?
- L'applicazione delle firme dei moduli è disabilitata?
- Le directory dei moduli o i file dei moduli sono scrivibili?
- È possibile leggere i log del kernel per confermare quanto accaduto?

Il triage iniziale include i seguenti controlli dello stato dei moduli, delle firme, del logging e dell'albero dei moduli.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Interpretazione:

- `modules_disabled=1` significa che i moduli non possono essere né caricati né scaricati, e il valore non può essere reimpostato a `0` fino al reboot.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` nella kernel command line o `CONFIG_MODULE_SIG_FORCE=y` richiede moduli firmati validamente; in caso contrario, i moduli non firmati possono essere caricati e possono taintare il kernel.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` non impone alcuna restrizione su `dmesg`; quando è impostato su `1`, l'accesso richiede `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- I path scrivibili sotto `/lib/modules/$(uname -r)/` sono pericolosi perché `modprobe` cerca in quell'albero e nei relativi dati delle dipendenze durante il caricamento dei moduli.<sup>[[8]](#references)</sup>

### Caricamento di un modulo e lettura dell'output del kernel

Se si dispone dell'autorizzazione legittima per caricare un modulo locale, `insmod` inserisce l'esatto file `.ko` fornito. La funzione init del modulo viene eseguita come parte del caricamento e i messaggi scritti con `printk()` vengono inviati al kernel log buffer, che normalmente viene letto con `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Un workflow minimo di revisione utilizza `modinfo` per esaminare i metadati, `insmod` e `rmmod` per caricare e rimuovere un modulo, `lsmod` per confermare lo stato di caricamento e `dmesg` per esaminare i kernel log.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Se `sudo -l` consente di eseguire `insmod`, `modprobe` o un wrapper che li utilizza, consideralo critico: `sudo -l` elenca i privilegi dell'utente che invoca il comando e il caricamento di un modulo del kernel richiede `CAP_SYS_MODULE`.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` consentito tramite Sudo

Una regola Sudo che consente a un utente di eseguire `insmod` non è paragonabile alla possibilità di usare un normale helper amministrativo. Il codice di inizializzazione del modulo viene eseguito come parte dell'inserimento, quindi la domanda pratica durante la revisione è se questo utente possa scegliere o modificare il modulo da caricare.<sup>[[3]](#references)</sup>

Il seguente flusso di revisione generico ripete questi controlli di ispezione, caricamento, stato, log e rimozione per un modulo candidato.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Se l'utente può fornire un file `.ko` arbitrario, in una valutazione autorizzata la regola deve essere considerata come una compromissione completa del sistema. Un pattern operativo più sicuro consiste nell'evitare di delegare il caricamento dei moduli tramite sudo; se è inevitabile, limitare il percorso esatto, la proprietà, i permessi, la policy di firma e il workflow di rimozione.<sup>[[3]](#references)[[10]](#references)</sup>

Per un pattern innocuo di compilazione di moduli in un lab controllato, di seguito sono mostrati un sorgente minimale e un Makefile; la forma `make -C /lib/modules/$(uname -r)/build M=$PWD` segue il workflow kbuild documentato dal kernel per i moduli esterni.<sup>[[5]](#references)[[7]](#references)</sup>
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
Compila e carica solo in un laboratorio autorizzato; kbuild compila il modulo esterno e i comandi di caricamento/rimozione invocano le interfacce dei moduli del kernel.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Controlli di abuse di `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` identifica l'helper userspace che il kernel esegue per le richieste di autoload dei moduli; questo sysctl influisce sull'autoloading, non sull'inserimento esplicito dei moduli. Se un attacker può modificarlo impostandolo sul percorso di un eseguibile scrivibile e attivare una richiesta di modulo, quell'helper diventa un percorso privilegiato per l'esecuzione di codice.<sup>[[1]](#references)</sup>

Controlla il percorso dell'helper corrente tramite l'interfaccia sysctl del kernel e verifica ownership e modalità del target.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Verifica se i sysctl, le regole sudo delegate o le file capabilities possono essere influenzati.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Il seguente pattern, destinato esclusivamente ai lab, modifica il percorso dell'helper e attiva una richiesta documentata di autoloading del modulo; usalo solo su un sistema isolato e autorizzato.<sup>[[1]](#references)</sup>

Sui kernel Linux attuali, non usare un eseguibile sconosciuto come trigger generico: il module autoloading legacy dei formati binari personalizzati è stato rimosso in Linux 6.14, mentre la documentazione del kernel identifica un tipo di filesystem sconosciuto come percorso per una richiesta di module autoloading.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Sui sistemi hardenizzati, questa operazione dovrebbe fallire quando le autorizzazioni impediscono le scritture non privilegiate su `kernel.modprobe`, il percorso dell'helper non è scrivibile o il caricamento automatico dei moduli è disabilitato.<sup>[[1]](#references)</sup>

### Analisi di `/lib/modules` scrivibile

Le directory dei moduli scrivibili possono consentire la sostituzione di moduli, l'installazione di moduli malevoli o l'abuso del caricamento automatico, a seconda di come viene successivamente invocato `modprobe`; `modprobe` cerca in `/lib/modules/$(uname -r)` e utilizza i relativi dati sulle dipendenze durante la risoluzione dei moduli.<sup>[[8]](#references)</sup>

Esaminare i file dei moduli scrivibili e i metadati delle dipendenze/alias nell'albero dei moduli della release del kernel attiva.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Se trovi contenuto di moduli scrivibile, esamina come `modprobe` risolve le dipendenze e come `modinfo` restituisce i metadati dei moduli.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Note difensive:

- Mantieni `/lib/modules` di proprietà di `root:root` e non scrivibile dagli utenti.<sup>[[8]](#references)</sup>
- Imposta `kernel.modules_disabled=1` dopo l'avvio, quando possibile dal punto di vista operativo.<sup>[[1]](#references)</sup>
- Applica la firma dei moduli sui sistemi che richiedono moduli caricabili.<sup>[[2]](#references)</sup>
- Monitora le scritture su `/proc/sys/kernel/modprobe`, `/lib/modules` e l'esecuzione imprevista di `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)</sup>

## References

- [1] [Documentazione per /proc/sys/kernel/ — Documentazione del kernel Linux](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Funzionalità di firma dei moduli del kernel — Documentazione del kernel Linux](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Nozioni di base sui driver — Documentazione del kernel Linux](https://docs.kernel.org/driver-api/basics.html)
- [6] [Registrazione dei messaggi con printk — Documentazione del kernel Linux](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Compilazione di moduli esterni — Documentazione del kernel Linux](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Unione del tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
{{#include ../../banners/hacktricks-training.md}}
