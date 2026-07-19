# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### Variabili di identificazione dell'utente

- **`ruid`**: il **real user ID** indica l'utente che ha avviato il processo.
- **`euid`**: noto come **effective user ID**, rappresenta l'identità dell'utente utilizzata dal sistema per determinare i privilegi del processo. Generalmente, `euid` corrisponde a `ruid`, tranne in casi come l'esecuzione di un binario SetUID, in cui `euid` assume l'identità del proprietario del file, concedendo così specifiche autorizzazioni operative.
- **`suid`**: questo **saved user ID** è fondamentale quando un processo con privilegi elevati (in genere eseguito come root) deve abbandonare temporaneamente i propri privilegi per eseguire determinate attività, per poi recuperare in seguito il proprio stato iniziale con privilegi elevati.

#### Nota importante

Un processo non eseguito come root può modificare il proprio `euid` solo per renderlo uguale all'attuale `ruid`, `euid` o `suid`.

### Comprendere le funzioni set\*uid

- **`setuid`**: contrariamente a quanto si potrebbe pensare inizialmente, `setuid` modifica principalmente `euid` anziché `ruid`. Nello specifico, per i processi con privilegi, imposta `ruid`, `euid` e `suid` sull'utente specificato, spesso root, rendendo di fatto permanenti questi ID a causa dell'`suid` sovrascritto. Informazioni dettagliate sono disponibili nella [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** e **`setresuid`**: queste funzioni consentono di modificare in modo preciso `ruid`, `euid` e `suid`. Tuttavia, le loro capacità dipendono dal livello di privilegi del processo. Per i processi non-root, le modifiche sono limitate ai valori correnti di `ruid`, `euid` e `suid`. Al contrario, i processi root o quelli con la capability `CAP_SETUID` possono assegnare valori arbitrari a questi ID. Ulteriori informazioni sono disponibili nella [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) e nella [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Queste funzionalità non sono progettate come meccanismo di sicurezza, ma per facilitare il flusso operativo previsto, ad esempio quando un programma adotta l'identità di un altro utente modificando il proprio effective user ID.

In particolare, sebbene `setuid` possa essere una scelta comune per l'elevazione dei privilegi a root (poiché allinea tutti gli ID a root), distinguere tra queste funzioni è fondamentale per comprendere e manipolare il comportamento degli user ID in scenari diversi.

### Meccanismi di esecuzione dei programmi in Linux

#### **System call `execve`**

- **Funzionalità**: `execve` avvia un programma, determinato dal primo argomento. Accetta due array di argomenti, `argv` per gli argomenti ed `envp` per l'ambiente.
- **Comportamento**: conserva lo spazio di memoria del chiamante, ma aggiorna gli segmenti stack, heap e dati. Il codice del programma viene sostituito dal nuovo programma.
- **Conservazione degli User ID**:
- `ruid`, `euid` e gli ID dei gruppi supplementari rimangono invariati.
- `euid` può subire modifiche specifiche se il nuovo programma ha impostato il bit SetUID.
- `suid` viene aggiornato a partire da `euid` dopo l'esecuzione.
- **Documentazione**: informazioni dettagliate sono disponibili nella [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **Funzione `system`**

- **Funzionalità**: a differenza di `execve`, `system` crea un processo figlio usando `fork` ed esegue un comando all'interno di tale processo figlio usando `execl`.
- **Esecuzione del comando**: esegue il comando tramite `sh` con `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Comportamento**: poiché `execl` è una forma di `execve`, opera in modo simile, ma nel contesto di un nuovo processo figlio.
- **Documentazione**: ulteriori informazioni sono disponibili nella [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Comportamento di `bash` e `sh` con SUID**

- **`bash`**:
- Dispone di un'opzione `-p` che influenza il modo in cui vengono gestiti `euid` e `ruid`.
- Senza `-p`, `bash` imposta `euid` su `ruid` se inizialmente sono diversi.
- Con `-p`, viene mantenuto l'`euid` iniziale.
- Ulteriori dettagli sono disponibili nella [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- Non dispone di un meccanismo simile a `-p` in `bash`.
- Il comportamento relativo agli user ID non è menzionato esplicitamente, tranne con l'opzione `-i`, che sottolinea la conservazione dell'uguaglianza tra `euid` e `ruid`.
- Ulteriori informazioni sono disponibili nella [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

Questi meccanismi, distinti nel loro funzionamento, offrono una gamma versatile di opzioni per eseguire e trasferire il controllo tra i programmi, con specifiche particolarità nella gestione e nella conservazione degli user ID.

### Test del comportamento degli User ID nelle esecuzioni

Esempi tratti da https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, consultalo per ulteriori informazioni

#### Caso 1: utilizzo di `setuid` con `system`

**Obiettivo**: comprendere l'effetto di `setuid` in combinazione con `system` e `bash` come `sh`.

**Codice C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Compilazione e autorizzazioni:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analisi:**

- `ruid` ed `euid` iniziano rispettivamente come 99 (nobody) e 1000 (frank).
- `setuid` li allinea entrambi a 1000.
- `system` esegue `/bin/bash -c id` a causa del symlink da sh a bash.
- `bash`, senza `-p`, modifica `euid` per farlo corrispondere a `ruid`, risultando quindi entrambi 99 (nobody).

#### Caso 2: Utilizzo di setreuid con system

**Codice C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Compilazione e autorizzazioni:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Esecuzione e risultato:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analisi:**

- `setreuid` imposta sia ruid che euid a 1000.
- `system` invoca bash, che mantiene gli user ID grazie alla loro uguaglianza, operando di fatto come frank.

#### Caso 3: Utilizzo di setuid con execve

Obiettivo: Esplorare l'interazione tra setuid ed execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Esecuzione e risultato:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analisi:**

- `ruid` rimane 99, ma `euid` viene impostato su 1000, in linea con l'effetto di setuid.

**Esempio di codice C 2 (Chiamata a Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Esecuzione e Risultato:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analisi:**

- Sebbene `euid` sia impostato su 1000 da `setuid`, `bash` reimposta `euid` su `ruid` (99) a causa dell'assenza di `-p`.

**Esempio di codice C 3 (utilizzando bash -p):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Esecuzione e risultato:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Riferimenti

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
