# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Variabili di identificazione dell'utente

- **`ruid`**: il **real user ID** indica l'utente che ha avviato il processo.<sup>[[1]](#references)</sup>
- **`euid`**: noto come **effective user ID**, rappresenta l'identità utente utilizzata dal sistema per determinare i privilegi del processo. Generalmente, `euid` corrisponde a `ruid`, tranne in casi come l'esecuzione di un binario SetUID (quando viene applicata la transizione set-user-ID), in cui `euid` assume l'identità del proprietario del file, garantendo così specifiche autorizzazioni operative.<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: questo **saved user ID** è fondamentale quando un processo con privilegi elevati (in genere eseguito come root) deve rinunciare temporaneamente ai propri privilegi per eseguire determinate attività, per poi recuperare successivamente il proprio stato iniziale elevato.<sup>[[1]](#references)</sup>

#### Nota importante

Un processo senza privilegi può modificare il proprio `euid` solo affinché corrisponda all'attuale `ruid`, `euid` o `suid`.<sup>[[3]](#references)</sup>

### Comprendere le funzioni set\*uid

- **`setuid`**: contrariamente a quanto si potrebbe inizialmente pensare, `setuid` imposta l'`euid` del processo chiamante. Per un processo privilegiato, imposta inoltre `ruid` e `suid` sull'utente specificato; dopo che tutti gli ID sono stati impostati su root, il processo non può recuperare un'identità precedente utilizzando `setuid`. Informazioni dettagliate sono disponibili nella [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** e **`setresuid`**: `setreuid` modifica `ruid` ed `euid`, mentre `setresuid` modifica tutti e tre gli ID. Per un processo senza privilegi, `setresuid` limita ogni valore di destinazione all'attuale `ruid`, `euid` o `suid`; `setreuid` limita `euid` a tali valori e `ruid` all'attuale `ruid` o `euid`. Un processo con `CAP_SETUID` può assegnare valori arbitrari agli ID supportati da ciascuna chiamata. Ulteriori informazioni sono disponibili nella [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) e nella [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Queste funzionalità non sono progettate come meccanismo di sicurezza, ma per facilitare il flusso operativo previsto, ad esempio quando un programma assume l'identità di un altro utente modificando il proprio effective user ID.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

È importante notare che una chiamata privilegiata a `setuid` può assegnare tutti e tre gli ID, mentre `setreuid` e `setresuid` espongono controlli differenti; distinguere queste funzioni è essenziale per comprendere le transizioni degli user ID.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Meccanismi di esecuzione dei programmi in Linux

#### **System Call `execve`**

- **Funzionalità**: `execve` avvia un programma, determinato dal primo argomento. Accetta due argomenti array, `argv` per gli argomenti ed `envp` per l'ambiente.<sup>[[5]](#references)</sup>
- **Comportamento**: conserva lo spazio di memoria del chiamante, ma aggiorna stack, heap e segmenti dati. Il codice del programma viene sostituito dal nuovo programma.<sup>[[5]](#references)</sup>
- **Conservazione degli User ID**:
- `ruid` e gli ID dei gruppi supplementari rimangono invariati.<sup>[[5]](#references)</sup>
- `euid` normalmente non cambia, ma può cambiare se il nuovo programma ha il bit SetUID impostato.<sup>[[5]](#references)</sup>
- `suid` viene aggiornato a partire da `euid` dopo l'esecuzione.<sup>[[5]](#references)</sup>
- **Documentazione**: informazioni dettagliate sono disponibili nella [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **Funzione `system`**

- **Funzionalità**: a differenza di `execve`, `system` si comporta come se creasse un processo figlio utilizzando `fork` ed eseguisse il comando all'interno di tale processo figlio tramite `execl`.<sup>[[6]](#references)</sup>
- **Esecuzione del comando**: esegue il comando tramite `sh` con `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.<sup>[[6]](#references)</sup>
- **Comportamento**: poiché `execl` è una chiamata della famiglia `exec`, opera in modo analogo a `execve`, ma nel contesto di un nuovo processo figlio.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Documentazione**: ulteriori informazioni sono disponibili nella [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).<sup>[[6]](#references)</sup>

#### **Comportamento di `bash` e `sh` con SUID**

- **`bash`**:
- Dispone di un'opzione `-p` che influenza il modo in cui vengono trattati `euid` e `ruid`.<sup>[[7]](#references)</sup>
- Senza `-p`, `bash` imposta `euid` su `ruid` se inizialmente sono diversi.<sup>[[7]](#references)</sup>
- Con `-p`, viene mantenuto l'`euid` iniziale.<sup>[[7]](#references)</sup>
- Ulteriori dettagli sono disponibili nella [`bash` man page](https://linux.die.net/man/1/bash).<sup>[[7]](#references)</sup>
- **`sh`**:
- POSIX `sh` non definisce un'opzione di conservazione dei privilegi in stile Bash `-p`.<sup>[[8]](#references)</sup>
- Il suo elenco di opzioni POSIX include `-i`, che seleziona la modalità interattiva e può essere rifiutata quando gli ID reali ed effettivi sono diversi.<sup>[[8]](#references)</sup>
- Ulteriori informazioni sono disponibili nella [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).<sup>[[8]](#references)</sup>

Questi meccanismi, distinti nel loro funzionamento, offrono una gamma versatile di opzioni per eseguire programmi e passare da un programma all'altro, con specifiche peculiarità nella gestione e nella conservazione degli user ID.

### Test dei comportamenti degli User ID nelle esecuzioni

Esempi tratti da https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail; consultalo per ulteriori informazioni.<sup>[[1]](#references)</sup>

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
**Compilazione e permessi:**
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
- In questo contesto non privilegiato, `setuid(1000)` lascia `ruid` a 99 ed `euid` a 1000.<sup>[[1]](#references)</sup>
- `system` esegue `/bin/bash -c id` a causa del symlink da sh a bash.
- `bash`, senza `-p`, adatta `euid` in modo che corrisponda a `ruid`, facendo sì che entrambi siano 99 (nobody).<sup>[[1]](#references)</sup>

#### Caso 2: Utilizzo di setreuid con system

**Codice C:**
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
**Compilazione e permessi:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Esecuzione e risultato:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analisi:**

- `setreuid` imposta sia ruid che euid su 1000.
- `system` invoca bash, che mantiene gli ID utente grazie alla loro uguaglianza, operando di fatto come frank.<sup>[[1]](#references)</sup>

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

- `ruid` rimane 99, ma `euid` viene impostato su 1000, in linea con l'effetto di setuid.<sup>[[1]](#references)</sup>

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
**Esecuzione e risultato:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analisi:**

- Sebbene `euid` sia impostato su 1000 da `setuid`, `bash` reimposta `euid` su `ruid` (99) a causa dell'assenza di `-p`.<sup>[[1]](#references)</sup>

**Esempio di codice C 3 (Utilizzo di bash -p):**
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
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - pagina man di setuid](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - pagina man di setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - pagina man di setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - pagina man di execve](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - pagina man di system](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - pagina man di bash](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - pagina man di POSIX sh](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
