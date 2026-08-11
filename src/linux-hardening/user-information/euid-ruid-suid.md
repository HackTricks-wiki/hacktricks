# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Gebruikersidentifikasieveranderlikes

- **`ruid`**: Die **werklike gebruiker-ID** dui die gebruiker aan wat die proses geïnisieer het.<sup>[[1]](#references)</sup>
- **`euid`**: Dit staan bekend as die **effektiewe gebruiker-ID** en verteenwoordig die gebruikeridentiteit wat deur die stelsel gebruik word om prosesvoorregte vas te stel. Oor die algemeen weerspieël `euid` die waarde van `ruid`, behalwe in gevalle soos die uitvoering van 'n SetUID binary (wanneer die set-user-ID-oorgang eerbiedig word), waar `euid` die lêereienaar se identiteit aanneem en sodoende spesifieke operasionele toestemmings verleen.<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: Hierdie **gestoorde gebruiker-ID** is belangrik wanneer 'n proses met hoë voorregte (gewoonlik as root) sy voorregte tydelik moet prysgee om sekere take uit te voer, en later sy oorspronklike verhoogde status moet herwin.<sup>[[1]](#references)</sup>

#### Belangrike nota

'n Onbevoorregte proses kan sy `euid` slegs verander om met die huidige `ruid`, `euid` of `suid` ooreen te stem.<sup>[[3]](#references)</sup>

### Verstaan van set\*uid-funksies

- **`setuid`**: In teenstelling met aanvanklike aannames, stel `setuid` die roepende proses se `euid` in. Vir 'n bevoorregte proses stel dit ook `ruid` en `suid` op die gespesifiseerde gebruiker; nadat alle ID's op root gestel is, kan die proses nie sy vorige identiteit met `setuid` herwin nie. Gedetailleerde insigte is beskikbaar op die [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** en **`setresuid`**: `setreuid` verander `ruid` en `euid`, terwyl `setresuid` al drie ID's verander. Vir 'n onbevoorregte proses beperk `setresuid` elke teiken tot die huidige `ruid`, `euid` of `suid`; `setreuid` beperk `euid` tot daardie waardes en `ruid` tot die huidige `ruid` of `euid`. 'n Proses met `CAP_SETUID` kan arbitrêre waardes aan die ID's toewys wat deur elke oproep ondersteun word. Meer inligting is beskikbaar op die [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) en die [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Hierdie funksionaliteit is nie as 'n sekuriteitsmeganisme ontwerp nie, maar om die beoogde operasionele vloei te fasiliteer, soos wanneer 'n program 'n ander gebruiker se identiteit aanneem deur sy effektiewe gebruiker-ID te verander.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Dit is belangrik dat 'n bevoorregte oproep na `setuid` al drie ID's kan toewys, terwyl `setreuid` en `setresuid` verskillende kontroles bied; die onderskeid tussen hierdie funksies is noodsaaklik om gebruiker-ID-oorgange te verstaan.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Meganismes vir programuitvoering in Linux

#### **`execve` System Call**

- **Funksionaliteit**: `execve` begin 'n program wat deur die eerste argument bepaal word. Dit aanvaar twee skikking-argumente, `argv` vir argumente en `envp` vir die omgewing.<sup>[[5]](#references)</sup>
- **Gedrag**: Dit behou die oproeper se geheuespasie, maar verfris die stack-, heap- en datasegmente. Die program se kode word deur die nuwe program vervang.<sup>[[5]](#references)</sup>
- **Bewaring van gebruiker-ID's**:
- `ruid` en aanvullende groep-ID's bly onveranderd.<sup>[[5]](#references)</sup>
- `euid` bly normaalweg onveranderd, maar kan verander indien die nuwe program die SetUID-bit gestel het.<sup>[[5]](#references)</sup>
- `suid` word ná uitvoering vanaf `euid` opgedateer.<sup>[[5]](#references)</sup>
- **Dokumentasie**: Gedetailleerde inligting is beskikbaar op die [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **`system` Function**

- **Funksionaliteit**: Anders as `execve`, tree `system` op asof dit 'n child process met `fork` skep en die command binne daardie child process met `execl` uitvoer.<sup>[[6]](#references)</sup>
- **Command-uitvoering**: Voer die command via `sh` uit met `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.<sup>[[6]](#references)</sup>
- **Gedrag**: Omdat `execl` 'n oproep uit die `exec`-familie is, werk dit soortgelyk aan `execve`, maar binne die konteks van 'n nuwe child process.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Dokumentasie**: Verdere insigte is beskikbaar op die [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).<sup>[[6]](#references)</sup>

#### **Gedrag van `bash` en `sh` met SUID**

- **`bash`**:
- Het 'n `-p`-opsie wat beïnvloed hoe `euid` en `ruid` hanteer word.<sup>[[7]](#references)</sup>
- Sonder `-p` stel `bash` `euid` op `ruid` indien hulle aanvanklik verskil.<sup>[[7]](#references)</sup>
- Met `-p` word die aanvanklike `euid` behou.<sup>[[7]](#references)</sup>
- Meer besonderhede is beskikbaar op die [`bash` man page](https://linux.die.net/man/1/bash).<sup>[[7]](#references)</sup>
- **`sh`**:
- POSIX `sh` definieer nie 'n Bash-styl `-p`-opsie vir die behoud van voorregte nie.<sup>[[8]](#references)</sup>
- Sy POSIX-opsielys sluit `-i` in, wat interactive mode kies en moontlik verwerp word wanneer die werklike en effektiewe ID's verskil.<sup>[[8]](#references)</sup>
- Bykomende inligting is beskikbaar op die [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).<sup>[[8]](#references)</sup>

Hierdie meganismes, wat in hul werking van mekaar verskil, bied 'n veelsydige reeks opsies vir die uitvoering van en oorgang tussen programme, met spesifieke nuanses oor hoe gebruiker-ID's bestuur en behou word.

### Toetsing van gebruiker-ID-gedrag tydens uitvoerings

Voorbeelde geneem van https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail; raadpleeg dit vir verdere inligting.<sup>[[1]](#references)</sup>

#### Geval 1: Gebruik van `setuid` met `system`

**Doelwit**: Om die uitwerking van `setuid` in kombinasie met `system` en `bash` as `sh` te verstaan.

**C Code**:
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
**Kompilering en Toestemmings:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ontleding:**

- `ruid` en `euid` begin onderskeidelik as 99 (nobody) en 1000 (frank).
- In hierdie onbevoorregte konteks laat `setuid(1000)` `ruid` op 99 en `euid` op 1000.<sup>[[1]](#references)</sup>
- `system` voer `/bin/bash -c id` uit weens die simboliese skakel van sh na bash.
- `bash`, sonder `-p`, pas `euid` aan om met `ruid` ooreen te stem, wat daartoe lei dat albei 99 (nobody) is.<sup>[[1]](#references)</sup>

#### Geval 2: Gebruik van setreuid met system

**C-kode:**
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
**Kompilering en toestemmings:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Uitvoering en resultaat:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ontleding:**

- `setreuid` stel beide ruid en euid op 1000.
- `system` roep bash aan, wat die gebruiker-ID's behou weens hul gelykheid, en effektief as frank werk.<sup>[[1]](#references)</sup>

#### Geval 3: Using setuid with execve

Doelwit: Ondersoek die interaksie tussen setuid en execve.
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
**Uitvoering en Resultaat:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analise:**

- `ruid` bly 99, maar euid word op 1000 gestel, in ooreenstemming met setuid se effek.<sup>[[1]](#references)</sup>

**C Code Example 2 (Bash oproep):**
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
**Uitvoering en Resultaat:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analise:**

- Alhoewel `euid` deur `setuid` op 1000 gestel word, stel `bash` euid terug na `ruid` (99) weens die afwesigheid van `-p`.<sup>[[1]](#references)</sup>

**C-kodevoorbeeld 3 (Gebruik bash -p):**
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
**Uitvoering en Resultaat:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [SetUID Konynsgat - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuid manbladsy](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid manbladsy](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid manbladsy](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve manbladsy](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - system manbladsy](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - bash manbladsy](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - POSIX sh manbladsy](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
