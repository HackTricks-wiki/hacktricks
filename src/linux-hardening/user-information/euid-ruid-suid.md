# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### Gebruikeridentifikasie-veranderlikes

- **`ruid`**: Die **werklike gebruiker-ID** dui die gebruiker aan wat die proses geïnisieer het.
- **`euid`**: Dit staan bekend as die **effektiewe gebruiker-ID** en verteenwoordig die gebruikeridentiteit wat deur die stelsel gebruik word om prosesvoorregte vas te stel. Oor die algemeen weerspieël `euid` die waarde van `ruid`, behalwe in gevalle soos die uitvoering van ’n SetUID binary, waar `euid` die identiteit van die lêereienaar aanneem en sodoende spesifieke operasionele toestemmings verleen.
- **`suid`**: Hierdie **gestoorde gebruiker-ID** is belangrik wanneer ’n proses met hoë voorregte (gewoonlik as root) sy voorregte tydelik moet prysgee om sekere take uit te voer, en later sy oorspronklike verhoogde status moet herwin.

#### Belangrike Nota

’n Proses wat nie onder root bedryf word nie, kan sy `euid` slegs verander om met die huidige `ruid`, `euid` of `suid` ooreen te stem.

### Verstaan set\*uid-funksies

- **`setuid`**: In teenstelling met aanvanklike aannames, wysig `setuid` hoofsaaklik `euid` eerder as `ruid`. Vir bevoorregte prosesse stel dit spesifiek `ruid`, `euid` en `suid` op die gespesifiseerde gebruiker, dikwels root, wat hierdie ID’s effektief vaslê weens die oorheersende `suid`. Gedetailleerde insigte is beskikbaar op die [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** en **`setresuid`**: Hierdie funksies laat die genuanseerde aanpassing van `ruid`, `euid` en `suid` toe. Hul vermoëns hang egter van die proses se voorregsvlak af. Vir nie-root-prosesse is wysigings beperk tot die huidige waardes van `ruid`, `euid` en `suid`. Daarteenoor kan root-prosesse of prosesse met die `CAP_SETUID`-vermoë arbitrêre waardes aan hierdie ID’s toewys. Meer inligting is beskikbaar op die [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) en die [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Hierdie funksionaliteit is nie as ’n sekuriteitsmeganisme ontwerp nie, maar om die beoogde operasionele vloei te fasiliteer, soos wanneer ’n program ’n ander gebruiker se identiteit aanneem deur sy effektiewe gebruiker-ID te verander.

Hoewel `setuid` algemeen gebruik kan word vir privilege elevation na root (omdat dit alle ID’s op root stel), is dit belangrik om tussen hierdie funksies te onderskei om gebruiker-ID-gedrag in verskillende scenario’s te verstaan en te manipuleer.

### Programuitvoeringsmeganismes in Linux

#### **`execve` System Call**

- **Funksionaliteit**: `execve` begin ’n program wat deur die eerste argument bepaal word. Dit aanvaar twee skikking-argumente: `argv` vir argumente en `envp` vir die omgewing.
- **Gedrag**: Dit behou die oproeper se geheuespasie, maar verfris die stack, heap en data-segmente. Die program se kode word deur die nuwe program vervang.
- **Bewaring van gebruiker-ID’s**:
- `ruid`, `euid` en aanvullende groep-ID’s bly onveranderd.
- `euid` kan genuanseerde veranderinge ondergaan indien die nuwe program die SetUID-bit gestel het.
- `suid` word ná uitvoering vanaf `euid` opgedateer.
- **Dokumentasie**: Gedetailleerde inligting is beskikbaar op die [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **`system` Function**

- **Funksionaliteit**: Anders as `execve`, skep `system` ’n child process met behulp van `fork` en voer ’n opdrag binne daardie child process uit met behulp van `execl`.
- **Opdraguitvoering**: Voer die opdrag via `sh` uit met `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Gedrag**: Omdat `execl` ’n vorm van `execve` is, werk dit soortgelyk, maar binne die konteks van ’n nuwe child process.
- **Dokumentasie**: Verdere insigte is beskikbaar op die [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Gedrag van `bash` en `sh` met SUID**

- **`bash`**:
- Het ’n `-p`-opsie wat beïnvloed hoe `euid` en `ruid` hanteer word.
- Sonder `-p` stel `bash` `euid` op `ruid` indien hulle aanvanklik verskil.
- Met `-p` word die aanvanklike `euid` behou.
- Meer besonderhede is beskikbaar op die [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- Beskik nie oor ’n meganisme soortgelyk aan `-p` in `bash` nie.
- Die gedrag rakende gebruiker-ID’s word nie uitdruklik genoem nie, behalwe onder die `-i`-opsie, wat die behoud van gelykheid tussen `euid` en `ruid` beklemtoon.
- Bykomende inligting is beskikbaar op die [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

Hierdie meganismes, wat van mekaar verskil in hul werking, bied ’n veelsydige reeks opsies vir die uitvoering van en oorgang tussen programme, met spesifieke nuanses in hoe gebruiker-ID’s bestuur en behou word.

### Toets van gebruiker-ID-gedrag tydens uitvoerings

Voorbeelde is geneem van https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail; raadpleeg dit vir verdere inligting

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
- `setuid` stel albei op 1000.
- `system` voer `/bin/bash -c id` uit weens die symbolic link van sh na bash.
- `bash`, sonder `-p`, pas `euid` aan om by `ruid` te pas, wat albei 99 (nobody) maak.

#### Geval 2: Gebruik van setreuid met system

**C-kode**:
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
**Kompilering en Toestemmings:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Uitvoering en Resultaat:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ontleding:**

- `setreuid` stel beide ruid en euid op 1000.
- `system` roep bash aan, wat die gebruiker-ID's behou omdat hulle gelyk is, en effektief as frank werk.

#### Geval 3: Using setuid with execve

Doel: Ondersoek die interaksie tussen setuid en execve.
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

- `ruid` bly 99, maar `euid` word op 1000 gestel, in ooreenstemming met `setuid` se effek.

**C-kodevoorbeeld 2 (Roep Bash aan):**
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

- Hoewel `euid` deur `setuid` op 1000 gestel word, stel `bash` `euid` terug na `ruid` (99) weens die afwesigheid van `-p`.

**C-kodevoorbeeld 3 (Gebruik van bash -p):**
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
uid=99(nobody) gid=99(nobody) euid=100
```
## Verwysings

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
