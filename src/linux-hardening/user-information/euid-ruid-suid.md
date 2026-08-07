# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Gebruikersidentifikasie-veranderlikes

- **`ruid`**: Die **werklike gebruikers-ID** dui die gebruiker aan wat die proses geïnisieer het.
- **`euid`**: Ook bekend as die **effektiewe gebruikers-ID**, verteenwoordig dit die gebruikersidentiteit wat die stelsel gebruik om proses-voorregte vas te stel. Gewoonlik weerspieël `euid` die waarde van `ruid`, behalwe in gevalle soos die uitvoering van ’n SetUID-binary, waar `euid` die lêereienaar se identiteit aanneem en sodoende spesifieke operasionele toestemmings verleen.
- **`suid`**: Hierdie **gestoorde gebruikers-ID** is belangrik wanneer ’n proses met hoë voorregte (tipies as root) sy voorregte tydelik moet prysgee om sekere take uit te voer, en later sy oorspronklike verhoogde status moet herwin.

#### Belangrike Nota

’n Proses wat nie onder root werk nie, kan sy `euid` slegs verander om met die huidige `ruid`, `euid` of `suid` ooreen te stem.

### Verstaan set\*uid-funksies

- **`setuid`**: In teenstelling met aanvanklike aannames, wysig `setuid` hoofsaaklik `euid` eerder as `ruid`. Vir bevoorregte prosesse bring dit spesifiek `ruid`, `euid` en `suid` in ooreenstemming met die gespesifiseerde gebruiker, dikwels root, wat hierdie IDs effektief vaslê weens die oorheersende `suid`. Gedetailleerde inligting is beskikbaar op die [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** en **`setresuid`**: Hierdie funksies maak die genuanseerde aanpassing van `ruid`, `euid` en `suid` moontlik. Hulle vermoëns hang egter van die proses se voorregvlak af. Vir nie-root-prosesse is wysigings beperk tot die huidige waardes van `ruid`, `euid` en `suid`. Daarteenoor kan root-prosesse of prosesse met die `CAP_SETUID`-vermoë arbitrêre waardes aan hierdie IDs toewys. Meer inligting kan verkry word uit die [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) en die [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Hierdie funksionaliteite is nie as ’n sekuriteitsmeganisme ontwerp nie, maar om die beoogde operasionele vloei te fasiliteer, soos wanneer ’n program ’n ander gebruiker se identiteit aanneem deur sy effektiewe gebruikers-ID te verander.

Hoewel `setuid` dikwels gebruik word om voorregte na root te verhoog (aangesien dit alle IDs op root instel), is dit belangrik om tussen hierdie funksies te onderskei om gebruikers-ID-gedrag in verskillende scenario’s te verstaan en te manipuleer.

### Programuitvoeringsmeganismes in Linux

#### **`execve`-stelseloproep**

- **Funksionaliteit**: `execve` begin ’n program wat deur die eerste argument bepaal word. Dit neem twee skikking-argumente, `argv` vir argumente en `envp` vir die omgewing.
- **Gedrag**: Dit behou die oproeper se geheuespasie, maar verfris die stack-, heap- en datas gedeeltes. Die program se kode word deur die nuwe program vervang.
- **Bewaring van gebruikers-ID’s**:
- `ruid`, `euid` en aanvullende groep-ID’s bly onveranderd.
- `euid` kan genuanseerde veranderinge ondergaan indien die nuwe program die SetUID-bit gestel het.
- `suid` word ná uitvoering vanaf `euid` opgedateer.
- **Dokumentasie**: Gedetailleerde inligting is beskikbaar op die [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **`system`-funksie**

- **Funksionaliteit**: Anders as `execve`, skep `system` ’n child process met behulp van `fork` en voer dit ’n command binne daardie child process uit deur `execl` te gebruik.
- **Command-uitvoering**: Voer die command via `sh` uit met `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Gedrag**: Aangesien `execl` ’n vorm van `execve` is, werk dit soortgelyk, maar binne die konteks van ’n nuwe child process.
- **Dokumentasie**: Verdere inligting kan op die [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html) verkry word.

#### **Gedrag van `bash` en `sh` met SUID**

- **`bash`**:
- Het ’n `-p`-opsie wat beïnvloed hoe `euid` en `ruid` hanteer word.
- Sonder `-p` stel `bash` `euid` op `ruid` indien hulle aanvanklik verskil.
- Met `-p` word die aanvanklike `euid` behou.
- Meer besonderhede is beskikbaar op die [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- Beskik nie oor ’n meganisme soortgelyk aan `-p` in `bash` nie.
- Die gedrag rakende gebruikers-ID’s word nie uitdruklik genoem nie, behalwe onder die `-i`-opsie, wat die behoud van gelykheid tussen `euid` en `ruid` beklemtoon.
- Bykomende inligting is beskikbaar op die [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

Hierdie meganismes, wat van mekaar verskil in hul werking, bied ’n veelsydige reeks opsies vir die uitvoering van en oorgang tussen programme, met spesifieke nuanses oor hoe gebruikers-ID’s bestuur en behou word.

### Toetsing van gebruikers-ID-gedrag tydens uitvoerings

Voorbeelde geneem uit https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail; raadpleeg dit vir verdere inligting<sup>[[1]](#references)</sup>

#### Geval 1: Gebruik van `setuid` met `system`

**Doelwit**: Om die uitwerking van `setuid` in kombinasie met `system` en `bash` as `sh` te verstaan.

**C-kode**:
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
**Kompilasie en Toestemmings:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analise:**

- `ruid` en `euid` begin onderskeidelik as 99 (nobody) en 1000 (frank).
- `setuid` bring albei op 1000.
- `system` voer `/bin/bash -c id` uit weens die simboliese skakel van sh na bash.
- `bash`, sonder `-p`, pas `euid` aan om met `ruid` ooreen te stem, wat daartoe lei dat albei 99 (nobody) is.

#### Geval 2: Gebruik van setreuid met system

**C Code**:
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
- `system` roep bash aan, wat die gebruikers-ID's behou weens hul gelykheid, en effektief as frank werk.

#### Geval 3: Using setuid with execve

Doelstelling: Ondersoek die interaksie tussen setuid en execve.
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

**C-kodevoorbeeld 2 (Bash oproep):**
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
**Ontleding:**

- Alhoewel `euid` deur `setuid` op 1000 gestel word, stel `bash` euid terug na `ruid` (99) weens die afwesigheid van `-p`.

**C-kodevoorbeeld 3 (Deur bash -p te gebruik):**
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

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve man page](https://man7.org/linux/man-pages/man2/execve.2.html)

{{#include ../../banners/hacktricks-training.md}}
