# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### Gebruiker Identifikasie Veranderlikes

- **`ruid`**: Die **werklike gebruiker ID** dui die gebruiker aan wat die proses begin het.
- **`euid`**: Bekend as die **effektiewe gebruiker ID**, dit verteenwoordig die gebruiker identiteit wat deur die stelsel gebruik word om proses regte te bepaal. Gewoonlik spieël `euid` `ruid`, behalwe in gevalle soos 'n SetUID binêre uitvoering, waar `euid` die lêer eienaar se identiteit aanneem, wat spesifieke operasionele toestemmings toeken.
- **`suid`**: Hierdie **bespaarde gebruiker ID** is belangrik wanneer 'n hoë-regte proses (gewoonlik wat as root loop) tydelik sy regte moet prysgee om sekere take uit te voer, net om later sy aanvanklike verhoogde status te herwin.

#### Belangrike Nota

'n Proses wat nie onder root werk nie, kan slegs sy `euid` aanpas om te ooreenstem met die huidige `ruid`, `euid`, of `suid`.

### Verstaan set\*uid Funksies

- **`setuid`**: Teen die aanvanklike aannames, verander `setuid` hoofsaaklik `euid` eerder as `ruid`. Spesifiek, vir bevoorregte prosesse, pas dit `ruid`, `euid`, en `suid` aan met die gespesifiseerde gebruiker, dikwels root, wat hierdie ID's effektief versterk as gevolg van die oorheersende `suid`. Gedetailleerde insigte kan gevind word in die [setuid man bladsy](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** en **`setresuid`**: Hierdie funksies stel in staat tot die nuanses aanpassing van `ruid`, `euid`, en `suid`. Hulle vermoëns is egter afhanklik van die proses se regte vlak. Vir nie-root prosesse is aanpassings beperk tot die huidige waardes van `ruid`, `euid`, en `suid`. In teenstelling, root prosesse of dié met `CAP_SETUID` vermoë kan arbitrêre waardes aan hierdie ID's toeken. Meer inligting kan verkry word van die [setresuid man bladsy](https://man7.org/linux/man-pages/man2/setresuid.2.html) en die [setreuid man bladsy](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Hierdie funksionaliteite is nie ontwerp as 'n sekuriteitsmeganisme nie, maar om die beoogde operasionele vloei te fasiliteer, soos wanneer 'n program 'n ander gebruiker se identiteit aanneem deur sy effektiewe gebruiker ID te verander.

Opmerklik, terwyl `setuid` 'n algemene keuse mag wees vir regte verhoging na root (aangesien dit al die ID's na root aanpas), is dit belangrik om te onderskei tussen hierdie funksies om gebruikers ID gedrag in verskillende scenario's te verstaan en te manipuleer.

### Program Uitvoeringsmeganismes in Linux

#### **`execve` Stelselsoproep**

- **Funksionaliteit**: `execve` begin 'n program, bepaal deur die eerste argument. Dit neem twee array argumente, `argv` vir argumente en `envp` vir die omgewing.
- **Gedrag**: Dit behou die geheue ruimte van die oproeper maar verfris die stapel, hoop, en data segmente. Die program se kode word vervang deur die nuwe program.
- **Gebruiker ID Bewaring**:
- `ruid`, `euid`, en aanvullende groep ID's bly onveranderd.
- `euid` mag nuanses veranderinge hê as die nuwe program die SetUID bit ingestel het.
- `suid` word opgedateer van `euid` na uitvoering.
- **Dokumentasie**: Gedetailleerde inligting kan gevind word op die [`execve` man bladsy](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **`system` Funksie**

- **Funksionaliteit**: Anders as `execve`, skep `system` 'n kind proses met behulp van `fork` en voer 'n opdrag binne daardie kind proses uit met `execl`.
- **Opdrag Uitvoering**: Voer die opdrag uit via `sh` met `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Gedrag**: Aangesien `execl` 'n vorm van `execve` is, werk dit soortgelyk maar in die konteks van 'n nuwe kind proses.
- **Dokumentasie**: Verdere insigte kan verkry word van die [`system` man bladsy](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Gedrag van `bash` en `sh` met SUID**

- **`bash`**:
- Het 'n `-p` opsie wat beïnvloed hoe `euid` en `ruid` hanteer word.
- Sonder `-p`, stel `bash` `euid` op `ruid` as hulle aanvanklik verskil.
- Met `-p`, word die aanvanklike `euid` behou.
- Meer besonderhede kan gevind word op die [`bash` man bladsy](https://linux.die.net/man/1/bash).
- **`sh`**:
- Besit nie 'n meganisme soortgelyk aan `-p` in `bash` nie.
- Die gedrag rakende gebruikers ID's word nie eksplisiet genoem nie, behalwe onder die `-i` opsie, wat die bewaring van `euid` en `ruid` gelykheid beklemtoon.
- Bykomende inligting is beskikbaar op die [`sh` man bladsy](https://man7.org/linux/man-pages/man1/sh.1p.html).

Hierdie meganismes, wat in hul werking uniek is, bied 'n veelsydige reeks opsies vir die uitvoering en oorgang tussen programme, met spesifieke nuanses in hoe gebruikers ID's bestuur en bewaar word.

### Toetsing van Gebruiker ID Gedrag in Uitvoerings

Voorbeelde geneem van https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, kyk dit vir verdere inligting

#### Geval 1: Gebruik `setuid` met `system`

**Doel**: Verstaan die effek van `setuid` in kombinasie met `system` en `bash` as `sh`.

**C Kode**:
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
**Analise:**

- `ruid` en `euid` begin as 99 (nobody) en 1000 (frank) onderskeidelik.
- `setuid` stel albei op 1000.
- `system` voer `/bin/bash -c id` uit as gevolg van die symlink van sh na bash.
- `bash`, sonder `-p`, pas `euid` aan om met `ruid` te ooreenstem, wat daartoe lei dat albei 99 (nobody) is.

#### Geval 2: Gebruik setreuid met system

**C Kode**:
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
**Analise:**

- `setreuid` stel beide ruid en euid op 1000.
- `system` roep bash aan, wat die gebruikers-ID's behou weens hul gelykheid, en funksioneer effektief as frank.

#### Geval 3: Gebruik van setuid met execve

Doel: Om die interaksie tussen setuid en execve te verken.
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

- `ruid` bly 99, maar euid is op 1000 gestel, in ooreenstemming met setuid se effek.

**C Kode Voorbeeld 2 (Bel Bash):**
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

- Alhoewel `euid` op 1000 gestel is deur `setuid`, stel `bash` euid terug na `ruid` (99) weens die afwesigheid van `-p`.

**C Kode Voorbeeld 3 (Gebruik bash -p):**
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
