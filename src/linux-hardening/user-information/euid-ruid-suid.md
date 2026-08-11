# euid, ruid, suid

### Promenljive za identifikaciju korisnika

- **`ruid`**: **real user ID** označava korisnika koji je pokrenuo proces.<sup>[[1]](#references)</sup>
- **`euid`**: Poznat kao **effective user ID**, predstavlja identitet korisnika koji sistem koristi za utvrđivanje privilegija procesa. Uobičajeno, `euid` odgovara vrednosti `ruid`, osim u slučajevima kao što je izvršavanje SetUID binarnog fajla (kada se poštuje set-user-ID tranzicija), gde `euid` preuzima identitet vlasnika fajla i time dobija određene operativne dozvole.<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: Ovaj **saved user ID** je ključan kada proces sa visokim privilegijama (obično pokrenut kao root) treba privremeno da se odrekne svojih privilegija radi izvršavanja određenih zadataka, a zatim kasnije ponovo preuzme svoj početni povišeni status.<sup>[[1]](#references)</sup>

#### Važna napomena

Neprivilegovani proces može da izmeni svoj `euid` samo tako da odgovara trenutnom `ruid`, `euid` ili `suid`.<sup>[[3]](#references)</sup>

### Razumevanje set\*uid funkcija

- **`setuid`**: Suprotno početnim pretpostavkama, `setuid` postavlja `euid` procesa koji poziva funkciju. Za privilegovani proces takođe postavlja `ruid` i `suid` na navedenog korisnika; nakon što se svi ID-jevi postave na root, proces ne može ponovo da preuzme prethodni identitet koristeći `setuid`. Detaljni uvid dostupan je na [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** i **`setresuid`**: `setreuid` menja `ruid` i `euid`, dok `setresuid` menja sva tri ID-ja. Za neprivilegovani proces, `setresuid` ograničava svaku ciljnu vrednost na trenutni `ruid`, `euid` ili `suid`; `setreuid` ograničava `euid` na te vrednosti, a `ruid` na trenutni `ruid` ili `euid`. Proces sa `CAP_SETUID` može da dodeli proizvoljne vrednosti ID-jevima koje podržava svaki poziv. Više informacija dostupno je na [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) i [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Ove funkcionalnosti nisu osmišljene kao bezbednosni mehanizam, već da omoguće predviđeni operativni tok, na primer kada program usvaja identitet drugog korisnika promenom svog effective user ID-ja.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Važno je napomenuti da privilegovani poziv `setuid` može da postavi sva tri ID-ja, dok `setreuid` i `setresuid` pružaju različite kontrole; razlikovanje ovih funkcija ključno je za razumevanje tranzicija user ID-ja.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Mehanizmi izvršavanja programa u Linuxu

#### **`execve` System Call**

- **Funkcionalnost**: `execve` pokreće program određen prvim argumentom. Prima dva niza argumenata, `argv` za argumente i `envp` za okruženje.<sup>[[5]](#references)</sup>
- **Ponašanje**: Zadržava memorijski prostor pozivaoca, ali osvežava stack, heap i data segmente. Kod programa zamenjuje se novim programom.<sup>[[5]](#references)</sup>
- **Očuvanje user ID-ja**:
- `ruid` i dodatni group ID-jevi ostaju nepromenjeni.<sup>[[5]](#references)</sup>
- `euid` obično ostaje nepromenjen, ali može da se promeni ako novi program ima postavljen SetUID bit.<sup>[[5]](#references)</sup>
- `suid` se nakon izvršavanja ažurira iz vrednosti `euid`.<sup>[[5]](#references)</sup>
- **Dokumentacija**: Detaljne informacije dostupne su na [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **`system` Function**

- **Funkcionalnost**: Za razliku od `execve`, `system` se ponaša kao da kreira child process koristeći `fork` i izvršava komandu unutar tog child process-a koristeći `execl`.<sup>[[6]](#references)</sup>
- **Izvršavanje komande**: Izvršava komandu putem `sh` koristeći `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.<sup>[[6]](#references)</sup>
- **Ponašanje**: Pošto je `execl` poziv iz `exec` familije, ponaša se slično kao `execve`, ali u kontekstu novog child process-a.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Dokumentacija**: Dodatni uvid može se dobiti na [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).<sup>[[6]](#references)</sup>

#### **Ponašanje `bash` i `sh` sa SUID-om**

- **`bash`**:
- Ima opciju `-p` koja utiče na način tretiranja `euid` i `ruid`.<sup>[[7]](#references)</sup>
- Bez opcije `-p`, `bash` postavlja `euid` na `ruid` ako se oni na početku razlikuju.<sup>[[7]](#references)</sup>
- Sa opcijom `-p`, početni `euid` se očuvava.<sup>[[7]](#references)</sup>
- Više detalja dostupno je na [`bash` man page](https://linux.die.net/man/1/bash).<sup>[[7]](#references)</sup>
- **`sh`**:
- POSIX `sh` ne definiše Bash-style opciju `-p` za očuvanje privilegija.<sup>[[8]](#references)</sup>
- Njegova POSIX lista opcija uključuje `-i`, koja bira interactive mode i može biti odbijena kada se realni i effective ID razlikuju.<sup>[[8]](#references)</sup>
- Dodatne informacije dostupne su na [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).<sup>[[8]](#references)</sup>

Ovi mehanizmi, različiti po načinu rada, pružaju širok raspon opcija za izvršavanje programa i prelazak između njih, uz specifične nijanse u načinu upravljanja i očuvanja user ID-jeva.

### Testiranje ponašanja user ID-jeva pri izvršavanju

Primeri su preuzeti sa https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail; pogledajte ga za dodatne informacije.<sup>[[1]](#references)</sup>

#### Slučaj 1: Korišćenje `setuid` sa `system`

**Cilj**: Razumevanje uticaja `setuid` u kombinaciji sa `system` i `bash` kao `sh`.

**C kod**:
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
**Kompilacija i dozvole:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

- `ruid` i `euid` počinju kao 99 (nobody), odnosno 1000 (frank).
- U ovom neprivilegovanom kontekstu, `setuid(1000)` ostavlja `ruid` na 99, a `euid` na 1000.<sup>[[1]](#references)</sup>
- `system` izvršava `/bin/bash -c id` zbog symlink-a sa sh na bash.
- `bash`, bez opcije `-p`, prilagođava `euid` tako da odgovara vrednosti `ruid`, što dovodi do toga da oba budu 99 (nobody).<sup>[[1]](#references)</sup>

#### Slučaj 2: Korišćenje setreuid sa system

**C kod:**
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
**Kompilacija i dozvole:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Izvršavanje i rezultat:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

- `setreuid` postavlja i ruid i euid na 1000.
- `system` poziva bash, koji održava ID-jeve korisnika zbog njihove jednakosti, praktično radeći kao frank.<sup>[[1]](#references)</sup>

#### Slučaj 3: Korišćenje setuid sa execve

Cilj: Istraživanje interakcije između setuid i execve.
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
**Izvršavanje i rezultat:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

- `ruid` ostaje 99, ali se `euid` postavlja na 1000, u skladu sa efektom setuid-a.<sup>[[1]](#references)</sup>

**C Code Example 2 (Pozivanje Bash-a):**
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
**Izvršavanje i rezultat:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

- Iako je `euid` postavljen na 1000 pomoću `setuid`, `bash` resetuje euid na `ruid` (99) zbog odsustva opcije `-p`.<sup>[[1]](#references)</sup>

**Primer C koda 3 (Korišćenje bash -p):**
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
**Izvršavanje i rezultat:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [SetUID zečja rupa - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - man stranica za setuid](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - man stranica za setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - man stranica za setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - man stranica za execve](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - man stranica za system](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - man stranica za bash](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - POSIX sh man stranica](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
