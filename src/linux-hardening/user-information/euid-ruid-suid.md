# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Promenljive za identifikaciju korisnika

- **`ruid`**: **stvarni ID korisnika** označava korisnika koji je pokrenuo proces.<sup>[[1]](#references)</sup>
- **`euid`**: Poznat kao **efektivni ID korisnika**, predstavlja identitet korisnika koji sistem koristi za utvrđivanje privilegija procesa. Uobičajeno je da `euid` bude isti kao `ruid`, osim u slučajevima kao što je izvršavanje SetUID binarne datoteke (kada se poštuje set-user-ID tranzicija), gde `euid` preuzima identitet vlasnika datoteke i time dobija određene operativne dozvole.<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: Ovaj **sačuvani ID korisnika** je ključan kada proces sa visokim privilegijama (obično pokrenut kao root) treba privremeno da se odrekne svojih privilegija radi izvršavanja određenih zadataka, a zatim ponovo preuzme svoj prvobitni povišeni status.<sup>[[1]](#references)</sup>

#### Važna napomena

Neprivilegovani proces može promeniti svoj `euid` samo tako da odgovara trenutnom `ruid`, `euid` ili `suid`.<sup>[[3]](#references)</sup>

### Razumevanje set\*uid funkcija

- **`setuid`**: Suprotno početnim pretpostavkama, `setuid` postavlja `euid` procesa koji ga poziva. Za privilegovani proces, takođe postavlja `ruid` i `suid` na navedenog korisnika; nakon što se svi ID-jevi postave na root, proces ne može ponovo da preuzme prethodni identitet pomoću `setuid`. Detaljni uvidi dostupni su na [setuid man stranici](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** i **`setresuid`**: `setreuid` menja `ruid` i `euid`, dok `setresuid` menja sva tri ID-ja. Za neprivilegovani proces, `setresuid` ograničava svaku ciljnu vrednost na trenutni `ruid`, `euid` ili `suid`; `setreuid` ograničava `euid` na te vrednosti, a `ruid` na trenutni `ruid` ili `euid`. Proces sa `CAP_SETUID` može dodeliti proizvoljne vrednosti ID-jevima koje svaki poziv podržava. Više informacija može se pronaći na [setresuid man stranici](https://man7.org/linux/man-pages/man2/setresuid.2.html) i [setreuid man stranici](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Ove funkcionalnosti nisu osmišljene kao bezbednosni mehanizam, već za podršku predviđenom operativnom toku, na primer kada program preuzima identitet drugog korisnika promenom svog efektivnog ID-ja korisnika.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Važno je napomenuti da privilegovani poziv `setuid` može dodeliti sva tri ID-ja, dok `setreuid` i `setresuid` nude različite kontrole; razlikovanje ovih funkcija ključno je za razumevanje tranzicija ID-ja korisnika.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Mehanizmi izvršavanja programa u Linuxu

#### **`execve` sistemski poziv**

- **Funkcionalnost**: `execve` pokreće program određen prvim argumentom. Prima dva argumenta u obliku nizova: `argv` za argumente i `envp` za okruženje.<sup>[[5]](#references)</sup>
- **Ponašanje**: Zadržava memorijski prostor pozivaoca, ali osvežava stek, hip i segmente podataka. Kod programa zamenjuje se novim programom.<sup>[[5]](#references)</sup>
- **Očuvanje ID-ja korisnika**:
- `ruid` i dopunski ID-jevi grupa ostaju nepromenjeni.<sup>[[5]](#references)</sup>
- `euid` se obično ne menja, ali može da se promeni ako novi program ima postavljen SetUID bit.<sup>[[5]](#references)</sup>
- `suid` se nakon izvršavanja ažurira iz vrednosti `euid`.<sup>[[5]](#references)</sup>
- **Dokumentacija**: Detaljne informacije dostupne su na [`execve` man stranici](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **`system` funkcija**

- **Funkcionalnost**: Za razliku od `execve`, `system` se ponaša kao da kreira child proces pomoću `fork` i izvršava komandu unutar tog child procesa pomoću `execl`.<sup>[[6]](#references)</sup>
- **Izvršavanje komande**: Izvršava komandu preko `sh` pomoću `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.<sup>[[6]](#references)</sup>
- **Ponašanje**: Pošto je `execl` poziv iz `exec` porodice, ponaša se slično kao `execve`, ali u kontekstu novog child procesa.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Dokumentacija**: Dodatni uvidi mogu se dobiti na [`system` man stranici](https://man7.org/linux/man-pages/man3/system.3.html).<sup>[[6]](#references)</sup>

#### **Ponašanje `bash` i `sh` sa SUID-om**

- **`bash`**:
- Ima opciju `-p` koja utiče na način obrade `euid` i `ruid`.<sup>[[7]](#references)</sup>
- Bez opcije `-p`, `bash` postavlja `euid` na `ruid` ako su se inicijalno razlikovali.<sup>[[7]](#references)</sup>
- Sa opcijom `-p`, početni `euid` se očuva.<sup>[[7]](#references)</sup>
- Više detalja može se pronaći na [`bash` man stranici](https://linux.die.net/man/1/bash).<sup>[[7]](#references)</sup>
- **`sh`**:
- POSIX `sh` ne definiše opciju za očuvanje privilegija u stilu Bash-a `-p`.<sup>[[8]](#references)</sup>
- Njegova POSIX lista opcija uključuje `-i`, koja bira interaktivni režim i može biti odbijena kada se stvarni i efektivni ID razlikuju.<sup>[[8]](#references)</sup>
- Dodatne informacije dostupne su na [`sh` man stranici](https://man7.org/linux/man-pages/man1/sh.1p.html).<sup>[[8]](#references)</sup>

Ovi mehanizmi, različiti po načinu rada, nude širok raspon opcija za izvršavanje programa i tranziciju između njih, uz specifične nijanse u načinu upravljanja i očuvanja ID-jeva korisnika.

### Testiranje ponašanja ID-ja korisnika tokom izvršavanja

Primeri su preuzeti sa https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail; pogledajte ih za dodatne informacije.<sup>[[1]](#references)</sup>

#### Slučaj 1: Korišćenje `setuid` sa `system`

**Cilj**: Razumevanje efekta funkcije `setuid` u kombinaciji sa `system` i `bash` kao `sh`.

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

- `ruid` i `euid` počinju kao 99 (nobody) i 1000 (frank), redom.
- U ovom neprivilegovanom kontekstu, `setuid(1000)` ostavlja `ruid` na 99, a `euid` na 1000.<sup>[[1]](#references)</sup>
- `system` izvršava `/bin/bash -c id` zbog simboličke veze sa `sh` na `bash`.
- `bash`, bez opcije `-p`, prilagođava `euid` tako da odgovara vrednosti `ruid`, što rezultuje time da su oba 99 (nobody).<sup>[[1]](#references)</sup>

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
- `system` poziva bash, koji zadržava ID-ove korisnika zbog njihove jednakosti, efektivno radeći kao frank.<sup>[[1]](#references)</sup>

#### Slučaj 3: Using setuid with execve

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

- `ruid` ostaje 99, ali se euid postavlja na 1000, u skladu sa efektom setuid-a.<sup>[[1]](#references)</sup>

**Primer C koda 2 (Pozivanje Bash-a):**
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

- Iako je `euid` postavljen na 1000 pomoću `setuid`, `bash` vraća `euid` na `ruid` (99) zbog odsustva opcije `-p`.<sup>[[1]](#references)</sup>

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

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuid stranica priručnika](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid stranica priručnika](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid stranica priručnika](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve stranica priručnika](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - system stranica priručnika](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - bash stranica priručnika](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - POSIX sh stranica priručnika](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
