# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Promenljive za identifikaciju korisnika

- **`ruid`**: **Stvarni ID korisnika** označava korisnika koji je pokrenuo proces.
- **`euid`**: Poznat kao **efektivni ID korisnika**, predstavlja identitet korisnika koji sistem koristi za utvrđivanje privilegija procesa. Uopšteno, `euid` odgovara vrednosti `ruid`, osim u slučajevima kao što je izvršavanje SetUID binary-ja, kada `euid` preuzima identitet vlasnika fajla i time dobija određene operativne dozvole.
- **`suid`**: Ovaj **sačuvani ID korisnika** je ključan kada proces sa visokim privilegijama (obično pokrenut kao root) treba privremeno da se odrekne svojih privilegija radi obavljanja određenih zadataka, a zatim ponovo povrati svoj početni povišeni status.

#### Važna napomena

Proces koji ne radi kao root može promeniti svoj `euid` samo tako da odgovara trenutnom `ruid`, `euid` ili `suid`.

### Razumevanje set\*uid funkcija

- **`setuid`**: Suprotno početnim pretpostavkama, `setuid` prvenstveno menja `euid`, a ne `ruid`. Konkretno, kod privilegovanih procesa usklađuje `ruid`, `euid` i `suid` sa navedenim korisnikom, često root-om, čime efektivno trajno postavlja ove ID-jeve zbog nadjačavajućeg `suid`. Detaljne informacije mogu se pronaći na [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** i **`setresuid`**: Ove funkcije omogućavaju precizno podešavanje vrednosti `ruid`, `euid` i `suid`. Međutim, njihove mogućnosti zavise od nivoa privilegija procesa. Kod procesa koji nisu root, izmene su ograničene na trenutne vrednosti `ruid`, `euid` i `suid`. Nasuprot tome, root procesi ili oni sa mogućnošću `CAP_SETUID` mogu dodeliti proizvoljne vrednosti ovim ID-jevima. Više informacija može se pronaći na [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) i [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Ove funkcionalnosti nisu osmišljene kao bezbednosni mehanizam, već da omoguće predviđeni tok rada, na primer kada program preuzima identitet drugog korisnika menjanjem svog efektivnog ID-ja korisnika.

Važno je napomenuti da, iako `setuid` može biti uobičajen izbor za podizanje privilegija na root (pošto usklađuje sve ID-jeve sa root-om), razlikovanje ovih funkcija ključno je za razumevanje i menjanje ponašanja korisničkih ID-jeva u različitim scenarijima.

### Mehanizmi izvršavanja programa u Linux-u

#### **`execve` sistemski poziv**

- **Funkcionalnost**: `execve` pokreće program određen prvim argumentom. Prima dva niza argumenata, `argv` za argumente i `envp` za okruženje.
- **Ponašanje**: Zadržava memorijski prostor pozivaoca, ali osvežava stek, heap i segmente podataka. Kod programa zamenjuje novi program.
- **Očuvanje korisničkih ID-jeva**:
- `ruid`, `euid` i dopunski ID-jevi grupa ostaju nepromenjeni.
- `euid` može biti suptilno promenjen ako novi program ima postavljen SetUID bit.
- `suid` se nakon izvršavanja ažurira iz vrednosti `euid`.
- **Dokumentacija**: Detaljne informacije mogu se pronaći na [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **`system` funkcija**

- **Funkcionalnost**: Za razliku od `execve`, `system` kreira child proces pomoću `fork` i izvršava komandu unutar tog child procesa koristeći `execl`.
- **Izvršavanje komande**: Izvršava komandu putem `sh` sa `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Ponašanje**: Pošto je `execl` oblik funkcije `execve`, ponaša se slično, ali u kontekstu novog child procesa.
- **Dokumentacija**: Dodatne informacije mogu se pronaći na [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Ponašanje `bash` i `sh` sa SUID**

- **`bash`**:
- Ima opciju `-p` koja utiče na način tretiranja `euid` i `ruid`.
- Bez opcije `-p`, `bash` postavlja `euid` na vrednost `ruid` ako su se početno razlikovali.
- Sa opcijom `-p`, početni `euid` se čuva.
- Više detalja može se pronaći na [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- Nema mehanizam sličan opciji `-p` u programu `bash`.
- Ponašanje u vezi sa korisničkim ID-jevima nije eksplicitno navedeno, osim kod opcije `-i`, koja naglašava očuvanje jednakosti `euid` i `ruid`.
- Dodatne informacije dostupne su na [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

Ovi mehanizmi, različiti po načinu rada, nude širok raspon opcija za izvršavanje programa i prelazak između njih, uz specifične nijanse u načinu upravljanja i očuvanja korisničkih ID-jeva.

### Testiranje ponašanja korisničkih ID-jeva pri izvršavanju

Primeri su preuzeti sa https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, pogledajte ih za dodatne informacije<sup>[[1]](#references)</sup>

#### Slučaj 1: Korišćenje `setuid` sa `system`

**Cilj**: Razumevanje efekta funkcije `setuid` u kombinaciji sa funkcijama `system` i `bash` kao `sh`.

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

- `ruid` i `euid` počinju sa 99 (nobody) i 1000 (frank), redom.
- `setuid` usklađuje oba sa 1000.
- `system` izvršava `/bin/bash -c id` zbog simboličke veze sa `sh` na `bash`.
- `bash`, bez `-p`, prilagođava `euid` tako da odgovara `ruid`, što dovodi do toga da oba budu 99 (nobody).

#### Slučaj 2: Korišćenje setreuid sa system

**C kod**:
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
- `system` poziva bash, koji zadržava ID-ove korisnika zbog njihove jednakosti i efektivno radi kao frank.

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

- `ruid` ostaje 99, ali je `euid` postavljen na 1000, u skladu sa efektom `setuid`.

**C primer koda 2 (Pozivanje Bash-a):**
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

- Iako je `euid` pomoću `setuid` postavljen na 1000, `bash` resetuje euid na `ruid` (99) zbog odsustva opcije `-p`.

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
uid=99(nobody) gid=99(nobody) euid=100
```
## Reference

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve man page](https://man7.org/linux/man-pages/man2/execve.2.html)

{{#include ../../banners/hacktricks-training.md}}
