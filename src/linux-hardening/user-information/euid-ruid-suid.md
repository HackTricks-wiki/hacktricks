# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### Varijable za identifikaciju korisnika

- **`ruid`**: **Stvarni ID korisnika** označava korisnika koji je pokrenuo proces.
- **`euid`**: Poznat kao **efektivni ID korisnika**, predstavlja identitet korisnika koji sistem koristi za utvrđivanje privilegija procesa. Uobičajeno je da `euid` bude isti kao `ruid`, osim u slučajevima kao što je izvršavanje SetUID binary-ja, kada `euid` preuzima identitet vlasnika fajla i time dobija određene operativne dozvole.
- **`suid`**: Ovaj **sačuvani ID korisnika** ključan je kada proces sa visokim privilegijama (obično pokrenut kao root) treba privremeno da se odrekne svojih privilegija radi obavljanja određenih zadataka, a zatim ponovo preuzme svoj početni povišeni status.

#### Važna napomena

Proces koji ne radi pod root korisnikom može da promeni svoj `euid` samo tako da odgovara trenutnom `ruid`, `euid` ili `suid`.

### Razumevanje set\*uid funkcija

- **`setuid`**: Suprotno početnim pretpostavkama, `setuid` prvenstveno menja `euid`, a ne `ruid`. Konkretno, kod privilegovanih procesa postavlja `ruid`, `euid` i `suid` na navedenog korisnika, često root, čime efektivno učvršćuje ove ID-jeve zbog nadjačavajućeg `suid`. Detaljnije informacije dostupne su na [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** i **`setresuid`**: Ove funkcije omogućavaju precizno podešavanje `ruid`, `euid` i `suid`. Međutim, njihove mogućnosti zavise od nivoa privilegija procesa. Kod procesa koji nisu root, izmene su ograničene na trenutne vrednosti `ruid`, `euid` i `suid`. Nasuprot tome, root procesi ili oni sa `CAP_SETUID` capability-jem mogu da dodele proizvoljne vrednosti ovim ID-jevima. Više informacija dostupno je na [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) i [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Ove funkcionalnosti nisu osmišljene kao security mehanizam, već da omoguće predviđeni operativni tok, na primer kada program preuzima identitet drugog korisnika menjanjem svog efektivnog ID-ja korisnika.

Važno je napomenuti da, iako `setuid` može biti uobičajen izbor za eskalaciju privilegija na root (jer sve ID-jeve postavlja na root), razlikovanje ovih funkcija predstavlja ključ za razumevanje i manipulisanje ponašanjem user ID-jeva u različitim scenarijima.

### Mehanizmi izvršavanja programa u Linux-u

#### **`execve` System Call**

- **Funkcionalnost**: `execve` pokreće program određen prvim argumentom. Prima dva argumenta u obliku nizova: `argv` za argumente i `envp` za okruženje.
- **Ponašanje**: Zadržava memorijski prostor pozivaoca, ali osvežava stack, heap i data segmente. Kod programa se zamenjuje novim programom.
- **Očuvanje user ID-jeva**:
- `ruid`, `euid` i dodatni group ID-jevi ostaju nepromenjeni.
- `euid` se može nijansirano promeniti ako novi program ima postavljen SetUID bit.
- `suid` se nakon izvršavanja ažurira iz vrednosti `euid`.
- **Dokumentacija**: Detaljne informacije dostupne su na [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **`system` funkcija**

- **Funkcionalnost**: Za razliku od `execve`, `system` kreira child proces pomoću `fork`-a i izvršava komandu unutar tog child procesa pomoću `execl`-a.
- **Izvršavanje komande**: Komandu izvršava putem `sh` koristeći `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Ponašanje**: Pošto je `execl` oblik funkcije `execve`, ponaša se slično, ali u kontekstu novog child procesa.
- **Dokumentacija**: Dodatne informacije dostupne su na [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Ponašanje `bash` i `sh` sa SUID-om**

- **`bash`**:
- Ima opciju `-p` koja utiče na način tretiranja `euid` i `ruid`.
- Bez opcije `-p`, `bash` postavlja `euid` na `ruid` ako su se u početku razlikovali.
- Sa opcijom `-p`, početni `euid` se očuvava.
- Više detalja dostupno je na [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- Nema mehanizam sličan opciji `-p` u `bash`-u.
- Ponašanje u vezi sa user ID-jevima nije eksplicitno navedeno, osim uz opciju `-i`, koja naglašava očuvanje jednakosti `euid` i `ruid`.
- Dodatne informacije dostupne su na [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

Ovi mehanizmi, različiti po načinu rada, nude raznovrstan skup opcija za izvršavanje i prelazak između programa, uz specifične nijanse u načinu upravljanja i očuvanja user ID-jeva.

### Testiranje ponašanja user ID-jeva tokom izvršavanja

Primeri su preuzeti sa https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, pogledajte ih za dodatne informacije

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

- `ruid` i `euid` počinju sa 99 (nobody) i 1000 (frank), redom.
- `setuid` poravnava oba na 1000.
- `system` izvršava `/bin/bash -c id` zbog simboličke veze sa `sh` na `bash`.
- `bash`, bez `-p`, prilagođava `euid` tako da odgovara `ruid`, zbog čega oba postaju 99 (nobody).

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
- `system` poziva bash, koji zadržava ID-ove korisnika zbog njihove jednakosti, efektivno radeći kao frank.

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

- `ruid` ostaje 99, ali se euid postavlja na 1000, u skladu sa efektom funkcije setuid.

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

- Iako je `euid` postavljen na 1000 pomoću `setuid`, `bash` vraća euid na `ruid` (99) zbog odsustva opcije `-p`.

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
**Izvršenje i rezultat:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Reference

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
