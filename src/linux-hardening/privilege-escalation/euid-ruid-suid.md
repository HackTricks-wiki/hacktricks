# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### User Identification Variables

- **`ruid`**: **real user ID** označava korisnika koji je pokrenuo proces.
- **`euid`**: Poznat kao **effective user ID**, predstavlja identitet korisnika koji sistem koristi za utvrđivanje privilegija procesa. Generalno, `euid` odražava `ruid`, osim u slučajevima kao što je izvršavanje SetUID binarnog fajla, gde `euid` preuzima identitet vlasnika fajla, čime se dodeljuju specifične operativne dozvole.
- **`suid`**: Ovaj **saved user ID** je ključan kada proces sa visokim privilegijama (obično pokrenut kao root) treba privremeno da se odrekne svojih privilegija kako bi izvršio određene zadatke, samo da bi kasnije povratio svoj prvobitni povišeni status.

#### Important Note

Proces koji ne radi pod root-om može samo da modifikuje svoj `euid` da odgovara trenutnom `ruid`, `euid` ili `suid`.

### Understanding set\*uid Functions

- **`setuid`**: Suprotno prvobitnim pretpostavkama, `setuid` prvenstveno modifikuje `euid` umesto `ruid`. Konkretno, za privilegovane procese, usklađuje `ruid`, `euid` i `suid` sa određenim korisnikom, često root, efektivno učvršćujući ove ID-ove zbog nadjačavajućeg `suid`. Detaljne informacije mogu se naći na [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** i **`setresuid`**: Ove funkcije omogućavaju suptilno podešavanje `ruid`, `euid` i `suid`. Međutim, njihove mogućnosti zavise od nivoa privilegija procesa. Za procese koji nisu root, modifikacije su ograničene na trenutne vrednosti `ruid`, `euid` i `suid`. Nasuprot tome, root procesi ili oni sa `CAP_SETUID` privilegijom mogu dodeliti proizvoljne vrednosti ovim ID-ovima. Više informacija može se dobiti iz [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) i [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Ove funkcionalnosti nisu dizajnirane kao mehanizam bezbednosti, već da olakšaju predviđeni operativni tok, kao kada program preuzima identitet drugog korisnika menjajući svoj effective user ID.

Važno je napomenuti da, iako `setuid` može biti uobičajen izbor za podizanje privilegija na root (pošto usklađuje sve ID-ove sa root), razlikovanje između ovih funkcija je ključno za razumevanje i manipulaciju ponašanjem korisničkih ID-ova u različitim scenarijima.

### Program Execution Mechanisms in Linux

#### **`execve` System Call**

- **Functionality**: `execve` pokreće program, određen prvim argumentom. Prihvaća dva niza argumenata, `argv` za argumente i `envp` za okruženje.
- **Behavior**: Zadržava memorijski prostor pozivaoca, ali osvežava stek, heap i podatkovne segmente. Kod programa se zamenjuje novim programom.
- **User ID Preservation**:
- `ruid`, `euid` i dodatni grupni ID-ovi ostaju nepromenjeni.
- `euid` može imati suptilne promene ako novi program ima postavljen SetUID bit.
- `suid` se ažurira iz `euid` nakon izvršenja.
- **Documentation**: Detaljne informacije mogu se naći na [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **`system` Function**

- **Functionality**: Za razliku od `execve`, `system` kreira podproces koristeći `fork` i izvršava komandu unutar tog podprocesa koristeći `execl`.
- **Command Execution**: Izvršava komandu putem `sh` sa `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Behavior**: Pošto je `execl` oblik `execve`, funkcioniše slično, ali u kontekstu novog podprocesa.
- **Documentation**: Dalje informacije mogu se dobiti iz [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Behavior of `bash` and `sh` with SUID**

- **`bash`**:
- Ima `-p` opciju koja utiče na to kako se tretiraju `euid` i `ruid`.
- Bez `-p`, `bash` postavlja `euid` na `ruid` ako se prvobitno razlikuju.
- Sa `-p`, prvobitni `euid` se čuva.
- Više detalja može se naći na [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- Ne poseduje mehanizam sličan `-p` u `bash`.
- Ponašanje u vezi sa korisničkim ID-ovima nije eksplicitno navedeno, osim pod `-i` opcijom, naglašavajući očuvanje jednakosti `euid` i `ruid`.
- Dodatne informacije su dostupne na [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

Ovi mehanizmi, različiti u svojoj operaciji, nude raznovrsne opcije za izvršavanje i prelazak između programa, sa specifičnim nijansama u načinu na koji se upravlja i čuva korisnički ID.

### Testing User ID Behaviors in Executions

Primeri preuzeti sa https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, proverite za dodatne informacije

#### Case 1: Using `setuid` with `system`

**Objective**: Razumevanje efekta `setuid` u kombinaciji sa `system` i `bash` kao `sh`.

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
**Kompilacija i Dozvole:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

- `ruid` i `euid` počinju kao 99 (nobody) i 1000 (frank) respektivno.
- `setuid` usklađuje oba na 1000.
- `system` izvršava `/bin/bash -c id` zbog symlink-a sa sh na bash.
- `bash`, bez `-p`, prilagođava `euid` da se poklapa sa `ruid`, što rezultira da oba budu 99 (nobody).

#### Slučaj 2: Korišćenje setreuid sa system

**C Kod**:
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
**Kompilacija i Dozvole:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Izvršenje i Rezultat:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

- `setreuid` postavlja i ruid i euid na 1000.
- `system` poziva bash, koji održava korisničke ID-ove zbog njihove jednakosti, efikasno delujući kao frank.

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
**Izvršenje i Rezultat:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

- `ruid` ostaje 99, ali euid je postavljen na 1000, u skladu sa efektom setuid-a.

**C Primer Koda 2 (Pozivanje Basha):**
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
**Izvršenje i Rezultat:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

- Iako je `euid` postavljen na 1000 pomoću `setuid`, `bash` resetuje euid na `ruid` (99) zbog odsustva `-p`.

**C Primer koda 3 (Korišćenje bash -p):**
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
**Izvršenje i Rezultat:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Reference

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
