# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### Zmienne identyfikacji użytkownika

- **`ruid`**: **Rzeczywisty identyfikator użytkownika** oznacza użytkownika, który zainicjował proces.
- **`euid`**: Znany jako **efektywny identyfikator użytkownika**, reprezentuje tożsamość użytkownika używaną przez system do ustalenia uprawnień procesu. Zazwyczaj `euid` jest taki sam jak `ruid`, z wyjątkiem sytuacji takich jak wykonanie pliku binarnego SetUID, gdy `euid` przyjmuje tożsamość właściciela pliku, zapewniając w ten sposób określone uprawnienia operacyjne.
- **`suid`**: Ten **zapisany identyfikator użytkownika** ma kluczowe znaczenie, gdy proces o wysokich uprawnieniach (zazwyczaj działający jako root) musi tymczasowo zrezygnować ze swoich uprawnień, aby wykonać określone zadania, a następnie odzyskać swój początkowy podwyższony status.

#### Ważna uwaga

Proces niedziałający jako root może zmienić swoje `euid` wyłącznie na bieżące `ruid`, `euid` lub `suid`.

### Zrozumienie funkcji set\*uid

- **`setuid`**: Wbrew początkowym założeniom, `setuid` modyfikuje przede wszystkim `euid`, a nie `ruid`. W szczególności w przypadku uprzywilejowanych procesów ustawia `ruid`, `euid` i `suid` na określonego użytkownika, często root, skutecznie utrwalając te identyfikatory dzięki nadrzędnemu `suid`. Szczegółowe informacje można znaleźć na [stronie man setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** i **`setresuid`**: Funkcje te umożliwiają precyzyjną modyfikację `ruid`, `euid` i `suid`. Ich możliwości zależą jednak od poziomu uprawnień procesu. W przypadku procesów innych niż root modyfikacje są ograniczone do bieżących wartości `ruid`, `euid` i `suid`. Natomiast procesy root lub procesy z capability `CAP_SETUID` mogą przypisywać tym identyfikatorom dowolne wartości. Więcej informacji można znaleźć na [stronie man setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) oraz [stronie man setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Funkcje te nie zostały zaprojektowane jako mechanizm bezpieczeństwa, lecz w celu ułatwienia zamierzonego przebiegu działania, na przykład gdy program przyjmuje tożsamość innego użytkownika poprzez zmianę swojego efektywnego identyfikatora użytkownika.

Warto zauważyć, że choć `setuid` może być często używany do podniesienia uprawnień do root (ponieważ ustawia wszystkie identyfikatory na root), rozróżnienie tych funkcji ma kluczowe znaczenie dla zrozumienia i modyfikowania zachowania identyfikatorów użytkowników w różnych scenariuszach.

### Mechanizmy wykonywania programów w systemie Linux

#### **Wywołanie systemowe `execve`**

- **Funkcjonalność**: `execve` uruchamia program określony przez pierwszy argument. Przyjmuje dwa argumenty tablicowe: `argv` dla argumentów oraz `envp` dla środowiska.
- **Zachowanie**: Zachowuje przestrzeń pamięci wywołującego, ale odświeża stos, stertę i segmenty danych. Kod programu zostaje zastąpiony przez nowy program.
- **Zachowanie identyfikatorów użytkownika**:
- `ruid`, `euid` oraz dodatkowe identyfikatory grup pozostają niezmienione.
- `euid` może ulec subtelnej zmianie, jeśli nowy program ma ustawiony bit SetUID.
- `suid` zostaje zaktualizowany na podstawie `euid` po wykonaniu.
- **Dokumentacja**: Szczegółowe informacje można znaleźć na [stronie man [`execve`](https://man7.org/linux/man-pages/man2/execve.2.html)].

#### **Funkcja `system`**

- **Funkcjonalność**: W przeciwieństwie do `execve`, `system` tworzy proces potomny za pomocą `fork` i wykonuje polecenie w tym procesie potomnym za pomocą `execl`.
- **Wykonywanie polecenia**: Wykonuje polecenie przez `sh` za pomocą `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Zachowanie**: Ponieważ `execl` jest formą `execve`, działa podobnie, ale w kontekście nowego procesu potomnego.
- **Dokumentacja**: Dodatkowe informacje można znaleźć na [stronie man [`system`](https://man7.org/linux/man-pages/man3/system.3.html)].

#### **Zachowanie `bash` i `sh` z SUID**

- **`bash`**:
- Ma opcję `-p` wpływającą na sposób traktowania `euid` i `ruid`.
- Bez `-p` `bash` ustawia `euid` na `ruid`, jeśli początkowo są różne.
- Z `-p` zachowywane jest początkowe `euid`.
- Więcej informacji można znaleźć na [stronie man [`bash`](https://linux.die.net/man/1/bash)].
- **`sh`**:
- Nie posiada mechanizmu podobnego do `-p` w `bash`.
- Zachowanie dotyczące identyfikatorów użytkownika nie jest wyraźnie opisane, z wyjątkiem opcji `-i`, która podkreśla zachowanie równości `euid` i `ruid`.
- Dodatkowe informacje są dostępne na [stronie man [`sh`](https://man7.org/linux/man-pages/man1/sh.1p.html)].

Mechanizmy te, różniące się sposobem działania, oferują szeroki zakres opcji wykonywania programów i przechodzenia między nimi, z określonymi niuansami dotyczącymi zarządzania identyfikatorami użytkowników i ich zachowywania.

### Testowanie zachowania identyfikatorów użytkownika podczas wykonywania

Przykłady pochodzą z https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, sprawdź ten materiał, aby uzyskać więcej informacji

#### Przypadek 1: Użycie `setuid` z `system`

**Cel**: Zrozumienie efektu działania `setuid` w połączeniu z `system` i `bash` jako `sh`.

**Kod C**:
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
**Kompilacja i uprawnienia:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

- `ruid` i `euid` rozpoczynają odpowiednio jako 99 (nobody) i 1000 (frank).
- `setuid` ustawia obie wartości na 1000.
- `system` wykonuje `/bin/bash -c id` z powodu dowiązania symbolicznego z sh do bash.
- `bash`, bez `-p`, dostosowuje `euid`, aby odpowiadało `ruid`, w wyniku czego obie wartości wynoszą 99 (nobody).

#### Przypadek 2: Użycie setreuid z system

**Kod C**:
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
**Kompilacja i uprawnienia:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Wykonanie i wynik:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

- `setreuid` ustawia zarówno ruid, jak i euid na 1000.
- `system` wywołuje bash, który zachowuje identyfikatory użytkownika ze względu na ich równość, skutecznie działając jako frank.

#### Przypadek 3: Użycie setuid z execve

Cel: Zbadanie interakcji między setuid i execve.
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
**Wykonanie i wynik:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

- `ruid` pozostaje równy 99, ale euid jest ustawiony na 1000, zgodnie z działaniem setuid.

**Przykład kodu C 2 (Wywoływanie Bash):**
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
**Wykonanie i wynik:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analiza:**

- Chociaż `euid` jest ustawione na 1000 przez `setuid`, `bash` resetuje `euid` do `ruid` (99) z powodu braku `-p`.

**Przykład kodu C 3 (użycie bash -p):**
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
**Wykonanie i wynik:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Referencje

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
