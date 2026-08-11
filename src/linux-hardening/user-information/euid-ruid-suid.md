# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Zmienne identyfikujące użytkownika

- **`ruid`**: **rzeczywisty identyfikator użytkownika** oznacza użytkownika, który zainicjował proces.<sup>[[1]](#references)</sup>
- **`euid`**: Znany jako **efektywny identyfikator użytkownika**, reprezentuje tożsamość użytkownika wykorzystywaną przez system do określania uprawnień procesu. Zazwyczaj `euid` jest taki sam jak `ruid`, z wyjątkiem przypadków takich jak wykonanie pliku binarnego SetUID (gdy przejście set-user-ID zostanie uwzględnione), w których `euid` przyjmuje tożsamość właściciela pliku, uzyskując tym samym określone uprawnienia operacyjne.<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: Ten **zapisany identyfikator użytkownika** ma kluczowe znaczenie, gdy proces o wysokich uprawnieniach (zwykle działający jako root) musi tymczasowo zrezygnować ze swoich uprawnień w celu wykonania określonych zadań, a następnie odzyskać swój początkowy podwyższony status.<sup>[[1]](#references)</sup>

#### Ważna uwaga

Nieuprzywilejowany proces może zmienić swoje `euid` tylko tak, aby odpowiadało bieżącemu `ruid`, `euid` lub `suid`.<sup>[[3]](#references)</sup>

### Zrozumienie funkcji set\*uid

- **`setuid`**: Wbrew początkowym założeniom, `setuid` ustawia `euid` procesu wywołującego. W przypadku procesu uprzywilejowanego ustawia również `ruid` i `suid` na określonego użytkownika; po ustawieniu wszystkich identyfikatorów na root proces nie może odzyskać wcześniejszej tożsamości za pomocą `setuid`. Szczegółowe informacje można znaleźć na [stronie man setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** i **`setresuid`**: `setreuid` zmienia `ruid` i `euid`, natomiast `setresuid` zmienia wszystkie trzy identyfikatory. W przypadku procesu nieuprzywilejowanego `setresuid` ogranicza każdą wartość docelową do bieżącego `ruid`, `euid` lub `suid`; `setreuid` ogranicza `euid` do tych wartości, a `ruid` do bieżącego `ruid` lub `euid`. Proces z `CAP_SETUID` może przypisywać dowolne wartości identyfikatorom obsługiwanym przez poszczególne wywołania. Więcej informacji można znaleźć na [stronie man setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) oraz [stronie man setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Funkcjonalności te nie zostały zaprojektowane jako mechanizm bezpieczeństwa, lecz w celu ułatwienia zamierzonego przebiegu operacji, na przykład gdy program przyjmuje tożsamość innego użytkownika poprzez zmianę swojego efektywnego identyfikatora użytkownika.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Warto zauważyć, że uprzywilejowane wywołanie `setuid` może przypisać wszystkie trzy identyfikatory, podczas gdy `setreuid` i `setresuid` udostępniają różne mechanizmy kontroli; rozróżnienie tych funkcji ma kluczowe znaczenie dla zrozumienia przejść między identyfikatorami użytkownika.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Mechanizmy wykonywania programów w systemie Linux

#### **Wywołanie systemowe `execve`**

- **Funkcjonalność**: `execve` uruchamia program określony przez pierwszy argument. Przyjmuje dwa argumenty będące tablicami: `argv` dla argumentów oraz `envp` dla środowiska.<sup>[[5]](#references)</sup>
- **Zachowanie**: Zachowuje przestrzeń pamięci wywołującego, ale odświeża segmenty stosu, sterty i danych. Kod programu zostaje zastąpiony przez nowy program.<sup>[[5]](#references)</sup>
- **Zachowanie identyfikatorów użytkownika**:
- `ruid` i dodatkowe identyfikatory grup pozostają niezmienione.<sup>[[5]](#references)</sup>
- `euid` zwykle pozostaje niezmienione, ale może się zmienić, jeśli nowy program ma ustawiony bit SetUID.<sup>[[5]](#references)</sup>
- `suid` zostaje zaktualizowane na podstawie `euid` po wykonaniu.<sup>[[5]](#references)</sup>
- **Dokumentacja**: Szczegółowe informacje można znaleźć na [stronie man `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **Funkcja `system`**

- **Funkcjonalność**: W przeciwieństwie do `execve`, `system` działa tak, jakby tworzył proces potomny za pomocą `fork`, a następnie wykonywał polecenie w tym procesie potomnym za pomocą `execl`.<sup>[[6]](#references)</sup>
- **Wykonywanie polecenia**: Wykonuje polecenie za pośrednictwem `sh` za pomocą `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.<sup>[[6]](#references)</sup>
- **Zachowanie**: Ponieważ `execl` jest wywołaniem z rodziny `exec`, działa podobnie do `execve`, ale w kontekście nowego procesu potomnego.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Dokumentacja**: Dodatkowe informacje można znaleźć na [stronie man `system`](https://man7.org/linux/man-pages/man3/system.3.html).<sup>[[6]](#references)</sup>

#### **Zachowanie `bash` i `sh` z SUID**

- **`bash`**:
- Ma opcję `-p`, która wpływa na sposób traktowania `euid` i `ruid`.<sup>[[7]](#references)</sup>
- Bez `-p` `bash` ustawia `euid` na `ruid`, jeśli początkowo się różnią.<sup>[[7]](#references)</sup>
- Z `-p` zachowywane jest początkowe `euid`.<sup>[[7]](#references)</sup>
- Więcej informacji można znaleźć na [stronie man `bash`](https://linux.die.net/man/1/bash).<sup>[[7]](#references)</sup>
- **`sh`**:
- POSIX `sh` nie definiuje opcji zachowania uprawnień w stylu Bash `-p`.<sup>[[8]](#references)</sup>
- Jego lista opcji POSIX obejmuje `-i`, która wybiera tryb interaktywny i może zostać odrzucona, gdy rzeczywiste i efektywne identyfikatory się różnią.<sup>[[8]](#references)</sup>
- Dodatkowe informacje są dostępne na [stronie man `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).<sup>[[8]](#references)</sup>

Mechanizmy te, różniące się sposobem działania, oferują szeroki zakres opcji wykonywania programów i przechodzenia między nimi, z określonymi niuansami dotyczącymi zarządzania identyfikatorami użytkownika i ich zachowywania.

### Testowanie zachowania identyfikatorów użytkownika podczas wykonywania

Przykłady pochodzą z https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, sprawdź ten materiał, aby uzyskać więcej informacji.<sup>[[1]](#references)</sup>

#### Przypadek 1: Użycie `setuid` z `system`

**Cel**: Zrozumienie wpływu `setuid` w połączeniu z `system` i `bash` jako `sh`.

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

- `ruid` i `euid` rozpoczynają odpowiednio od wartości 99 (nobody) i 1000 (frank).
- W tym nieuprzywilejowanym kontekście `setuid(1000)` pozostawia `ruid` na poziomie 99, a `euid` na poziomie 1000.<sup>[[1]](#references)</sup>
- `system` wykonuje `/bin/bash -c id` z powodu dowiązania symbolicznego z sh do bash.
- `bash`, bez `-p`, dostosowuje `euid` do `ruid`, w wyniku czego obie wartości wynoszą 99 (nobody).<sup>[[1]](#references)</sup>

#### Przypadek 2: Using setreuid with system

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
- `system` wywołuje bash, który zachowuje identyfikatory użytkowników ze względu na ich równość, efektywnie działając jako frank.<sup>[[1]](#references)</sup>

#### Przypadek 3: Using setuid with execve

Cel: Zbadanie interakcji między setuid a execve.
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

- `ruid` pozostaje równy 99, ale euid zostaje ustawiony na 1000, zgodnie z działaniem setuid.<sup>[[1]](#references)</sup>

**Przykład kodu C 2 (wywoływanie Bash):**
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

- Chociaż `euid` jest ustawione na 1000 przez `setuid`, `bash` resetuje `euid` do `ruid` (99) z powodu braku `-p`.<sup>[[1]](#references)</sup>

**Przykład kodu C 3 (Użycie bash -p):**
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
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [Królicza nora SetUID - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - strona podręcznika man setuid](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - strona podręcznika man setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - strona podręcznika man setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - strona podręcznika man execve](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - strona podręcznika man system](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - strona podręcznika man bash](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - strona podręcznika man POSIX sh](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
