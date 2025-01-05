# User Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

User namespace to funkcja jądra Linux, która **zapewnia izolację mapowań identyfikatorów użytkowników i grup**, pozwalając każdemu user namespace na posiadanie **własnego zestawu identyfikatorów użytkowników i grup**. Ta izolacja umożliwia procesom działającym w różnych user namespaces **posiadanie różnych uprawnień i własności**, nawet jeśli dzielą te same identyfikatory użytkowników i grup numerycznie.

User namespaces są szczególnie przydatne w konteneryzacji, gdzie każdy kontener powinien mieć swój niezależny zestaw identyfikatorów użytkowników i grup, co pozwala na lepsze bezpieczeństwo i izolację między kontenerami a systemem gospodarza.

### Jak to działa:

1. Gdy nowy user namespace jest tworzony, **zaczyna się od pustego zestawu mapowań identyfikatorów użytkowników i grup**. Oznacza to, że każdy proces działający w nowym user namespace **początkowo nie ma uprawnień poza namespace**.
2. Mapowania identyfikatorów mogą być ustalane między identyfikatorami użytkowników i grup w nowym namespace a tymi w namespace nadrzędnym (lub gospodarzu). To **pozwala procesom w nowym namespace na posiadanie uprawnień i własności odpowiadających identyfikatorom użytkowników i grup w namespace nadrzędnym**. Jednak mapowania identyfikatorów mogą być ograniczone do określonych zakresów i podzbiorów identyfikatorów, co pozwala na precyzyjną kontrolę nad uprawnieniami przyznawanymi procesom w nowym namespace.
3. W obrębie user namespace, **procesy mogą mieć pełne uprawnienia roota (UID 0) do operacji wewnątrz namespace**, jednocześnie mając ograniczone uprawnienia poza namespace. To pozwala **kontenerom działać z możliwościami podobnymi do roota w swoim własnym namespace bez posiadania pełnych uprawnień roota w systemie gospodarza**.
4. Procesy mogą przemieszczać się między namespaces za pomocą wywołania systemowego `setns()` lub tworzyć nowe namespaces za pomocą wywołań systemowych `unshare()` lub `clone()` z flagą `CLONE_NEWUSER`. Gdy proces przemieszcza się do nowego namespace lub go tworzy, zacznie używać mapowań identyfikatorów użytkowników i grup związanych z tym namespace.

## Laboratorium:

### Tworzenie różnych Namespaces

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Montując nową instancję systemu plików `/proc`, używając parametru `--mount-proc`, zapewniasz, że nowa przestrzeń montowania ma **dokładny i izolowany widok informacji o procesach specyficznych dla tej przestrzeni nazw**.

<details>

<summary>Błąd: bash: fork: Nie można przydzielić pamięci</summary>

Gdy `unshare` jest wykonywane bez opcji `-f`, napotykany jest błąd z powodu sposobu, w jaki Linux obsługuje nowe przestrzenie nazw PID (identyfikator procesu). Kluczowe szczegóły oraz rozwiązanie są opisane poniżej:

1. **Wyjaśnienie problemu**:

- Jądro Linuxa pozwala procesowi na tworzenie nowych przestrzeni nazw za pomocą wywołania systemowego `unshare`. Jednak proces, który inicjuje tworzenie nowej przestrzeni nazw PID (nazywany "procesem unshare"), nie wchodzi do nowej przestrzeni nazw; tylko jego procesy potomne to robią.
- Uruchomienie `%unshare -p /bin/bash%` uruchamia `/bin/bash` w tym samym procesie co `unshare`. W konsekwencji, `/bin/bash` i jego procesy potomne znajdują się w oryginalnej przestrzeni nazw PID.
- Pierwszy proces potomny `/bin/bash` w nowej przestrzeni nazw staje się PID 1. Gdy ten proces kończy działanie, uruchamia sprzątanie przestrzeni nazw, jeśli nie ma innych procesów, ponieważ PID 1 ma specjalną rolę przyjmowania procesów osieroconych. Jądro Linuxa wyłączy wtedy przydzielanie PID w tej przestrzeni nazw.

2. **Konsekwencja**:

- Zakończenie PID 1 w nowej przestrzeni nazw prowadzi do usunięcia flagi `PIDNS_HASH_ADDING`. Skutkuje to niepowodzeniem funkcji `alloc_pid` w przydzieleniu nowego PID podczas tworzenia nowego procesu, co skutkuje błędem "Nie można przydzielić pamięci".

3. **Rozwiązanie**:
- Problem można rozwiązać, używając opcji `-f` z `unshare`. Ta opcja sprawia, że `unshare` fork'uje nowy proces po utworzeniu nowej przestrzeni nazw PID.
- Wykonanie `%unshare -fp /bin/bash%` zapewnia, że polecenie `unshare` samo staje się PID 1 w nowej przestrzeni nazw. `/bin/bash` i jego procesy potomne są następnie bezpiecznie zawarte w tej nowej przestrzeni nazw, co zapobiega przedwczesnemu zakończeniu PID 1 i umożliwia normalne przydzielanie PID.

Zapewniając, że `unshare` działa z flagą `-f`, nowa przestrzeń nazw PID jest prawidłowo utrzymywana, co pozwala na działanie `/bin/bash` i jego podprocesów bez napotkania błędu przydzielania pamięci.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Aby użyć przestrzeni nazw użytkownika, demon Dockera musi być uruchomiony z **`--userns-remap=default`** (W Ubuntu 14.04 można to zrobić, modyfikując `/etc/default/docker`, a następnie wykonując `sudo service docker restart`)

### Sprawdź, w której przestrzeni nazw znajduje się twój proces
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Można sprawdzić mapę użytkowników z kontenera docker za pomocą:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Lub z hosta za pomocą:
```bash
cat /proc/<pid>/uid_map
```
### Znajdź wszystkie przestrzenie nazw użytkowników
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Wejdź do przestrzeni nazw użytkownika
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Możesz **wejść do innej przestrzeni nazw procesów tylko jako root**. I **nie możesz** **wejść** do innej przestrzeni nazw **bez deskryptora** wskazującego na nią (takiego jak `/proc/self/ns/user`).

### Utwórz nową przestrzeń nazw użytkownika (z mapowaniami)
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Odzyskiwanie uprawnień

W przypadku przestrzeni nazw użytkowników, **gdy tworzona jest nowa przestrzeń nazw użytkowników, proces, który wchodzi do tej przestrzeni, otrzymuje pełny zestaw uprawnień w tej przestrzeni**. Te uprawnienia pozwalają procesowi na wykonywanie operacji uprzywilejowanych, takich jak **montowanie** **systemów plików**, tworzenie urządzeń czy zmiana właściciela plików, ale **tylko w kontekście jego przestrzeni nazw użytkowników**.

Na przykład, gdy masz uprawnienie `CAP_SYS_ADMIN` w przestrzeni nazw użytkowników, możesz wykonywać operacje, które zazwyczaj wymagają tego uprawnienia, takie jak montowanie systemów plików, ale tylko w kontekście swojej przestrzeni nazw użytkowników. Jakiekolwiek operacje, które wykonasz z tym uprawnieniem, nie wpłyną na system gospodarza ani inne przestrzenie nazw.

> [!WARNING]
> Dlatego, nawet jeśli uzyskanie nowego procesu w nowej przestrzeni nazw użytkowników **przywróci ci wszystkie uprawnienia** (CapEff: 000001ffffffffff), w rzeczywistości możesz **używać tylko tych związanych z przestrzenią nazw** (na przykład montowanie), a nie wszystkich. Tak więc, samo to nie wystarczy, aby uciec z kontenera Docker.
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#include ../../../../banners/hacktricks-training.md}}
