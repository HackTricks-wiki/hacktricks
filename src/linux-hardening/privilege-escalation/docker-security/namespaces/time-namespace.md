# Time Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Namespace czasu w systemie Linux pozwala na per-namespace przesunięcia do systemowych zegarów monotonicznych i czasów uruchomienia. Jest powszechnie używany w kontenerach Linux do zmiany daty/czasu wewnątrz kontenera oraz dostosowywania zegarów po przywróceniu z punktu kontrolnego lub migawki.

## Laboratorium:

### Tworzenie różnych Namespace'ów

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
Montując nową instancję systemu plików `/proc`, używając parametru `--mount-proc`, zapewniasz, że nowa przestrzeń montowania ma **dokładny i izolowany widok informacji o procesach specyficznych dla tej przestrzeni**.

<details>

<summary>Błąd: bash: fork: Nie można przydzielić pamięci</summary>

Gdy `unshare` jest wykonywane bez opcji `-f`, napotykany jest błąd z powodu sposobu, w jaki Linux obsługuje nowe przestrzenie nazw PID (identyfikator procesu). Kluczowe szczegóły oraz rozwiązanie są przedstawione poniżej:

1. **Wyjaśnienie problemu**:

- Jądro Linuxa pozwala procesowi na tworzenie nowych przestrzeni nazw za pomocą wywołania systemowego `unshare`. Jednak proces, który inicjuje tworzenie nowej przestrzeni nazw PID (nazywany "procesem unshare"), nie wchodzi do nowej przestrzeni; tylko jego procesy potomne to robią.
- Uruchomienie `%unshare -p /bin/bash%` uruchamia `/bin/bash` w tym samym procesie co `unshare`. W konsekwencji, `/bin/bash` i jego procesy potomne znajdują się w oryginalnej przestrzeni nazw PID.
- Pierwszy proces potomny `/bin/bash` w nowej przestrzeni staje się PID 1. Gdy ten proces kończy działanie, uruchamia czyszczenie przestrzeni nazw, jeśli nie ma innych procesów, ponieważ PID 1 ma specjalną rolę przyjmowania procesów osieroconych. Jądro Linuxa wyłączy wtedy przydzielanie PID w tej przestrzeni.

2. **Konsekwencja**:

- Zakończenie PID 1 w nowej przestrzeni prowadzi do usunięcia flagi `PIDNS_HASH_ADDING`. Skutkuje to niepowodzeniem funkcji `alloc_pid` w przydzieleniu nowego PID podczas tworzenia nowego procesu, co skutkuje błędem "Nie można przydzielić pamięci".

3. **Rozwiązanie**:
- Problem można rozwiązać, używając opcji `-f` z `unshare`. Ta opcja sprawia, że `unshare` fork'uje nowy proces po utworzeniu nowej przestrzeni nazw PID.
- Wykonanie `%unshare -fp /bin/bash%` zapewnia, że polecenie `unshare` samo staje się PID 1 w nowej przestrzeni. `/bin/bash` i jego procesy potomne są wtedy bezpiecznie zawarte w tej nowej przestrzeni, co zapobiega przedwczesnemu zakończeniu PID 1 i umożliwia normalne przydzielanie PID.

Zapewniając, że `unshare` działa z flagą `-f`, nowa przestrzeń nazw PID jest prawidłowo utrzymywana, co pozwala na działanie `/bin/bash` i jego podprocesów bez napotkania błędu przydzielania pamięci.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Sprawdź, w którym namespace znajduje się twój proces
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Znajdź wszystkie przestrzenie nazw czasu
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Wejdź do przestrzeni nazw czasu
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
## Manipulowanie przesunięciami czasowymi

Począwszy od Linuxa 5.6, dwa zegary mogą być wirtualizowane na każdy namespace czasowy:

* `CLOCK_MONOTONIC`
* `CLOCK_BOOTTIME`

Ich różnice per-namespace są udostępniane (i mogą być modyfikowane) przez plik `/proc/<PID>/timens_offsets`:
```
$ sudo unshare -Tr --mount-proc bash   # -T creates a new timens, -r drops capabilities
$ cat /proc/$$/timens_offsets
monotonic 0
boottime  0
```
Plik zawiera dwie linie – po jednej dla każdego zegara – z przesunięciem w **nanosekundach**. Procesy, które mają **CAP_SYS_TIME** _w przestrzeni nazw czasu_, mogą zmieniać tę wartość:
```
# advance CLOCK_MONOTONIC by two days (172 800 s)
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
# verify
$ cat /proc/$$/uptime   # first column uses CLOCK_MONOTONIC
172801.37  13.57
```
Jeśli potrzebujesz, aby zegar ścienny (`CLOCK_REALTIME`) również się zmieniał, musisz nadal polegać na klasycznych mechanizmach (`date`, `hwclock`, `chronyd`, …); **nie** jest on przestrzennie izolowany.


### `unshare(1)` flagi pomocnicze (util-linux ≥ 2.38)
```
sudo unshare -T \
--monotonic="+24h"  \
--boottime="+7d"    \
--mount-proc         \
bash
```
Długie opcje automatycznie zapisują wybrane delty do `timens_offsets` zaraz po utworzeniu przestrzeni nazw, oszczędzając ręczne `echo`.

---

## Wsparcie OCI i Runtime

* **Specyfikacja Runtime OCI v1.1** (listopad 2023) dodała dedykowany typ przestrzeni nazw `time` oraz pole `linux.timeOffsets`, aby silniki kontenerowe mogły żądać wirtualizacji czasu w przenośny sposób.
* **runc >= 1.2.0** implementuje tę część specyfikacji. Minimalny fragment `config.json` wygląda następująco:
```json
{
"linux": {
"namespaces": [
{"type": "time"}
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Następnie uruchom kontener za pomocą `runc run <id>`.

>  UWAGA: runc **1.2.6** (luty 2025) naprawił błąd "exec do kontenera z prywatnym timens", który mógł prowadzić do zawieszenia i potencjalnego DoS. Upewnij się, że używasz wersji ≥ 1.2.6 w produkcji.

---

## Rozważania dotyczące bezpieczeństwa

1. **Wymagana zdolność** – Proces potrzebuje **CAP_SYS_TIME** wewnątrz swojej przestrzeni nazw użytkownika/czasu, aby zmienić offsety. Usunięcie tej zdolności w kontenerze (domyślnie w Dockerze i Kubernetes) zapobiega manipulacjom.
2. **Brak zmian zegara ściennego** – Ponieważ `CLOCK_REALTIME` jest współdzielony z hostem, atakujący nie mogą fałszować czasów życia certyfikatów, wygaśnięcia JWT itp. tylko za pomocą timens.
3. **Unikanie logów / detekcji** – Oprogramowanie, które polega na `CLOCK_MONOTONIC` (np. ograniczniki przepustowości oparte na czasie działania), może być zdezorientowane, jeśli użytkownik przestrzeni nazw dostosuje offset. Preferuj `CLOCK_REALTIME` dla znaczników czasowych istotnych dla bezpieczeństwa.
4. **Powierzchnia ataku jądra** – Nawet po usunięciu `CAP_SYS_TIME`, kod jądra pozostaje dostępny; utrzymuj hosta w aktualizacji. Linux 5.6 → 5.12 otrzymał wiele poprawek błędów timens (NULL-deref, problemy z sygnowaniem).

### Lista kontrolna wzmacniania

* Usuń `CAP_SYS_TIME` w domyślnym profilu uruchamiania kontenera.
* Utrzymuj runtime'y w aktualizacji (runc ≥ 1.2.6, crun ≥ 1.12).
* Ustal wersję util-linux ≥ 2.38, jeśli polegasz na pomocnikach `--monotonic/--boottime`.
* Audytuj oprogramowanie w kontenerze, które odczytuje **uptime** lub **CLOCK_MONOTONIC** dla logiki krytycznej dla bezpieczeństwa.

## Odniesienia

* man7.org – Strona podręcznika przestrzeni nazw czasu: <https://man7.org/linux/man-pages/man7/time_namespaces.7.html>
* Blog OCI – "OCI v1.1: nowe przestrzenie nazw czasu i RDT" (15 listopada 2023): <https://opencontainers.org/blog/2023/11/15/oci-spec-v1.1>

{{#include ../../../../banners/hacktricks-training.md}}
