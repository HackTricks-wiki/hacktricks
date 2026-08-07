# Maskowane ścieżki

{{#include ../../../../banners/hacktricks-training.md}}

Maskowane ścieżki to zabezpieczenia runtime, które ukrywają przed kontenerem szczególnie wrażliwe lokalizacje systemu plików związane z kernelem, montując na nich bind mounty lub w inny sposób uniemożliwiając dostęp do nich. Ich celem jest uniemożliwienie workloadowi bezpośredniej interakcji z interfejsami, których zwykłe aplikacje nie potrzebują, zwłaszcza wewnątrz procfs.

Ma to znaczenie, ponieważ wiele container escapes i technik wpływających na hosta zaczyna się od odczytu lub zapisu specjalnych plików w `/proc` lub `/sys`. Jeśli te lokalizacje są zamaskowane, attacker traci bezpośredni dostęp do użytecznej części kernelowego interfejsu kontroli, nawet po uzyskaniu code execution wewnątrz kontenera.

## Działanie

Runtimes często maskują wybrane ścieżki, takie jak:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Dokładna lista zależy od runtime i konfiguracji hosta. Ważną właściwością jest to, że z perspektywy kontenera ścieżka staje się niedostępna lub zostaje zastąpiona, mimo że nadal istnieje na hoście.

## Lab

Sprawdź konfigurację masked paths udostępnianą przez Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Zbadaj rzeczywiste zachowanie montowania wewnątrz workloadu:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Wpływ na bezpieczeństwo

Maskowanie nie tworzy głównej granicy izolacji, ale usuwa kilka celów o wysokiej wartości w post-exploitation. Bez maskowania przejęty kontener może być w stanie sprawdzać stan kernela, odczytywać poufne informacje o procesach lub kluczach albo wchodzić w interakcję z obiektami procfs/sysfs, które nigdy nie powinny być widoczne dla aplikacji.

## Błędne konfiguracje

Głównym błędem jest odmaskowanie szerokich klas ścieżek dla wygody lub debugowania. W Podman może się to pojawić jako `--security-opt unmask=ALL` lub ukierunkowane odmaskowanie. W Kubernetes nadmiernie szeroka ekspozycja proc może wystąpić przez `procMount: Unmasked`. Innym poważnym problemem jest udostępnienie hosta `/proc` lub `/sys` przez bind mount, co całkowicie omija ideę ograniczonego widoku kontenera.

## Nadużycie

Jeśli maskowanie jest słabe lub nieobecne, zacznij od ustalenia, które wrażliwe ścieżki procfs/sysfs są bezpośrednio dostępne:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Jeśli rzekomo zamaskowana ścieżka jest dostępna, dokładnie ją zbadaj:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Co mogą ujawnić te polecenia:

- `/proc/timer_list` może ujawnić dane host dotyczące timerów i schedulera. Jest to głównie primitive reconnaissance, ale potwierdza, że container może odczytywać informacje związane z kernelem, które normalnie są ukryte.
- `/proc/keys` jest znacznie bardziej wrażliwy. W zależności od konfiguracji host może ujawniać wpisy keyringu, opisy kluczy oraz relacje między usługami hosta korzystającymi z subsystemu kernel keyring.
- `/sys/firmware` pomaga zidentyfikować tryb uruchamiania, interfejsy firmware oraz szczegóły platformy przydatne do fingerprintingu hosta i ustalenia, czy workload widzi stan na poziomie hosta.
- `/proc/config.gz` może ujawnić konfigurację uruchomionego kernela, co jest przydatne przy dopasowywaniu wymagań wstępnych publicznych exploitów kernela lub zrozumieniu, dlaczego określona funkcja jest dostępna.
- `/proc/sched_debug` ujawnia stan schedulera i często obala intuicyjne założenie, że PID namespace powinien całkowicie ukrywać informacje o niezwiązanych procesach.

Interesujące wyniki obejmują bezpośredni odczyt tych plików, dowody na to, że dane należą do hosta, a nie do ograniczonego widoku containera, lub dostęp do innych lokalizacji procfs/sysfs, które domyślnie są zwykle maskowane.

## Checks

Celem tych checks jest ustalenie, które ścieżki runtime celowo ukrył oraz czy bieżący workload nadal widzi ograniczony filesystem mający dostęp do kernela.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Co jest tutaj interesujące:

- Długa lista maskowanych ścieżek jest normalna w hardened runtimes.
- Brak maskowania wrażliwych wpisów procfs wymaga dokładniejszej analizy.
- Jeśli wrażliwa ścieżka jest dostępna, a container ma również silne capabilities lub szerokie mounts, ekspozycja ma większe znaczenie.

## Domyślne ustawienia runtime'u

| Runtime / platforma | Stan domyślny | Domyślne działanie | Typowe ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Włączone domyślnie | Docker definiuje domyślną listę maskowanych ścieżek | udostępnianie hostowych mounts proc/sys, `--privileged` |
| Podman | Włączone domyślnie | Podman stosuje domyślne maskowane ścieżki, chyba że zostaną one ręcznie odmaskowane | `--security-opt unmask=ALL`, selektywne odmaskowanie, `--privileged` |
| Kubernetes | Dziedziczy domyślne ustawienia runtime'u | Używa zachowania maskowania bazowego runtime'u, chyba że ustawienia Pod osłabiają ochronę proc | `procMount: Unmasked`, wzorce uprzywilejowanych workloadów, szerokie host mounts |
| containerd / CRI-O under Kubernetes | Domyślne ustawienia runtime'u | Zwykle stosuje maskowane ścieżki OCI/runtime'u, chyba że zostaną nadpisane | bezpośrednie zmiany konfiguracji runtime'u, te same ścieżki osłabiania w Kubernetes |

Maskowane ścieżki są zwykle obecne domyślnie. Głównym problemem operacyjnym nie jest ich brak w runtime, lecz celowe odmaskowanie lub host bind mounts, które niwelują tę ochronę.

{{#include ../../../../banners/hacktricks-training.md}}
