# Maskowane ścieżki

{{#include ../../../../banners/hacktricks-training.md}}

Maskowane ścieżki to zabezpieczenia uruchomieniowe, które ukrywają szczególnie wrażliwe, skierowane do jądra lokalizacje systemu plików przed kontenerem przez nadmontowanie ich (bind-mount) lub w inny sposób uniemożliwiają dostęp. Celem jest zapobieganie bezpośredniej interakcji workloadu z interfejsami, których zwykłe aplikacje nie potrzebują, szczególnie w obrębie procfs.

Ma to znaczenie, ponieważ wiele container escape'ów i trików wpływających na hosta zaczyna się od odczytu lub zapisu specjalnych plików pod `/proc` lub `/sys`. Jeśli te lokalizacje są maskowane, atakujący traci bezpośredni dostęp do przydatnej części powierzchni kontrolnej jądra nawet po uzyskaniu wykonania kodu wewnątrz kontenera.

## Działanie

Środowiska uruchomieniowe często maskują wybrane ścieżki, takie jak:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Dokładna lista zależy od runtime'u i konfiguracji hosta. Ważną właściwością jest to, że z punktu widzenia kontenera ścieżka staje się niedostępna lub zastąpiona, mimo że nadal istnieje na hoście.

## Laboratorium

Inspect the masked-path configuration exposed by Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Sprawdź rzeczywiste zachowanie mountów wewnątrz workloadu:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Wpływ na bezpieczeństwo

Maskowanie nie tworzy głównej granicy izolacji, ale usuwa kilka wysokowartościowych post-exploitation targets. Bez maskowania skompromitowany kontener może mieć możliwość inspekcji stanu jądra, odczytu wrażliwych informacji o procesach lub informacji o kluczach, albo interakcji z obiektami procfs/sysfs, które nigdy nie powinny być widoczne dla aplikacji.

## Nieprawidłowe konfiguracje

Głównym błędem jest odmaskowywanie szerokich klas ścieżek dla wygody lub debugowania. W Podman może to wyglądać jak `--security-opt unmask=ALL` lub ukierunkowane odmaskowywanie. W Kubernetes zbyt szeroka ekspozycja proc może przejawiać się przez `procMount: Unmasked`. Innym poważnym problemem jest eksponowanie hostowego `/proc` lub `/sys` przez bind mount, co całkowicie omija ideę zredukowanego widoku kontenera.

## Wykorzystywanie

Jeśli maskowanie jest słabe lub nieobecne, zacznij od zidentyfikowania, które wrażliwe ścieżki procfs/sysfs są bezpośrednio osiągalne:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Jeśli rzekomo zamaskowana ścieżka jest dostępna, dokładnie ją sprawdź:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Co te polecenia mogą ujawnić:

- `/proc/timer_list` może ujawnić hostowe dane dotyczące timerów i scheduler. To w przeważającej mierze prymityw rozpoznawczy, ale potwierdza, że container może czytać informacje skierowane do kernel, które normalnie są ukryte.
- `/proc/keys` jest znacznie bardziej wrażliwy. W zależności od konfiguracji hosta może ujawnić keyring entries, key descriptions oraz powiązania między usługami hosta korzystającymi z kernel keyring subsystem.
- `/sys/firmware` pomaga zidentyfikować boot mode, firmware interfaces i szczegóły platformy, które są przydatne do host fingerprinting oraz do zrozumienia, czy workload widzi host-level state.
- `/proc/config.gz` może ujawnić konfigurację uruchomionego kernel, co jest wartościowe przy dopasowywaniu wymagań public kernel exploit lub zrozumieniu, dlaczego konkretny feature jest osiągalny.
- `/proc/sched_debug` ujawnia stan scheduler i często omija intuicyjne oczekiwanie, że PID namespace powinien całkowicie ukrywać niezwiązane informacje o procesach.

Interesujące wyniki to m.in. bezpośrednie odczyty tych plików, dowody na to, że dane należą do hosta, a nie do ograniczonego widoku container, lub dostęp do innych procfs/sysfs lokalizacji, które zwykle są domyślnie maskowane.

## Sprawdzenia

Celem tych sprawdzeń jest ustalenie, które ścieżki runtime celowo ukrył i czy bieżący workload nadal widzi zredukowany kernel-facing filesystem.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Co jest interesujące tutaj:

- Długa lista masked-path jest normalna w hardened runtimes.
- Brak maskowania w przypadku wrażliwych wpisów procfs wymaga dokładniejszej inspekcji.
- Jeśli wrażliwa ścieżka jest dostępna i container ma też rozbudowane capabilities lub szerokie mounts, ekspozycja ma większe znaczenie.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Włączone domyślnie | Docker definiuje domyślną listę masked paths | ujawnianie hostowych proc/sys mountów, `--privileged` |
| Podman | Włączone domyślnie | Podman stosuje domyślne masked paths, chyba że zostaną odmaskowane ręcznie | `--security-opt unmask=ALL`, skierowane odmaskowanie, `--privileged` |
| Kubernetes | Dziedziczy domyślne ustawienia runtime | Używa zachowania maskowania leżącego poniżej runtime, chyba że ustawienia Poda osłabiają ekspozycję proc | `procMount: Unmasked`, wzorce workloadów typu privileged, szerokie hostowe mounty |
| containerd / CRI-O under Kubernetes | Domyślne ustawienie runtime | Zwykle stosuje OCI/runtime masked paths, chyba że jest nadpisane | bezpośrednie zmiany konfiguracji runtime, te same mechanizmy osłabiania w Kubernetes |

Masked paths są zazwyczaj obecne domyślnie. Głównym problemem operacyjnym nie jest ich brak w runtime, lecz celowe odmaskowanie lub hostowe bind mounty, które niweczą ochronę.
