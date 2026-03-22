# Maskowane ścieżki

{{#include ../../../../banners/hacktricks-training.md}}

Maskowane ścieżki to mechanizmy ochronne działające w czasie uruchomienia, które ukrywają szczególnie wrażliwe, względem jądra, lokalizacje w systemie plików przed kontenerem przez bind-mounting nad nimi lub w inny sposób uniemożliwiając do nich dostęp. Celem jest zapobieganie temu, by workload wchodził w bezpośrednie interakcje z interfejsami, których zwykłe aplikacje nie potrzebują, szczególnie wewnątrz procfs.

To ma znaczenie, ponieważ wiele container escapes i trików wpływających na hosta zaczyna się od odczytu lub zapisu specjalnych plików w katalogach `/proc` lub `/sys`. Jeśli te lokalizacje są maskowane, atakujący traci bezpośredni dostęp do użytecznej części powierzchni kontrolnej jądra nawet po uzyskaniu wykonania kodu wewnątrz kontenera.

## Działanie

Środowiska uruchomieniowe (runtimes) często maskują wybrane ścieżki, takie jak:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Dokładna lista zależy od runtime i konfiguracji hosta. Istotną właściwością jest to, że z punktu widzenia kontenera ścieżka staje się niedostępna lub zastąpiona, mimo że wciąż istnieje na hoście.

## Laboratorium

Sprawdź konfigurację masked-path ujawnioną przez Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Sprawdź faktyczne zachowanie montowania wewnątrz workloadu:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Wpływ na bezpieczeństwo

Masking nie stanowi głównej granicy izolacji, ale eliminuje kilka wysoko wartościowych celów post-exploitation. Bez masking, skompromitowany container może być w stanie sprawdzić stan jądra, odczytać wrażliwe informacje o procesach lub kluczach kryptograficznych, albo współdziałać z obiektami procfs/sysfs, które nigdy nie powinny być widoczne dla aplikacji.

## Nieprawidłowe konfiguracje

Głównym błędem jest unmasking szerokich klas ścieżek dla wygody lub debugowania. W Podman może to występować jako `--security-opt unmask=ALL` lub ukierunkowany unmasking. W Kubernetes nadmierna ekspozycja proc może pojawić się jako `procMount: Unmasked`. Innym poważnym problemem jest udostępnianie hosta `/proc` lub `/sys` przez bind mount, co całkowicie omija ideę zredukowanego widoku container.

## Wykorzystanie

Jeśli masking jest słaby lub nieobecny, zacznij od zidentyfikowania, które wrażliwe ścieżki procfs/sysfs są bezpośrednio osiągalne:
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

- `/proc/timer_list` może ujawnić dane timera i planisty hosta. To głównie prymityw rozpoznawczy, ale potwierdza, że kontener może czytać informacje skierowane do jądra, które zwykle są ukryte.
- `/proc/keys` jest znacznie bardziej wrażliwy. W zależności od konfiguracji hosta może ujawnić wpisy keyring, opisy kluczy oraz relacje między usługami hosta korzystającymi z podsystemu keyring jądra.
- `/sys/firmware` pomaga zidentyfikować tryb uruchamiania, interfejsy firmware oraz szczegóły platformy, które są użyteczne do fingerprintingu hosta i do zrozumienia, czy workload widzi stan na poziomie hosta.
- `/proc/config.gz` może ujawnić konfigurację uruchomionego jądra, co jest cenne do dopasowania wymagań publicznych exploitów jądra lub zrozumienia, dlaczego konkretna funkcja jest osiągalna.
- `/proc/sched_debug` ujawnia stan planisty i często obchodzi intuicyjne oczekiwanie, że przestrzeń nazw PID powinna całkowicie ukrywać informacje o niepowiązanych procesach.

Interesujące wyniki obejmują bezpośrednie odczyty tych plików, dowody na to, że dane należą do hosta, a nie do ograniczonego widoku kontenera, lub dostęp do innych lokalizacji procfs/sysfs, które zwykle są domyślnie maskowane.

## Sprawdzenia

Celem tych sprawdzeń jest ustalenie, które ścieżki runtime celowo ukrył i czy bieżący workload wciąż widzi zredukowany system plików skierowany do jądra.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Co jest tutaj interesujące:

- Długa lista masked-path jest normalna w hardened runtimes.
- Brak maskowania w wrażliwych wpisach procfs wymaga bliższej inspekcji.
- Jeśli wrażliwa ścieżka jest dostępna, a container ma też silne capabilities lub szerokie mounts, ekspozycja ma większe znaczenie.

## Domyślne ustawienia runtime

| Runtime / platform | Domyślny stan | Domyślne zachowanie | Typowe ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Włączone domyślnie | Docker definiuje domyślną masked path list | eksponowanie host proc/sys mounts, `--privileged` |
| Podman | Włączone domyślnie | Podman stosuje domyślne masked paths chyba że zostaną ręcznie unmasked | `--security-opt unmask=ALL`, targeted unmasking, `--privileged` |
| Kubernetes | Dziedziczy domyślne ustawienia runtime | Używa zachowania maskowania underlying runtime, chyba że ustawienia Pod osłabiają proc exposure | `procMount: Unmasked`, privileged workload patterns, broad host mounts |
| containerd / CRI-O under Kubernetes | Runtime default | Zwykle stosuje OCI/runtime masked paths chyba że zostaną nadpisane | bezpośrednie zmiany konfiguracji runtime, te same ścieżki osłabiające w Kubernetes |

Masked paths zwykle są obecne domyślnie. Główny problem operacyjny to nie brak w runtime, lecz celowe unmasking lub host bind mounts, które niweczą ochronę.
{{#include ../../../../banners/hacktricks-training.md}}
