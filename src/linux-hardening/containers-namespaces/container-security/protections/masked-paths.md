# Maskowane ścieżki

{{#include ../../../../banners/hacktricks-training.md}}

Maskowane ścieżki to zabezpieczenia runtime, które ukrywają przed kontenerem szczególnie wrażliwe lokalizacje systemu plików obsługujące kernel, nakładając na nie bind mount lub w inny sposób uniemożliwiając dostęp do nich. Ich celem jest uniemożliwienie workloadowi bezpośredniej interakcji z interfejsami, których zwykłe aplikacje nie potrzebują, szczególnie wewnątrz procfs.

Ma to znaczenie, ponieważ wiele container escapes i technik wpływających na hosta zaczyna się od odczytu lub zapisu specjalnych plików w `/proc` albo `/sys`. Jeśli te lokalizacje są maskowane, attacker traci bezpośredni dostęp do użytecznej części powierzchni kontrolnej kernela, nawet po uzyskaniu code execution wewnątrz kontenera.

## Działanie

Runtimes często maskują wybrane ścieżki, takie jak:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Dokładna lista zależy od runtime i konfiguracji hosta. Ważną właściwością jest to, że z perspektywy kontenera ścieżka staje się niedostępna lub zostaje zastąpiona, mimo że nadal istnieje na hoście.

## Laboratorium

Sprawdź konfigurację masked paths udostępnianą przez Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Sprawdź rzeczywiste zachowanie mountowania wewnątrz workloadu:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Wpływ na bezpieczeństwo

Maskowanie nie tworzy głównej granicy izolacji, ale usuwa kilka wartościowych celów post-exploitation. Bez maskowania przejęty kontener może być w stanie sprawdzać stan kernela, odczytywać poufne informacje o procesach lub kluczach albo wchodzić w interakcję z obiektami procfs/sysfs, które nigdy nie powinny być widoczne dla aplikacji.

## Błędne konfiguracje

Głównym błędem jest znoszenie maskowania szerokich klas ścieżek dla wygody lub debugowania. W Podman może to występować jako `--security-opt unmask=ALL` albo selektywne znoszenie maskowania. W Kubernetes nadmiernie szeroka ekspozycja proc może występować przez `procMount: Unmasked`. Innym poważnym problemem jest udostępnienie host `/proc` lub `/sys` przez bind mount, co całkowicie omija założenie ograniczonego widoku kontenera.

## Nadużycie

Jeśli maskowanie jest słabe lub nieobecne, zacznij od ustalenia, które poufne ścieżki procfs/sysfs są bezpośrednio dostępne:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Jeśli rzekomo zamaskowana ścieżka jest dostępna, dokładnie ją przeanalizuj:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Co te polecenia mogą ujawnić:

- `/proc/timer_list` może ujawnić dane hosta dotyczące timerów i schedulera. Jest to głównie reconnaissance primitive, ale potwierdza, że kontener może odczytywać informacje związane z kernelem, które zwykle są ukryte.
- `/proc/keys` jest znacznie bardziej wrażliwy. W zależności od konfiguracji hosta może ujawnić wpisy keyringu, opisy kluczy oraz zależności między usługami hosta korzystającymi z kernelowego podsystemu keyringu.
- `/sys/firmware` pomaga zidentyfikować tryb uruchamiania, interfejsy firmware oraz szczegóły platformy przydatne do fingerprintingu hosta i ustalenia, czy workload ma dostęp do stanu na poziomie hosta.
- `/proc/config.gz` może ujawnić konfigurację uruchomionego kernela, co jest cenne przy dopasowywaniu wymagań wstępnych publicznych exploitów kernela lub ustalaniu, dlaczego określona funkcja jest dostępna.
- `/proc/sched_debug` ujawnia stan schedulera i często podważa intuicyjne oczekiwanie, że PID namespace powinien całkowicie ukrywać informacje o niepowiązanych procesach.

Interesujące wyniki obejmują bezpośredni odczyt tych plików, dowody na to, że dane należą do hosta, a nie do ograniczonego widoku kontenera, oraz dostęp do innych lokalizacji procfs/sysfs, które domyślnie są często maskowane.

## Checks

Celem tych checks jest ustalenie, które ścieżki runtime celowo ukrył oraz czy bieżący workload nadal widzi ograniczony filesystem związany z kernelem.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Co jest tutaj interesujące:

- Długa lista masked paths jest normalna w hardened runtimes.
- Brak maskowania wrażliwych wpisów procfs zasługuje na dokładniejszą analizę.
- Jeśli wrażliwa ścieżka jest dostępna, a kontener ma również silne capabilities lub szerokie mounty, ekspozycja ma większe znaczenie.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Typowe ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Włączone domyślnie | Docker definiuje domyślną listę masked paths | udostępnianie mountów host proc/sys, `--privileged` |
| Podman | Włączone domyślnie | Podman stosuje domyślne masked paths, chyba że zostaną one ręcznie odmaskowane | `--security-opt unmask=ALL`, ukierunkowane odmaskowanie, `--privileged` |
| Kubernetes | Dziedziczy ustawienia domyślne runtime | Używa zachowania maskowania bazowego runtime, chyba że ustawienia Pod osłabiają ochronę proc | `procMount: Unmasked`, wzorce uprzywilejowanych workloadów, szerokie mounty host |
| containerd / CRI-O under Kubernetes | Ustawienia domyślne runtime | Zwykle stosuje masked paths OCI/runtime, chyba że zostaną nadpisane | bezpośrednie zmiany konfiguracji runtime, te same ścieżki osłabienia w Kubernetes |

Masked paths są zwykle obecne domyślnie. Głównym problemem operacyjnym nie jest ich brak w runtime, lecz celowe odmaskowanie lub bind mounty host, które niwelują tę ochronę.
{{#include ../../../../banners/hacktricks-training.md}}
