# Maskowane ścieżki

{{#include ../../../../banners/hacktricks-training.md}}

Maskowane ścieżki to zabezpieczenia działające w czasie uruchomienia, które ukrywają przed kontenerem szczególnie wrażliwe lokalizacje systemu plików dostępne dla jądra — przez nakładanie na nie bind-mountów lub uniemożliwianie dostępu do nich w inny sposób. Specyfikacja OCI runtime definiuje `maskedPaths` jako ścieżki bezwzględne, które nie mogą być odczytywane wewnątrz kontenera. <sup>[[1]](#references)</sup>

Ma to znaczenie, ponieważ wiele technik ucieczki z kontenera i oddziałujących na hosta zaczyna się od odczytu lub zapisu specjalnych plików w `/proc` lub `/sys`. Jeśli te lokalizacje są maskowane, atakujący traci bezpośredni dostęp do przydatnej części interfejsu kontroli jądra, nawet po uzyskaniu możliwości wykonywania kodu wewnątrz kontenera.

## Działanie

Środowiska uruchomieniowe często maskują wybrane ścieżki, takie jak:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Dokładna lista zależy od środowiska uruchomieniowego i konfiguracji hosta. Ważne jest to, że z punktu widzenia kontenera ścieżka staje się niedostępna lub zostaje zastąpiona, mimo że nadal istnieje na hoście.

## Laboratorium

Sprawdź konfigurację maskowanych ścieżek udostępnianą przez Docker:

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```

Sprawdź rzeczywiste zachowanie montowania wewnątrz obciążenia:

```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```

Wymieniona ścieżka niekoniecznie jest dostępna do odczytu: runc może zamaskować plik za pomocą bind mountu `/dev/null`, a katalog — za pomocą pustego tmpfs tylko do odczytu. Sprawdź dokładny punkt montowania, a nie tylko to, czy `ls` działa. <sup>[[4]](#references)</sup>

## Wpływ na bezpieczeństwo

Maskowanie nie tworzy głównej granicy izolacji, ale usuwa kilka atrakcyjnych celów po eksploatacji. Bez maskowania przejęty kontener może być w stanie sprawdzać stan jądra, odczytywać poufne informacje o procesach lub kluczach albo wchodzić w interakcję z obiektami procfs/sysfs, które nigdy nie powinny być widoczne dla aplikacji.

## Błędna konfiguracja

Głównym błędem jest odsłanianie szerokich grup ścieżek dla wygody lub debugowania. W Podman może się to odbywać za pomocą `--security-opt unmask=ALL` lub selektywnego odsłaniania ścieżek. <sup>[[2]](#references)</sup> W Kubernetes nadmiernie szeroki dostęp do proc może być konfigurowany przez `procMount: Unmasked`; obecnie Kubernetes wymaga dla tego ustawienia `spec.hostUsers: false` (przestrzeni nazw użytkowników), natomiast wersje 1.12–1.29 nie egzekwowały tego wymogu. <sup>[[3]](#references)</sup> Innym poważnym problemem jest udostępnianie hostowego `/proc` lub `/sys` przez bind mount, co całkowicie niweczy ideę ograniczonego widoku kontenera.

## Nadużycie

Jeśli maskowanie jest niewystarczające lub go brakuje, zacznij od ustalenia, które wrażliwe ścieżki procfs/sysfs są bezpośrednio dostępne:

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

Jeśli rzekomo zamaskowana ścieżka jest dostępna, dokładnie ją sprawdź:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

Co mogą ujawnić te polecenia:

- `/proc/timer_list` może ujawnić dane hosta dotyczące timerów i planisty. To przede wszystkim prymityw rozpoznawczy, ale potwierdza, że kontener może odczytywać informacje związane z jądrem, które zwykle są ukryte.
- `/proc/keys` wyświetla metadane tylko tych kluczy, do których czytelnik ma uprawnienie **view**, z uwzględnieniem kontroli LSM. Może ujawnić typy i opisy kluczy, ale nie zrzuca ich zawartości. <sup>[[6]](#references)</sup>
- `/sys/firmware` pomaga ustalić tryb rozruchu, interfejsy firmware'u i szczegóły platformy przydatne do fingerprintingu hosta oraz oceny, czy workload widzi stan na poziomie hosta.
- `/proc/config.gz` może ujawnić konfigurację uruchomionego jądra, co jest przydatne przy sprawdzaniu wymagań publicznych exploitów jądra lub ustalaniu, dlaczego dostępna jest dana funkcja.
- `/proc/sched_debug` ujawnia stan planisty i często przeczy intuicyjnemu założeniu, że PID namespace całkowicie ukrywa informacje o niepowiązanych procesach.

Interesujące wyniki to bezpośredni odczyt tych plików, dowody, że dane pochodzą z hosta, a nie z ograniczonego widoku kontenera, lub dostęp do innych lokalizacji procfs/sysfs, które są zwykle domyślnie maskowane.

### Race condition źródła maski podczas uruchamiania kontenera

W podatnych implementacjach runc maski plików zależą od inode `/dev/null` w kontenerze. Atakujący, który może uruchamiać równolegle kontenery ze współdzielonymi mountami, w tym równoległe kroki BuildKit, może wykorzystać race condition podczas uruchamiania i usunąć `/dev/null`, zanim runc zamontuje go w miejscu maskowanych plików procfs. Runtime uznaje wtedy brakujące **źródło** za brak miejsca docelowego maski i po cichu pomija te maski plików. Błąd zależy od race condition podczas konfiguracji runtime; usunięcie `/dev/null` po uruchomieniu nie cofa już zainstalowanej maski. <sup>[[4]](#references)</sup>

Po kontrolowanym teście porównaj żądaną listę masek z dokładnymi punktami montowania w nowym kontenerze. <sup>[[4]](#references)</sup> `findmnt -M` sprawdza wskazany punkt montowania i nie przechodzi do nadrzędnego mounta; jeśli `findmnt` nie jest dostępne, sprawdź `/proc/self/mountinfo`. <sup>[[5]](#references)</sup> Pomyślny wynik `ls` ani pusty wynik `cat` nie dowodzą, że maski nie ma. <sup>[[4]](#references)</sup>

Użyj [poniższych kontroli](#checks), aby porównać żądane maski z dokładnymi punktami montowania w nowym kontenerze.

Pominięta maska pliku może ujawnić dane procfs, jeśli pozwalają na to standardowe uprawnienia i polityka LSM. Sama w sobie **nie** umożliwia zapisu do `/proc/sys`: to osobna kontrola [read-only-path](read-only-paths.md). Odmienny przypadek podstawienia symlinka `/dev/null`, który może przekierować bind mount do zapisywalnego celu procfs, opisano w sekcji [race condition runtime'u w PID namespace](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs). <sup>[[4]](#references)</sup>

## Kontrole

Celem tych kontroli jest ustalenie, które ścieżki runtime celowo ukrył oraz czy bieżący workload nadal widzi ograniczony system plików związany z jądrem.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

Użyj dokładnego sprawdzenia mountpointu, ponieważ zamaskowany plik nadal może istnieć, a odczyt może zwrócić pusty wynik z `/dev/null`. Brak mountpointu to ustalenie wymagające zbadania, a nie samodzielny dowód na możliwość odczytu danych hosta. <sup>[[4]](#references)[[5]](#references)</sup>

Co jest tu istotne:

- Długa lista zamaskowanych ścieżek jest normalna w hardened runtime.
- Brak maskowania wrażliwych wpisów procfs wymaga dokładniejszej analizy.
- Jeśli dostępna jest wrażliwa ścieżka, a kontener ma też silne capabilities lub szerokie mounty, ekspozycja ma większe znaczenie.

## Runtime Defaults

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Typowe ręczne osłabienia |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie włączone | Docker definiuje domyślną listę zamaskowanych ścieżek | udostępnianie mountów hosta proc/sys, `--privileged` |
| Podman | Domyślnie włączone | Podman stosuje domyślne zamaskowane ścieżki, o ile nie zostaną ręcznie odmaskowane | `--security-opt unmask=ALL`, selektywne odmaskowywanie, `--privileged` |
| Kubernetes | Dziedziczy domyślne ustawienia runtime | Używa zachowania maskowania bazowego runtime, o ile ustawienia poda nie osłabiają ekspozycji proc | `procMount: Unmasked` (w bieżących wydaniach wymaga `hostUsers: false`), wzorce uprzywilejowanych workloadów, szerokie mounty hosta |
| containerd / CRI-O w Kubernetes | Domyślne ustawienie runtime | Zwykle stosuje zamaskowane ścieżki OCI/runtime, o ile nie zostaną nadpisane | bezpośrednie zmiany konfiguracji runtime, te same ścieżki osłabień w Kubernetes |

Zamaskowane ścieżki są zwykle obecne domyślnie. Główny problem operacyjny nie polega na ich braku w runtime, lecz na celowym odmaskowaniu lub mountach bind hosta, które niwelują tę ochronę.

## References

- [1] [Open Container Initiative - Konfiguracja kontenerów Linux: Masked Paths](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Dokumentacja Podman - opcje bezpieczeństwa `podman run`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Dokumentacja Kubernetes - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [Ostrzeżenie runc: wyścig źródła mountu masked-path](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [Podręcznik findmnt(8)](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [Podręcznik keyrings(7)](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}
