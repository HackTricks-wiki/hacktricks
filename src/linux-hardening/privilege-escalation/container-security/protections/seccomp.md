# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

**seccomp** to mechanizm, który pozwala kernelowi zastosować filtr do syscalli, które proces może wywołać. W środowiskach konteneryzowanych seccomp jest zwykle używany w trybie filtra, tak aby proces nie był po prostu oznaczony jako "restricted" w niejasnym sensie, lecz podlegał konkretnej polityce syscalli. Ma to znaczenie, ponieważ wiele container breakouts wymaga dostępu do bardzo specyficznych interfejsów kernela. Jeśli proces nie może pomyślnie wywołać odpowiednich syscalli, duża klasa ataków znika, zanim jakiekolwiek niuanse namespaces czy capabilities staną się istotne.

Podstawowy model myślenia jest prosty: namespaces decydują **co proces może zobaczyć**, capabilities decydują **jakie uprzywilejowane działania proces może nominalnie próbować wykonać**, a seccomp decyduje **czy kernel w ogóle zaakceptuje punkt wejścia syscall dla podejmowanej akcji**. Dlatego seccomp często uniemożliwia ataki, które na podstawie samych capabilities wyglądałyby na możliwe.

## Wpływ na bezpieczeństwo

Wiele niebezpiecznych powierzchni kernela jest dostępnych jedynie przez stosunkowo niewielki zbiór syscalli. Przykłady, które wielokrotnie mają znaczenie przy hardeningu kontenerów, to `mount`, `unshare`, `clone` lub `clone3` z określonymi flagami, `bpf`, `ptrace`, `keyctl` i `perf_event_open`. Atakujący, który ma dostęp do tych syscalli, może być w stanie utworzyć nowe namespaces, manipulować subsystemami kernela lub oddziaływać z powierzchnią ataku, której normalny kontener aplikacji wcale nie potrzebuje.

Dlatego domyślne profile seccomp w runtime są tak ważne. Nie są one jedynie "dodatkową obroną". W wielu środowiskach stanowią różnicę między kontenerem, który może korzystać z szerokiej części funkcjonalności kernela, a takim, który jest ograniczony do zestawu syscalli bliższego temu, czego aplikacja rzeczywiście potrzebuje.

## Tryby i budowa filtra

Seccomp historycznie miał tryb strict, w którym dostępny pozostawał tylko niewielki zestaw syscalli, ale tryb istotny dla nowoczesnych container runtimes to seccomp filter mode, często nazywany **seccomp-bpf**. W tym modelu kernel ocenia program filtra, który decyduje, czy syscall powinien być dozwolony, odrzucony z errno, przechwycony, zalogowany, lub spowodować zabicie procesu. Container runtimes wykorzystują ten mechanizm, ponieważ jest wystarczająco ekspresyjny, by blokować szerokie klasy niebezpiecznych syscalli, a jednocześnie pozwalać na normalne zachowanie aplikacji.

Dwa niskopoziomowe przykłady są przydatne, ponieważ czynią mechanizm konkretnym zamiast magicznym. Tryb strict demonstruje stary model "przetrwa tylko minimalny zestaw syscalli":
```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
int output = open("output.txt", O_WRONLY);
const char *val = "test";
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
write(output, val, strlen(val) + 1);
open("output.txt", O_RDONLY);
}
```
Ostatnie `open` powoduje zabicie procesu, ponieważ nie jest częścią minimalnego zestawu trybu strict.

Przykład filtra libseccomp wyraźniej pokazuje nowoczesny model polityki:
```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));
seccomp_load(ctx);
seccomp_release(ctx);
printf("pid=%d\n", getpid());
}
```
Taki styl polityki powinni sobie wyobrazić większość czytelników, gdy myślą o runtime seccomp profiles.

## Laboratorium

Najprostszy sposób, aby potwierdzić, że seccomp jest aktywny w containerze, to:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Możesz też spróbować operacji, którą domyślne profile zwykle ograniczają:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Jeśli kontener działa pod zwykłym domyślnym profilem seccomp, operacje w stylu `unshare` są często blokowane. To przydatna demonstracja, ponieważ pokazuje, że nawet jeśli narzędzie userspace istnieje w obrazie, ścieżka jądra, której potrzebuje, może być nadal niedostępna.
Jeśli kontener działa pod zwykłym domyślnym profilem seccomp, operacje w stylu `unshare` są często blokowane, nawet gdy narzędzie userspace istnieje w obrazie.

Aby ogólniej sprawdzić status procesu, uruchom:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Użycie w czasie wykonywania

Docker obsługuje zarówno domyślne, jak i niestandardowe profile seccomp i pozwala administratorom wyłączyć je za pomocą `--security-opt seccomp=unconfined`. Podman oferuje podobne wsparcie i często łączy seccomp z uruchamianiem bez uprawnień root, co daje rozsądne ustawienia domyślne. Kubernetes udostępnia seccomp przez konfigurację workload, gdzie `RuntimeDefault` zazwyczaj jest rozsądną wartością bazową, a `Unconfined` powinno być traktowane jako wyjątek wymagający uzasadnienia, a nie jako wygodny przełącznik.

W środowiskach opartych na containerd i CRI-O dokładna ścieżka jest bardziej wielowarstwowa, ale zasada jest taka sama: silnik wyższego poziomu lub orchestrator decyduje, co ma się stać, a runtime ostatecznie instaluje wynikową politykę seccomp dla procesu kontenera. Wynik nadal zależy od końcowej konfiguracji runtime, która dociera do jądra.

### Przykład niestandardowej polityki

Docker i podobne silniki mogą załadować niestandardowy profil seccomp z JSON. Minimalny przykład, który odrzuca `chmod`, jednocześnie pozwalając na wszystko inne, wygląda tak:
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
Nie dołączyłeś treści pliku. Proszę wklej zawartość pliku src/linux-hardening/privilege-escalation/container-security/protections/seccomp.md, który mam przetłumaczyć na polski — zachowam dokładnie tę samą składnię markdown/HTML i nie będę tłumaczyć tagów, linków ani ścieżek.
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Polecenie kończy się błędem `Operation not permitted`, co pokazuje, że ograniczenie wynika z polityki syscalli, a nie tylko z zwykłych uprawnień plików. W praktycznym utwardzaniu systemu allowlists są zazwyczaj silniejsze niż permisywne domyślne ustawienia z małym blacklist.

## Misconfigurations

Najpoważniejszym błędem jest ustawienie seccomp na **unconfined**, ponieważ aplikacja nie działała przy domyślnej polityce. To częste podczas rozwiązywania problemów i bardzo niebezpieczne jako stałe rozwiązanie. Po usunięciu filtra wiele prymitywów ucieczki opartych na syscallach znów staje się osiągalnych, szczególnie jeśli dostępne są potężne capabilities lub współdzielony namespace hosta.

Kolejnym częstym problemem jest użycie **custom permissive profile**, skopiowanego z jakiegoś bloga lub wewnętrznego workaroundu bez dokładnej weryfikacji. Zespoły czasem pozostawiają prawie wszystkie niebezpieczne syscalle, po prostu dlatego, że profil był zbudowany wokół „przestań łamać aplikację” zamiast „przyznaj tylko to, czego aplikacja naprawdę potrzebuje”. Trzeci błąd polega na założeniu, że seccomp jest mniej ważny dla non-root containers. W rzeczywistości sporo powierzchni ataku jądra pozostaje istotne nawet gdy proces nie ma UID 0.

## Abuse

Jeśli seccomp jest nieobecny lub poważnie osłabiony, atakujący może wywołać syscalle tworzące namespace, rozszerzyć osiągalną powierzchnię ataku jądra przez `bpf` lub `perf_event_open`, nadużyć `keyctl`, albo połączyć te ścieżki syscalli z niebezpiecznymi capability, takimi jak `CAP_SYS_ADMIN`. W wielu rzeczywistych atakach seccomp nie jest jedynym brakującym mechanizmem kontroli, ale jego brak skraca ścieżkę exploitu dramatycznie, ponieważ usuwa jedną z nielicznych obron, które mogą zatrzymać ryzykowny syscall zanim reszta modelu uprawnień zacznie działać.

Najbardziej praktycznym testem jest wypróbowanie dokładnych rodzin syscalli, które domyślne profile zwykle blokują. Jeśli nagle działają, stan zabezpieczeń kontenera uległ dużej zmianie:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Jeśli `CAP_SYS_ADMIN` lub inna silna capability jest obecna, sprawdź, czy seccomp jest jedyną brakującą barierą przed mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Na niektórych celach natychmiastowa wartość nie polega na pełnym escape, lecz na information gathering i kernel attack-surface expansion. Te polecenia pomagają ustalić, czy szczególnie wrażliwe syscall paths są osiągalne:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Jeśli seccomp jest nieobecny i kontener jest dodatkowo uprzywilejowany w innych aspektach, wtedy ma sens przejście do bardziej szczegółowych technik breakout, które zostały już udokumentowane na stronach legacy container-escape.

### Pełny przykład: seccomp był jedyną rzeczą blokującą `unshare`

Na wielu celach praktyczny efekt usunięcia seccomp jest taki, że wywołania systemowe związane z tworzeniem namespace'ów lub mount nagle zaczynają działać. Jeśli kontener ma również `CAP_SYS_ADMIN`, następująca sekwencja może stać się możliwa:
```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
mount -t tmpfs tmpfs /tmp/nsroot &&
mkdir -p /tmp/nsroot/proc &&
mount -t proc proc /tmp/nsroot/proc &&
mount | grep /tmp/nsroot
'
```
Sam w sobie to jeszcze nie jest host escape, ale pokazuje, że seccomp był barierą uniemożliwiającą mount-related exploitation.

### Pełny przykład: seccomp wyłączony + cgroup v1 `release_agent`

Jeśli seccomp jest wyłączony i container może zamontować hierarchie cgroup v1, technika `release_agent` z sekcji cgroups staje się osiągalna:
```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
To nie jest seccomp-only exploit. Chodzi o to, że gdy seccomp przestanie być ograniczony, syscall-heavy breakout chains, które wcześniej były blokowane, mogą zacząć działać dokładnie tak, jak zostały napisane.

## Sprawdzenia

Celem tych sprawdzeń jest ustalenie, czy seccomp jest w ogóle aktywny, czy towarzyszy mu `no_new_privs`, oraz czy konfiguracja runtime wyraźnie pokazuje, że seccomp jest wyłączony.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Co jest tutaj interesujące:

- Niezerowa wartość `Seccomp` oznacza, że filtrowanie jest aktywne; `0` zwykle oznacza brak ochrony seccomp.
- Jeśli opcje zabezpieczeń runtime zawierają `seccomp=unconfined`, kontener stracił jedną z najważniejszych obron na poziomie syscall.
- `NoNewPrivs` nie jest samym seccomp, ale widok obu razem zwykle wskazuje na bardziej ostrożną postawę hardeningu niż brak obu.

Jeśli kontener już ma podejrzane mounts, broad capabilities, lub shared host namespaces, a seccomp jest również unconfined, tę kombinację należy traktować jako poważny sygnał eskalacji. Kontener nadal może nie być trywialnie przełamany, ale liczba punktów wejścia do jądra dostępnych dla atakującego gwałtownie wzrosła.

## Domyślne ustawienia środowiska uruchomieniowego

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Zazwyczaj włączone domyślnie | Używa wbudowanego domyślnego profilu seccomp Dockera, chyba że zostanie nadpisany | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Zazwyczaj włączone domyślnie | Stosuje domyślny profil seccomp runtime, chyba że zostanie nadpisany | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Nie gwarantowane domyślnie** | Jeśli `securityContext.seccompProfile` nie jest ustawiony, domyślne to `Unconfined`, chyba że kubelet włączy `--seccomp-default`; `RuntimeDefault` lub `Localhost` muszą być ustawione jawnie | `securityContext.seccompProfile.type: Unconfined`, pozostawienie seccomp niezdefiniowanego na klastrach bez `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Podąża za ustawieniami węzła i Pod w Kubernetes | Profil runtime jest używany, gdy Kubernetes żąda `RuntimeDefault` lub gdy kubelet włącza domyślne seccomp | To samo co w wierszu Kubernetes; bezpośrednia konfiguracja CRI/OCI może również całkowicie pominąć seccomp |

Zachowanie Kubernetes jest tym, które najczęściej zaskakuje operatorów. W wielu klastrach seccomp nadal jest nieobecny, chyba że Pod o to poprosi lub kubelet jest skonfigurowany tak, by domyślnie stosować `RuntimeDefault`.
