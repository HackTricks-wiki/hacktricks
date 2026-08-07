# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

**seccomp** to mechanizm umożliwiający kernelowi stosowanie filtra do syscalls, które może wywoływać proces. W środowiskach kontenerowych seccomp jest zwykle używany w trybie filtrowania, dzięki czemu proces nie jest po prostu ogólnie oznaczany jako „restricted”, lecz podlega konkretnej polityce dotyczącej syscalls. Ma to znaczenie, ponieważ wiele container breakouts wymaga uzyskania dostępu do bardzo konkretnych interfejsów kernela. Jeśli proces nie może skutecznie wywołać odpowiednich syscalls, duża klasa ataków znika, zanim w ogóle znaczenie zaczną mieć niuanse dotyczące namespaces lub capabilities.

Kluczowy model mentalny jest prosty: namespaces decydują, **co proces może zobaczyć**, capabilities decydują, **jakich uprzywilejowanych działań proces może nominalnie próbować**, a seccomp decyduje, **czy kernel w ogóle zaakceptuje punkt wejścia syscall dla podejmowanej próby działania**. Dlatego seccomp często zapobiega atakom, które na podstawie samych capabilities wyglądałyby na możliwe.

## Wpływ na bezpieczeństwo

Duża część niebezpiecznej powierzchni kernela jest dostępna wyłącznie za pośrednictwem stosunkowo niewielkiego zestawu syscalls. Przykłady, które wielokrotnie mają znaczenie w hardeningu kontenerów, obejmują `mount`, `unshare`, `clone` lub `clone3` z określonymi flagami, `bpf`, `ptrace`, `keyctl` oraz `perf_event_open`. Atakujący, który może uzyskać dostęp do tych syscalls, może być w stanie tworzyć nowe namespaces, manipulować subsystemami kernela lub wchodzić w interakcję z powierzchnią ataku, której normalny application container w ogóle nie potrzebuje.

Dlatego domyślne profile seccomp runtime są tak ważne. Nie są jedynie „dodatkową ochroną”. W wielu środowiskach stanowią różnicę między kontenerem, który może korzystać z dużej części funkcjonalności kernela, a takim, który jest ograniczony do powierzchni syscalls bliższej temu, czego aplikacja rzeczywiście potrzebuje.

## Tryby i tworzenie filtrów

seccomp historycznie posiadał tryb ścisły, w którym dostępny pozostawał tylko niewielki zestaw syscalls, ale trybem istotnym dla współczesnych container runtimes jest tryb filtrowania seccomp, często nazywany **seccomp-bpf**. W tym modelu kernel ocenia program filtra, który decyduje, czy syscall powinien zostać dozwolony, odrzucony z errno, przechwycony, zalogowany lub czy proces powinien zostać zakończony.<sup>[[1]](#references)</sup> Container runtimes używają tego mechanizmu, ponieważ jest on wystarczająco elastyczny, aby blokować szerokie klasy niebezpiecznych syscalls, jednocześnie umożliwiając normalne działanie aplikacji.

Dwa przykłady niskopoziomowe są przydatne, ponieważ pokazują działanie mechanizmu w konkretny, a nie magiczny sposób. Tryb ścisły demonstruje stary model „przetrwa tylko minimalny zestaw syscalls”:
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
Końcowe `open` powoduje zakończenie procesu, ponieważ nie należy do minimalnego zestawu trybu strict.

Przykład filtra libseccomp wyraźniej pokazuje nowoczesny model polityk:
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
Ten styl polityki to coś, co większość czytelników powinna mieć na myśli, gdy myśli o profilach seccomp w czasie wykonywania.

## Laboratorium

Prostym sposobem potwierdzenia, że seccomp jest aktywny w kontenerze, jest:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Możesz również spróbować operacji, którą domyślne profile zazwyczaj ograniczają:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Jeśli kontener działa z użyciem normalnego domyślnego profilu seccomp, operacje typu `unshare` są często blokowane. Jest to przydatna demonstracja, ponieważ pokazuje, że nawet jeśli narzędzie userspace znajduje się w obrazie, ścieżka jądra, której potrzebuje, może być nadal niedostępna.

Jeśli kontener działa z użyciem normalnego domyślnego profilu seccomp, operacje typu `unshare` są często blokowane, nawet gdy narzędzie userspace znajduje się w obrazie.

Aby ogólniej sprawdzić stan procesu, uruchom:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Użycie w czasie wykonywania

Docker obsługuje zarówno domyślne, jak i niestandardowe profile seccomp oraz pozwala administratorom je wyłączyć za pomocą `--security-opt seccomp=unconfined`.<sup>[[2]](#references)</sup> Podman oferuje podobne wsparcie i często łączy seccomp z rootless execution, zapewniając bardzo rozsądny poziom bezpieczeństwa domyślnie. Kubernetes udostępnia seccomp poprzez konfigurację workloadu, gdzie `RuntimeDefault` jest zazwyczaj rozsądną bazą, a `Unconfined` należy traktować jako wyjątek wymagający uzasadnienia, a nie jako wygodny przełącznik.<sup>[[3]](#references)</sup>

W środowiskach opartych na containerd i CRI-O dokładna ścieżka jest bardziej warstwowa, ale zasada pozostaje taka sama: wyższy poziom engine lub orchestratora decyduje, co powinno się wydarzyć, a runtime ostatecznie instaluje wynikającą z tego politykę seccomp dla procesu kontenera. Rezultat nadal zależy od końcowej konfiguracji runtime, która dociera do kernela.

### Przykład niestandardowej polityki

Docker i podobne engine mogą ładować niestandardowy profil seccomp z JSON. Minimalny przykład, który blokuje `chmod`, jednocześnie zezwalając na wszystko inne, wygląda następująco:
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
Zastosowano z:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Polecenie kończy się błędem `Operation not permitted`, co pokazuje, że ograniczenie wynika z polityki syscall, a nie wyłącznie ze zwykłych uprawnień do plików. W praktycznym hardeningu allowlisty są zazwyczaj silniejsze niż liberalne wartości domyślne z niewielką blacklistą.

## Błędne konfiguracje

Najbardziej rażącym błędem jest ustawienie seccomp na **unconfined**, ponieważ aplikacja nie działała przy użyciu domyślnej polityki. Jest to częste podczas troubleshootingu i bardzo niebezpieczne jako stałe rozwiązanie. Po usunięciu filtra ponownie staje się dostępnych wiele mechanizmów breakout opartych na syscall, szczególnie gdy jednocześnie są używane potężne capabilities lub współdzielone namespace hosta.

Innym częstym problemem jest użycie **custom permissive profile**, skopiowanego z jakiegoś bloga lub wewnętrznego workaroundu, bez dokładnego sprawdzenia. Zespoły czasami pozostawiają niemal wszystkie niebezpieczne syscall wyłącznie dlatego, że profil został zbudowany wokół założenia „powstrzymać aplikację przed awarią”, a nie „przyznać tylko to, czego aplikacja rzeczywiście potrzebuje”. Kolejnym błędnym założeniem jest uznanie, że seccomp ma mniejsze znaczenie w kontenerach non-root. W rzeczywistości znaczna część kernel attack surface pozostaje istotna nawet wtedy, gdy proces nie działa jako UID 0.

## Abuse

Jeśli seccomp nie jest używany lub został poważnie osłabiony, attacker może mieć możliwość wywoływania syscall związanych z tworzeniem namespace, rozszerzania dostępnego kernel attack surface za pomocą `bpf` lub `perf_event_open`, nadużywania `keyctl` albo łączenia tych ścieżek syscall z niebezpiecznymi capabilities, takimi jak `CAP_SYS_ADMIN`. W wielu rzeczywistych atakach seccomp nie jest jedyną brakującą kontrolą, ale jego brak znacząco skraca ścieżkę exploita, ponieważ usuwa jedną z niewielu obron, które mogą zatrzymać ryzykowny syscall, zanim w ogóle zadziała reszta modelu uprawnień.

Najbardziej użytecznym testem praktycznym jest wypróbowanie dokładnych rodzin syscall, które zwykle blokują profile domyślne. Jeśli nagle zaczną działać, postura bezpieczeństwa kontenera uległa dużej zmianie:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Jeśli obecne są `CAP_SYS_ADMIN` lub inne silne capability, sprawdź, czy seccomp jest jedyną brakującą barierą przed nadużyciem opartym na mount:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
W przypadku niektórych celów bezpośrednim rezultatem nie jest pełny escape, lecz zbieranie informacji i rozszerzanie attack surface kernela. Te polecenia pomagają ustalić, czy dostępne są szczególnie wrażliwe ścieżki syscalli:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Jeśli seccomp jest nieobecny, a kontener jest również uprzywilejowany na inne sposoby, wtedy ma sens przejście do bardziej szczegółowych technik ucieczki, które zostały już opisane na starszych stronach dotyczących ucieczki z kontenerów.

### Pełny przykład: seccomp był jedyną rzeczą blokującą `unshare`

Na wielu celach praktycznym skutkiem usunięcia seccomp jest to, że wywołania systemowe tworzenia namespaces lub mount nagle zaczynają działać. Jeśli kontener ma również `CAP_SYS_ADMIN`, poniższa sekwencja może stać się możliwa:
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
Samo w sobie nie jest to jeszcze host escape, ale pokazuje, że seccomp był barierą uniemożliwiającą exploitation związany z mount.

### Pełny przykład: seccomp wyłączony + `release_agent` w cgroup v1

Jeśli seccomp jest wyłączony, a kontener może montować hierarchie cgroup v1, technika `release_agent` z sekcji dotyczącej cgroups staje się dostępna:
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
To nie jest exploit działający wyłącznie dzięki seccomp. Chodzi o to, że gdy seccomp jest ustawiony jako unconfined, chainy breakoutów intensywnie korzystające z syscalli, które wcześniej były blokowane, mogą zacząć działać dokładnie tak, jak zostały napisane.

## Sprawdzenia

Celem tych sprawdzeń jest ustalenie, czy seccomp jest w ogóle aktywny, czy towarzyszy mu `no_new_privs` oraz czy konfiguracja runtime jawnie wskazuje na wyłączenie seccomp.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Co jest tutaj interesujące:

- Niezerowa wartość `Seccomp` oznacza, że filtrowanie jest aktywne; `0` zwykle oznacza brak ochrony seccomp.
- Jeśli opcje bezpieczeństwa runtime zawierają `seccomp=unconfined`, workload utracił jedną ze swoich najbardziej użytecznych mechanizmów obrony na poziomie syscalli.
- `NoNewPrivs` nie jest samym seccomp, ale obecność obu tych ustawień zwykle wskazuje na bardziej staranne podejście do hardeningu niż brak obu.

Jeśli kontener ma już podejrzane mounty, szerokie capabilities lub współdzielone namespaces hosta, a seccomp jest również ustawiony jako unconfined, tę kombinację należy traktować jako poważny sygnał eskalacji. Kontener nadal może nie być możliwy do łatwego przełamania, ale liczba punktów wejścia do kernela dostępnych dla attackera gwałtownie wzrosła.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne działanie | Częste ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Zwykle włączone domyślnie | Używa wbudowanego domyślnego profilu seccomp Docker, chyba że zostanie on zastąpiony | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Zwykle włączone domyślnie | Stosuje domyślny profil seccomp runtime, chyba że zostanie on zastąpiony | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Domyślnie nie jest gwarantowane** | Jeśli `securityContext.seccompProfile` nie jest ustawione, domyślnie używane jest `Unconfined`, chyba że kubelet włącza `--seccomp-default`; w przeciwnym razie `RuntimeDefault` lub `Localhost` należy ustawić jawnie | `securityContext.seccompProfile.type: Unconfined`, pozostawienie seccomp nieustawionego w klastrach bez `seccompDefault`, `privileged: true` |
| containerd / CRI-O w Kubernetes | Zależy od ustawień node i Pod | Profil runtime jest używany, gdy Kubernetes żąda `RuntimeDefault` lub gdy włączone jest domyślne ustawianie seccomp przez kubelet | Tak jak w wierszu dotyczącym Kubernetes; bezpośrednia konfiguracja CRI/OCI również może całkowicie pominąć seccomp |

Zachowanie Kubernetes jest tym, co najczęściej zaskakuje operatorów. W wielu klastrach seccomp nadal nie jest włączony, chyba że Pod go zażąda lub kubelet zostanie skonfigurowany tak, aby domyślnie używać `RuntimeDefault`.<sup>[[3]](#references)</sup>

## References

- [1] [Linux kernel documentation: Seccomp BPF (SECure COMPuting with filters)](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [2] [Docker Docs: Seccomp security profiles for Docker](https://docs.docker.com/engine/security/seccomp/)
- [3] [Kubernetes Docs: Restrict a Container's Syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)

{{#include ../../../../banners/hacktricks-training.md}}
