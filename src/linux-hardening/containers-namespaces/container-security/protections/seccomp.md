# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Wprowadzenie

**seccomp** to mechanizm, który pozwala kernelowi stosować filtr do syscalls, które może wywoływać proces. W środowiskach kontenerowych seccomp jest zwykle używany w trybie filter, dzięki czemu proces nie jest po prostu ogólnie oznaczony jako „restricted”, lecz podlega konkretnej polityce syscalls. Ma to znaczenie, ponieważ wiele container breakouts wymaga uzyskania dostępu do bardzo konkretnych interfejsów kernela. Jeśli proces nie może skutecznie wywołać odpowiednich syscalls, duża klasa ataków znika, zanim w ogóle znaczenie zaczną mieć niuanse związane z namespaces lub capabilities.

Kluczowy model mentalny jest prosty: namespaces decydują, **co proces może zobaczyć**, capabilities decydują, **jakich uprzywilejowanych działań proces może nominalnie próbować**, a seccomp decyduje, **czy kernel w ogóle zaakceptuje entry point syscall dla podejmowanej próby działania**. Dlatego seccomp często zapobiega atakom, które w przeciwnym razie wyglądałyby na możliwe wyłącznie na podstawie capabilities.

## Wpływ na bezpieczeństwo

Duża część niebezpiecznej powierzchni kernela jest dostępna wyłącznie przez stosunkowo niewielki zestaw syscalls. Przykłady, które regularnie mają znaczenie w container hardening, obejmują `mount`, `unshare`, `clone` lub `clone3` z określonymi flags, `bpf`, `ptrace`, `keyctl` oraz `perf_event_open`. Attacker, który może uzyskać dostęp do tych syscalls, może być w stanie tworzyć nowe namespaces, manipulować subsystemami kernela lub wchodzić w interakcję z attack surface, którego normalny application container w ogóle nie potrzebuje.

Dlatego domyślne profile seccomp runtime są tak ważne. Nie są jedynie „dodatkową ochroną”. W wielu środowiskach stanowią różnicę między kontenerem, który może korzystać z szerokiej części funkcjonalności kernela, a kontenerem ograniczonym do powierzchni syscalls bliższej temu, czego aplikacja rzeczywiście potrzebuje.

## Tryby i konstruowanie filtrów

seccomp historycznie posiadał strict mode, w którym dostępny pozostawał tylko niewielki zestaw syscalls, ale trybem istotnym dla współczesnych container runtimes jest seccomp filter mode, często nazywany **seccomp-bpf**. W tym modelu kernel analizuje filter program, który decyduje, czy syscall powinien zostać dozwolony, odrzucony z errno, przechwycony, zalogowany czy też powinien spowodować zakończenie procesu. Container runtimes używają tego mechanizmu, ponieważ jest on wystarczająco elastyczny, aby blokować szerokie klasy niebezpiecznych syscalls, jednocześnie umożliwiając normalne działanie aplikacji.

Dwa przykłady niskopoziomowe są przydatne, ponieważ przedstawiają mechanizm w konkretny, a nie magiczny sposób. Strict mode pokazuje dawny model „przetrwa tylko minimalny zestaw syscalls”:
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
Ten styl polityki jest tym, co większość czytelników powinna mieć na myśli, gdy myśli o profilach seccomp działających w czasie wykonywania.

## Laboratorium

Prostym sposobem potwierdzenia, że seccomp jest aktywny w kontenerze, jest:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Możesz również spróbować operacji, które domyślne profile często ograniczają:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Jeśli kontener działa z użyciem normalnego domyślnego profilu seccomp, operacje typu `unshare` są często blokowane. Jest to przydatna demonstracja, ponieważ pokazuje, że nawet jeśli narzędzie userspace istnieje wewnątrz obrazu, ścieżka kernela, której ono potrzebuje, może być nadal niedostępna.

Jeśli kontener działa z użyciem normalnego domyślnego profilu seccomp, operacje typu `unshare` są często blokowane, nawet gdy narzędzie userspace istnieje wewnątrz obrazu.

Aby bardziej ogólnie sprawdzić status procesu, uruchom:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Użycie w czasie działania

Docker obsługuje zarówno domyślne, jak i niestandardowe profile seccomp oraz pozwala administratorom je wyłączyć za pomocą `--security-opt seccomp=unconfined`. Podman oferuje podobne wsparcie i często łączy seccomp z wykonywaniem rootless, co zapewnia bardzo rozsądny poziom bezpieczeństwa domyślnie. Kubernetes udostępnia seccomp poprzez konfigurację workloadów, gdzie `RuntimeDefault` jest zwykle rozsądną bazą, a `Unconfined` powinno być traktowane jako wyjątek wymagający uzasadnienia, a nie jako wygodny przełącznik.

W środowiskach opartych na containerd i CRI-O dokładna ścieżka jest bardziej wielowarstwowa, ale zasada pozostaje taka sama: silnik wyższego poziomu lub orchestrator decyduje, co powinno się wydarzyć, a runtime ostatecznie instaluje wynikową politykę seccomp dla procesu kontenera. Rezultat nadal zależy od finalnej konfiguracji runtime, która dociera do kernela.

### Przykład niestandardowej polityki

Docker i podobne silniki mogą ładować niestandardowy profil seccomp z JSON. Minimalny przykład odmawiający wykonania `chmod`, a jednocześnie zezwalający na wszystko inne, wygląda następująco:
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
Zastosowano za pomocą:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Polecenie kończy się błędem `Operation not permitted`, co pokazuje, że ograniczenie wynika z polityki syscall, a nie wyłącznie ze zwykłych uprawnień do plików. W praktycznym hardeningu allowlisty są zazwyczaj bezpieczniejsze niż permisywne ustawienia domyślne z niewielką blacklistą.

## Błędne konfiguracje

Najbardziej rażącym błędem jest ustawienie seccomp na **unconfined**, ponieważ aplikacja nie działała z domyślną polityką. Jest to częste podczas rozwiązywania problemów i bardzo niebezpieczne jako stała poprawka. Po usunięciu filtra ponownie staje się dostępnych wiele opartych na syscallach prymitywów breakout, szczególnie gdy jednocześnie obecne są szerokie capabilities lub współdzielenie namespace hosta.

Innym częstym problemem jest użycie **custom permissive profile**, skopiowanego z jakiegoś bloga lub wewnętrznego workaroundu bez dokładnego przeglądu. Zespoły czasami pozostawiają niemal wszystkie niebezpieczne syscalle wyłącznie dlatego, że profil został zbudowany wokół założenia „powstrzymać aplikację przed awarią”, a nie „przyznać tylko to, czego aplikacja rzeczywiście potrzebuje”. Trzecim błędnym założeniem jest uznanie, że seccomp ma mniejsze znaczenie w kontenerach non-root. W rzeczywistości znaczna część attack surface kernela pozostaje istotna nawet wtedy, gdy proces nie działa jako UID 0.

## Nadużycie

Jeśli seccomp jest nieobecny lub poważnie osłabiony, attacker może być w stanie wywoływać syscale tworzące namespace, rozszerzać dostępny attack surface kernela za pomocą `bpf` lub `perf_event_open`, nadużywać `keyctl` albo łączyć te ścieżki syscall z niebezpiecznymi capabilities, takimi jak `CAP_SYS_ADMIN`. W wielu rzeczywistych atakach seccomp nie jest jedynym brakującym mechanizmem kontroli, ale jego brak znacząco skraca ścieżkę exploita, ponieważ usuwa jedną z niewielu obron, które mogą zatrzymać ryzykowny syscall, zanim pozostała część modelu uprawnień w ogóle zacznie mieć znaczenie.

Najbardziej użytecznym praktycznym testem jest próba wykonania dokładnie tych rodzin syscall, które zwykle blokują profile domyślne. Jeśli nagle zaczną działać, posture kontenera uległo znacznej zmianie:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Jeśli obecne jest `CAP_SYS_ADMIN` lub inna silna capability, sprawdź, czy seccomp jest jedyną brakującą barierą przed nadużyciem opartym na mount:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
W przypadku niektórych celów bezpośrednim celem nie jest pełne wydostanie się z kontenera, lecz zbieranie informacji i poszerzanie powierzchni ataku kernela. Te polecenia pomagają ustalić, czy możliwy jest dostęp do szczególnie wrażliwych ścieżek syscalli:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Jeśli seccomp jest nieobecny, a kontener jest również uprzywilejowany na inne sposoby, wtedy warto przejść do bardziej szczegółowych technik breakout opisanych już na starszych stronach dotyczących container-escape.

### Pełny przykład: seccomp był jedyną rzeczą blokującą `unshare`

Na wielu targetach praktycznym skutkiem usunięcia seccomp jest to, że wywołania systemowe tworzenia namespace'ów lub montowania nagle zaczynają działać. Jeśli kontener ma również `CAP_SYS_ADMIN`, możliwe staje się wykonanie następującej sekwencji:
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
Samo w sobie nie jest to jeszcze ucieczką z hosta, ale pokazuje, że seccomp był barierą uniemożliwiającą wykorzystanie mechanizmów związanych z mount.

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
Nie jest to exploit dotyczący wyłącznie seccomp. Chodzi o to, że gdy seccomp zostanie ustawiony jako unconfined, chainy breakout oparte intensywnie na syscallach, które wcześniej były blokowane, mogą zacząć działać dokładnie tak, jak zostały napisane.

## Checks

Celem tych checks jest ustalenie, czy seccomp jest w ogóle aktywny, czy towarzyszy mu `no_new_privs` oraz czy konfiguracja runtime pokazuje, że seccomp został jawnie wyłączony.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Co jest tutaj interesujące:

- Niezerowa wartość `Seccomp` oznacza, że filtrowanie jest aktywne; `0` zwykle oznacza brak ochrony seccomp.
- Jeśli opcje bezpieczeństwa runtime obejmują `seccomp=unconfined`, workload utracił jedną z najbardziej użytecznych obron na poziomie syscalli.
- `NoNewPrivs` nie jest samym seccomp, ale obecność obu tych elementów zwykle wskazuje na staranniejsze podejście do hardeningu niż brak obu.

Jeśli kontener ma już podejrzane mounty, szerokie capabilities lub współdzielone namespace'y hosta, a seccomp jest również ustawiony jako unconfined, taką kombinację należy traktować jako poważny sygnał eskalacji. Kontener może nadal nie być możliwy do przełamania w trywialny sposób, ale liczba dostępnych dla attackera punktów wejścia do kernela gwałtownie wzrosła.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne działanie | Częste ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Zwykle włączone domyślnie | Używa wbudowanego domyślnego profilu seccomp Docker, o ile nie zostanie on nadpisany | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Zwykle włączone domyślnie | Stosuje domyślny profil seccomp runtime, o ile nie zostanie on nadpisany | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Domyślnie nie jest gwarantowane** | Jeśli `securityContext.seccompProfile` nie jest ustawione, domyślnie używane jest `Unconfined`, chyba że kubelet ma włączone `--seccomp-default`; w przeciwnym razie `RuntimeDefault` lub `Localhost` musi zostać ustawione jawnie | `securityContext.seccompProfile.type: Unconfined`, pozostawienie seccomp nieustawionego w klastrach bez `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Zależy od ustawień node'a i Pod | Profil runtime jest używany, gdy Kubernetes zażąda `RuntimeDefault` lub gdy włączone jest domyślne ustawianie seccomp przez kubelet | Tak samo jak w wierszu Kubernetes; bezpośrednia konfiguracja CRI/OCI również może całkowicie pominąć seccomp |

Zachowanie Kubernetes jest tym, co najczęściej zaskakuje operatorów. W wielu klastrach seccomp nadal nie jest używany, chyba że Pod go zażąda lub kubelet zostanie skonfigurowany tak, aby domyślnie używać `RuntimeDefault`.
{{#include ../../../../banners/hacktricks-training.md}}
