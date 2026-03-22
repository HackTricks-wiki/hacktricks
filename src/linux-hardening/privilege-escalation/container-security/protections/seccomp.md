# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

**seccomp** to mechanizm, który pozwala kernelowi zastosować filtr do syscalli, które proces może wywołać. W środowiskach konteneryzowanych seccomp jest zwykle używany w trybie filtrów, dzięki czemu proces nie jest jedynie oznaczony jako "restricted" w ogólnym sensie, lecz podlega konkretnej polityce syscalli. Ma to znaczenie, ponieważ wiele ucieczek z kontenera wymaga dostępu do bardzo konkretnych interfejsów jądra. Jeśli proces nie może pomyślnie wywołać odpowiednich syscalli, duża klasa ataków znika, zanim niuanse związane z namespaces czy capabilities staną się istotne.

Główny model myślowy jest prosty: namespaces decydują **co proces może zobaczyć**, capabilities decydują **które uprzywilejowane działania proces nominalnie może próbować wykonać**, a seccomp decyduje **czy kernel w ogóle zaakceptuje punkt wejścia syscall dla próby wykonania danej operacji**. Dlatego seccomp często zapobiega atakom, które inaczej wyglądałyby na możliwe tylko na podstawie samych capabilities.

## Wpływ na bezpieczeństwo

Duża część niebezpiecznej powierzchni jądra jest dostępna tylko przez stosunkowo niewielki zbiór syscalli. Przykłady, które wielokrotnie mają znaczenie przy hardeningu kontenerów, to `mount`, `unshare`, `clone` lub `clone3` z określonymi flagami, `bpf`, `ptrace`, `keyctl` oraz `perf_event_open`. Atakujący, który ma dostęp do tych syscalli, może być w stanie utworzyć nowe namespaces, manipulować podsystemami jądra lub oddziaływać z powierzchnią ataku, której zwykły kontener aplikacyjny w ogóle nie potrzebuje.

Dlatego domyślne profile seccomp w runtime są tak ważne. Nie są one jedynie "dodatkową obroną". W wielu środowiskach stanowią różnicę między kontenerem, który może korzystać z szerokiej części funkcjonalności jądra, a takim, którego powierzchnia syscalli jest ograniczona do tego, czego aplikacja rzeczywiście potrzebuje.

## Tryby i konstrukcja filtra

seccomp historycznie miał tryb ścisły, w którym dostępny pozostawał tylko bardzo mały zestaw syscalli, ale trybem istotnym dla nowoczesnych runtime'ów kontenerowych jest tryb filtra seccomp, często nazywany **seccomp-bpf**. W tym modelu kernel ocenia program filtra, który decyduje, czy syscall ma być dozwolony, odrzucony z errno, przechwycony (trapped), zalogowany, czy też ma zakończyć proces. Runtime'y kontenerów używają tego mechanizmu, ponieważ jest wystarczająco ekspresyjny, by blokować szerokie klasy niebezpiecznych syscalli, a jednocześnie pozwalać na normalne działanie aplikacji.

Dwa niskopoziomowe przykłady są użyteczne, ponieważ sprawiają, że mechanizm jest konkretny, a nie magiczny. Tryb ścisły demonstruje stary model "tylko minimalny zestaw syscalli przetrwa":
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
Ostatnie wywołanie `open` powoduje zabicie procesu, ponieważ nie jest częścią minimalnego zestawu trybu ścisłego.

Przykład filtra libseccomp pokazuje nowoczesny model polityki bardziej przejrzyście:
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
Ten styl polityki to obraz, jaki większość czytelników powinna mieć na myśli, gdy myśli o runtime seccomp profiles.

## Lab

Prosty sposób, aby potwierdzić, że seccomp jest aktywny w containerze, to:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Możesz także spróbować operacji, którą profile domyślne często ograniczają:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Jeśli kontener działa pod normalnym domyślnym profilem seccomp, operacje typu `unshare` są często zablokowane. To przydatna demonstracja, ponieważ pokazuje, że nawet jeśli narzędzie userspace istnieje w obrazie, ścieżka w jądrze, której potrzebuje, nadal może być niedostępna.

Jeśli kontener działa pod normalnym domyślnym profilem seccomp, operacje typu `unshare` są często zablokowane nawet gdy narzędzie userspace istnieje w obrazie.

Aby ogólniej sprawdzić status procesu, uruchom:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Użycie w czasie wykonywania

Docker obsługuje zarówno domyślne, jak i niestandardowe profile seccomp i pozwala administratorom wyłączyć je za pomocą `--security-opt seccomp=unconfined`. Podman oferuje podobne wsparcie i często łączy seccomp z uruchamianiem bez uprawnień root jako sensowną konfigurację domyślną. Kubernetes udostępnia seccomp poprzez konfigurację workload, gdzie `RuntimeDefault` zwykle stanowi rozsądne wyjście bazowe, a `Unconfined` powinien być traktowany jako wyjątek wymagający uzasadnienia, a nie jako wygodny przełącznik.

W środowiskach opartych na containerd i CRI-O dokładna ścieżka jest bardziej wielowarstwowa, ale zasada pozostaje ta sama: silnik wyższego poziomu lub orchestrator decyduje, co powinno się wydarzyć, a runtime ostatecznie instaluje wynikową politykę seccomp dla procesu kontenera. Efekt końcowy nadal zależy od ostatecznej konfiguracji runtime, która dociera do jądra.

### Przykład niestandardowej polityki

Docker i podobne silniki mogą załadować niestandardowy profil seccomp z JSON. Minimalny przykład, który odmawia `chmod`, a jednocześnie pozwala na wszystko inne, wygląda tak:
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
Zastosowano przy użyciu:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Polecenie kończy się błędem `Operation not permitted`, co pokazuje, że ograniczenie wynika z polityki syscalli, a nie tylko z zwykłych uprawnień do plików. W praktycznym hardeningu listy dozwolonych są zazwyczaj silniejsze niż permisywne ustawienia domyślne z małą czarną listą.

## Błędne konfiguracje

Największym błędem jest ustawienie seccomp na **unconfined** tylko dlatego, że aplikacja nie działała pod domyślną polityką. Często zdarza się to podczas rozwiązywania problemów i jest bardzo niebezpieczne jako trwałe rozwiązanie. Gdy filtr zniknie, wiele prymitywów ucieczki opartych na syscallach stanie się znowu osiągalnych, szczególnie gdy obecne są potężne capabilities lub współdzielenie przestrzeni nazw hosta.

Kolejnym częstym problemem jest użycie **custom permissive profile**, skopiowanego z jakiegoś bloga lub wewnętrznego obejścia bez dokładnego przeglądu. Zespoły czasem pozostawiają niemal wszystkie niebezpieczne syscalli tylko dlatego, że profil powstał wokół założenia „przestań psuć aplikację” zamiast „przyznaj tylko to, czego aplikacja faktycznie potrzebuje”. Trzecim błędnym założeniem jest traktowanie seccomp jako mniej istotnego w przypadku kontenerów niebędących rootem. W rzeczywistości znacząca powierzchnia ataku jądra pozostaje istotna nawet gdy proces nie ma UID 0.

## Nadużycia

Jeśli seccomp jest nieobecny lub mocno osłabiony, atakujący może być w stanie wywołać syscall'e tworzenia przestrzeni nazw, rozszerzyć osiągalną powierzchnię ataku jądra przez `bpf` lub `perf_event_open`, nadużyć `keyctl`, lub połączyć te ścieżki syscalli z niebezpiecznymi capabilities, takimi jak `CAP_SYS_ADMIN`. W wielu rzeczywistych atakach seccomp nie jest jedynym brakującym mechanizmem kontroli, ale jego nieobecność znacznie skraca ścieżkę exploita, ponieważ usuwa jedną z nielicznych obron, które mogą zatrzymać ryzykowny syscall zanim reszta modelu uprawnień zacznie działać.

Najbardziej użytecznym praktycznym testem jest wypróbowanie dokładnych rodzin syscalli, które domyślne profile zwykle blokują. Jeśli nagle zaczną działać, postawa kontenera uległa dużej zmianie:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Jeśli obecne jest `CAP_SYS_ADMIN` lub inne silne capability, sprawdź, czy seccomp jest jedyną brakującą barierą przed mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
W przypadku niektórych celów bezpośrednią wartością nie jest pełne escape, lecz information gathering i kernel attack-surface expansion. Te polecenia pomagają ustalić, czy szczególnie wrażliwe syscall paths są osiągalne:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Jeśli seccomp jest nieobecny, a kontener jest również uprzywilejowany w innych aspektach, wtedy ma sens przejście do bardziej specyficznych technik breakout już udokumentowanych na stronach legacy container-escape.

### Pełny przykład: seccomp był jedyną rzeczą blokującą `unshare`

W wielu przypadkach praktyczny skutek usunięcia seccomp jest taki, że namespace-creation lub mount syscalls nagle zaczynają działać. Jeśli kontener ma również `CAP_SYS_ADMIN`, następująca sekwencja może stać się możliwa:
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
Samo w sobie nie stanowi jeszcze host escape, ale pokazuje, że seccomp był barierą uniemożliwiającą mount-related exploitation.

### Pełny przykład: seccomp wyłączony + cgroup v1 `release_agent`

Jeśli seccomp jest wyłączony i kontener może mount cgroup v1 hierarchies, technika `release_agent` z sekcji cgroups staje się osiągalna:
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
To nie jest exploit dotyczący wyłącznie seccomp. Chodzi o to, że gdy seccomp przestanie być ograniczony, syscall-heavy breakout chains, które wcześniej były blokowane, mogą zacząć działać dokładnie tak, jak zostały napisane.

## Checks

Celem tych kontroli jest ustalenie, czy seccomp jest w ogóle aktywny, czy towarzyszy mu `no_new_privs`, oraz czy konfiguracja runtime wyraźnie pokazuje, że seccomp został wyłączony.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Co jest tu interesujące:

- Wartość `Seccomp` różna od zera oznacza, że filtrowanie jest aktywne; `0` zwykle oznacza brak ochrony seccomp.
- Jeśli opcje bezpieczeństwa runtime zawierają `seccomp=unconfined`, workload utracił jedną z najważniejszych obron na poziomie wywołań systemowych.
- `NoNewPrivs` nie jest samym seccompem, ale widok obu jednocześnie zwykle wskazuje na bardziej staranne podejście do hardeningu niż brak któregokolwiek.

Jeżeli kontener ma już podejrzane punkty montowania, szerokie capabilities lub współdzielone host namespaces, a seccomp jest również unconfined, taka kombinacja powinna być traktowana jako poważny sygnał eskalacji. Kontener może nadal nie być łatwo przełamany, ale liczba punktów wejścia do jądra dostępnych dla atakującego znacznie wzrosła.

## Domyślne ustawienia runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Zazwyczaj włączone domyślnie | Używa wbudowanego domyślnego profilu seccomp Dockera, jeśli nie zostanie nadpisany | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Zazwyczaj włączone domyślnie | Stosuje domyślny profil seccomp runtime, jeśli nie zostanie nadpisany | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Nie gwarantowane domyślnie** | Jeśli `securityContext.seccompProfile` nie jest ustawiony, domyślnie jest `Unconfined`, chyba że kubelet włączy `--seccomp-default`; w przeciwnym razie `RuntimeDefault` lub `Localhost` muszą zostać ustawione jawnie | `securityContext.seccompProfile.type: Unconfined`, pozostawienie seccomp nieustawionego na klastrach bez `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Podąża za ustawieniami węzła i Podów w Kubernetes | Profil runtime jest używany, gdy Kubernetes żąda `RuntimeDefault` lub gdy w kubelecie włączono domyślną politykę seccomp | Jak w wierszu Kubernetes; bezpośrednia konfiguracja CRI/OCI może również całkowicie pominąć seccomp |

Zachowanie Kubernetes jest tym, które najczęściej zaskakuje operatorów. W wielu klastrach seccomp nadal jest nieobecny, chyba że Pod go zażąda lub kubelet jest skonfigurowany, by ustawiać domyślnie `RuntimeDefault`.
{{#include ../../../../banners/hacktricks-training.md}}
