# Ocena i zabezpieczanie

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Dobra ocena kontenera powinna odpowiedzieć na dwa równoległe pytania. Po pierwsze: co atakujący może zrobić z poziomu bieżącego workloadu? Po drugie: które decyzje operatora to umożliwiły? Narzędzia do enumeracji pomagają w pierwszym pytaniu, a wytyczne dotyczące hardeningu w drugim. Umieszczenie obu informacji na jednej stronie sprawia, że sekcja jest bardziej użyteczna jako odniesienie w terenie, a nie tylko katalog trików związanych z escape.

## Narzędzia do enumeracji

Kilka narzędzi jest przydatnych do szybkiego scharakteryzowania środowiska kontenerowego:

- `linpeas` potrafi zidentyfikować wiele wskaźników kontenera, zamontowane sockets, zestawy capabilities, niebezpieczne filesystems oraz wskazówki dotyczące breakout.
- `CDK` koncentruje się specyficznie na środowiskach kontenerowych i zawiera enumerację oraz niektóre zautomatyzowane checks dotyczące escape.
- `amicontained` jest lekkie i przydatne do identyfikacji ograniczeń kontenera, capabilities, exposure namespace oraz prawdopodobnych klas breakout.
- `deepce` to kolejne narzędzie skoncentrowane na kontenerach z checkami ukierunkowanymi na breakout.
- `grype` jest przydatne, gdy ocena obejmuje przegląd podatności pakietów w image zamiast tylko analizę runtime escape.

Wartością tych narzędzi jest szybkość i pokrycie, nie pewność. Pomagają szybko ujawnić przybliżony stan zabezpieczeń, ale interesujące odkrycia wciąż wymagają ręcznej interpretacji w kontekście rzeczywistego runtime, namespace, capability i modelu montowania.

## Priorytety hardeningu

Najważniejsze zasady hardeningu są koncepcyjnie proste, choć ich implementacja zależy od platformy. Unikaj privileged containers. Unikaj mounted runtime sockets. Nie przyznawaj kontenerom zapisywalnych host paths, chyba że istnieje bardzo konkretna potrzeba. Używaj user namespaces lub rootless execution tam, gdzie to możliwe. Usuń wszystkie capabilities i przywróć tylko te, których workload naprawdę potrzebuje. Trzymaj seccomp, AppArmor i SELinux włączone, zamiast je wyłączać, żeby rozwiązać problemy z kompatybilnością aplikacji. Ogranicz zasoby, aby skompromitowany container nie mógł w prosty sposób odciąć usługi dla hosta.

Higiena image i build ma takie samo znaczenie jak runtime posture. Używaj minimalnych images, rebuilduj często, skanuj je, wymagaj provenance tam, gdzie to praktyczne, i trzymaj secrets poza warstwami. Kontener działający jako non-root z małym image i wąską powierzchnią syscall i capability jest znacznie łatwiejszy do obrony niż duży convenience image działający jako host-equivalent root z preinstalowanymi narzędziami debugowania.

## Przykłady wyczerpania zasobów

Kontrole zasobów nie są efektowne, ale są częścią bezpieczeństwa kontenerów, ponieważ ograniczają blast radius kompromitacji. Bez limitów memory, CPU lub PID, prosty shell może wystarczyć, by pogorszyć działanie hosta lub sąsiednich workloads.

Przykładowe testy wpływające na hosta:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Te przykłady są przydatne, ponieważ pokazują, że nie każdy niebezpieczny efekt działania kontenera to czyste "escape". Słabe limity cgroup wciąż mogą przekształcić code execution w rzeczywisty wpływ operacyjny.

## Narzędzia do hardeningu

Dla środowisk skoncentrowanych na Dockerze, `docker-bench-security` pozostaje użyteczną bazą odniesienia do audytu po stronie hosta, ponieważ sprawdza typowe problemy konfiguracyjne względem powszechnie uznawanych wytycznych benchmarkowych:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Narzędzie nie zastępuje threat modeling, ale nadal jest przydatne do znajdowania niedbałych daemon, mount, network i runtime ustawień domyślnych, które kumulują się z czasem.

## Sprawdzenia

Użyj ich jako szybkie, wstępne polecenia podczas oceny:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- Proces uruchomiony jako root z szerokimi capabilities i `Seccomp: 0` wymaga natychmiastowej uwagi.
- Podejrzane mounts i runtime sockets często zapewniają szybszą ścieżkę do wpływu niż jakikolwiek kernel exploit.
- Połączenie słabej runtime posture i słabych resource limits zwykle wskazuje na ogólnie permissive container environment, a nie na pojedynczy, odizolowany błąd.
