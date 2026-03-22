# Ocena i utwardzanie

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Dobra ocena kontenera powinna odpowiedzieć na dwa równoległe pytania. Po pierwsze — co atakujący może zrobić z bieżącego workloadu? Po drugie — które decyzje operatora to umożliwiły? Narzędzia do enumeracji pomagają w pierwszym pytaniu, a wytyczne dotyczące utwardzania w drugim. Umieszczenie obu na jednej stronie sprawia, że sekcja jest bardziej użyteczna jako podręczna ściągawka niż tylko katalog escape tricks.

## Narzędzia do enumeracji

Kilka narzędzi jest przydatnych do szybkiego scharakteryzowania środowiska kontenerowego:

- `linpeas` potrafi zidentyfikować wiele wskaźników kontenera, zamontowanych sockets, capability sets, niebezpiecznych systemów plików oraz wskazówek dotyczących breakout.
- `CDK` koncentruje się konkretnie na środowiskach kontenerowych i zawiera enumerację oraz niektóre zautomatyzowane sprawdzenia escape.
- `amicontained` jest lekkie i przydatne do identyfikacji ograniczeń kontenera, capabilities, namespace exposure oraz prawdopodobnych klas breakout.
- `deepce` to kolejny enumerator skupiony na kontenerach z breakout-oriented checks.
- `grype` jest użyteczny, gdy ocena obejmuje przegląd podatności pakietów w image zamiast tylko runtime escape analysis.

Wartość tych narzędzi to szybkość i zasięg, a nie pewność. Pomagają szybko odsłonić ogólną postawę, ale interesujące ustalenia nadal wymagają ręcznej interpretacji względem rzeczywistego runtime, namespace, capability i modelu mount.

## Priorytety utwardzania

Najważniejsze zasady utwardzania są koncepcyjnie proste, chociaż ich wdrożenie różni się w zależności od platformy. Unikaj privileged containers. Unikaj zamontowanych runtime sockets. Nie dawaj kontenerom zapisywalnych ścieżek hosta, chyba że istnieje bardzo konkretny powód. Używaj user namespaces lub rootless execution tam, gdzie to możliwe. Drop all capabilities i przywracaj tylko te, których workload naprawdę potrzebuje. Trzymaj seccomp, AppArmor i SELinux włączone zamiast ich wyłączać, żeby rozwiązać problemy ze zgodnością aplikacji. Ogranicz zasoby, aby skompromitowany kontener nie mógł trywialnie odciąć usługi dla hosta.

Higiena image i procesu build ma równie duże znaczenie co postura w runtime. Używaj minimalnych image'ów, przebudowuj często, skanuj je, wymagaj udokumentowanego pochodzenia tam, gdzie to możliwe, i trzymaj sekrety poza warstwami. Kontener uruchamiany jako non-root z małym image i wąską powierzchnią syscall i capability jest znacznie łatwiejszy do obrony niż duży convenience image uruchomiony jako host-equivalent root z preinstalowanymi narzędziami do debugowania.

## Przykłady wyczerpania zasobów

Kontrole zasobów nie są efektowne, ale są częścią bezpieczeństwa kontenerów, ponieważ ograniczają promień szkód po kompromitacji. Bez limitów pamięci, CPU czy PID, prosty shell może wystarczyć do degradacji hosta lub sąsiednich workloadów.

Przykłady testów wpływających na hosta:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Te przykłady są przydatne, ponieważ pokazują, że nie każdy niebezpieczny wynik w kontenerze jest czystym "escape". Słabe limity cgroup mogą nadal przekształcić code execution w rzeczywisty wpływ operacyjny.

## Hardening Tooling

Dla środowisk zorientowanych na Docker, `docker-bench-security` pozostaje przydatną podstawą audytu po stronie hosta, ponieważ sprawdza typowe problemy konfiguracyjne względem powszechnie uznanych wytycznych benchmarkowych:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Narzędzie nie zastępuje threat modeling, ale nadal jest wartościowe przy znajdowaniu niedbałych ustawień daemon, mount, network i runtime defaults, które kumulują się w czasie.

## Sprawdzenia

Użyj ich jako szybkich poleceń do wstępnej oceny:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- Proces root z szerokimi uprawnieniami i `Seccomp: 0` zasługuje na natychmiastową uwagę.
- Podejrzane mounty i runtime sockets często dają szybszą drogę do wpływu niż jakikolwiek kernel exploit.
- Połączenie słabej konfiguracji runtime i niskich limitów zasobów zazwyczaj wskazuje na ogólnie przyzwalające container environment, a nie na pojedynczy, odosobniony błąd.
{{#include ../../../banners/hacktricks-training.md}}
