# Bezpieczeństwo obrazów, podpisywanie i sekrety

{{#include ../../../banners/hacktricks-training.md}}

## Rejestry obrazów i zaufanie

Bezpieczeństwo kontenera zaczyna się jeszcze przed uruchomieniem workloadu. Obraz określa, które pliki binarne, interpretery, biblioteki, skrypty startowe i osadzona konfiguracja trafią do środowiska produkcyjnego. Jeśli obraz zawiera backdoor, jest nieaktualny lub został zbudowany z zaszytymi w nim sekretami, późniejsze hardening środowiska uruchomieniowego i tak operuje na skompromitowanym artefakcie.

Dlatego provenance obrazu, skanowanie podatności, weryfikacja podpisów i obsługa sekretów powinny być omawiane razem z namespaces i seccomp. Chronią one inną fazę cyklu życia, ale występujące w niej błędy często definiują attack surface, który środowisko uruchomieniowe musi później ograniczać.

## Rejestry obrazów i zaufanie

Obrazy mogą pochodzić z publicznych rejestrów, takich jak Docker Hub, albo z prywatnych rejestrów zarządzanych przez organizację. Kwestia bezpieczeństwa nie dotyczy wyłącznie miejsca przechowywania obrazu, lecz także tego, czy zespół może ustalić jego provenance i integralność. Pobieranie niepodpisanych lub niedostatecznie śledzonych obrazów ze źródeł publicznych zwiększa ryzyko przedostania się do środowiska produkcyjnego złośliwej lub zmodyfikowanej zawartości. Nawet wewnętrznie hostowane rejestry wymagają jasno określonej odpowiedzialności, procesu przeglądu i polityki zaufania.

Docker Content Trust historycznie wykorzystywał koncepcje Notary i TUF do wymagania podpisanych obrazów. Dokładne details ekosystemu ewoluowały, ale trwała lekcja pozostaje aktualna: tożsamość i integralność obrazu powinny być weryfikowalne, a nie zakładane.

Przykładowy historyczny workflow Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Celem tego przykładu nie jest stwierdzenie, że każdy zespół musi nadal korzystać z tych samych narzędzi, lecz pokazanie, że podpisywanie i zarządzanie kluczami to zadania operacyjne, a nie abstrakcyjna teoria.

## Skanowanie pod kątem podatności

Skanowanie obrazów pomaga odpowiedzieć na dwa różne pytania. Po pierwsze, czy obraz zawiera znane podatne pakiety lub biblioteki? Po drugie, czy obraz zawiera zbędne oprogramowanie, które zwiększa powierzchnię ataku? Obraz pełen narzędzi debugujących, powłok, interpreterów i nieaktualnych pakietów jest zarówno łatwiejszy do wykorzystania, jak i trudniejszy do przeanalizowania.

Przykłady powszechnie używanych skanerów obejmują:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Wyniki działania tych narzędzi należy interpretować ostrożnie. Podatność w nieużywanym pakiecie nie wiąże się z takim samym ryzykiem jak exposed RCE path, ale obie kwestie nadal mają znaczenie przy podejmowaniu decyzji dotyczących hardeningu.

## Sekrety podczas budowania

Jednym z najstarszych błędów w pipeline'ach budowania kontenerów jest bezpośrednie osadzanie sekretów w obrazie lub przekazywanie ich przez zmienne środowiskowe, które później stają się widoczne za pośrednictwem `docker inspect`, logów budowania lub odzyskanych warstw. Sekrety używane podczas budowania powinny być montowane efemerycznie w trakcie budowania, zamiast kopiowania ich do systemu plików obrazu.

BuildKit ulepszył ten model, umożliwiając dedykowane zarządzanie sekretami używanymi podczas budowania. Zamiast zapisywania sekretu w warstwie, krok budowania może użyć go tymczasowo:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Ma to znaczenie, ponieważ warstwy obrazu są trwałymi artefaktami. Gdy sekret znajdzie się w zatwierdzonej warstwie, późniejsze usunięcie pliku w innej warstwie nie usuwa faktycznie pierwotnego ujawnienia z historii obrazu.

## Sekrety w czasie działania

Sekrety wymagane przez działający workload również powinny, w miarę możliwości, unikać doraźnych wzorców, takich jak zwykłe zmienne środowiskowe. Często stosowanymi mechanizmami są volumes, dedykowane integracje do zarządzania sekretami, Docker secrets oraz Kubernetes Secrets. Żaden z nich nie eliminuje całkowicie ryzyka, zwłaszcza jeśli attacker ma już code execution w workloadzie, ale nadal są lepsze niż trwałe przechowywanie credentials w obrazie lub ich swobodne ujawnianie za pośrednictwem narzędzi inspekcyjnych.

Prosta deklaracja sekretu w stylu Docker Compose wygląda następująco:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
W Kubernetes obiekty Secret, projected volumes, service-account tokens oraz cloud workload identities tworzą szerszy i potężniejszy model, ale zwiększają również ryzyko przypadkowego ujawnienia przez host mounts, zbyt szerokie RBAC lub niewłaściwy projekt Podów.

## Abuse

Podczas przeglądu targetu celem jest ustalenie, czy secrets zostały wbudowane w image, wyciekły do layers lub zostały zamontowane w przewidywalnych lokalizacjach runtime:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Te polecenia pomagają rozróżnić trzy różne problemy: wycieki konfiguracji aplikacji, wycieki warstw obrazu oraz pliki sekretów wstrzykiwane w czasie wykonywania. Jeśli sekret pojawia się w ścieżce `/run/secrets`, projected volume lub tokenie tożsamości cloud, następnym krokiem jest ustalenie, czy zapewnia dostęp wyłącznie do bieżącego workloadu, czy do znacznie większej control plane.

### Pełny przykład: sekret osadzony w systemie plików obrazu

Jeśli pipeline budowania skopiował pliki `.env` lub dane uwierzytelniające do finalnego obrazu, post-exploitation staje się proste:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Wpływ zależy od aplikacji, ale osadzone signing keys, JWT secrets lub cloud credentials mogą z łatwością zamienić compromise kontenera w compromise API, lateral movement lub fałszowanie zaufanych application tokens.

### Pełny przykład: sprawdzanie wycieku sekretów podczas build

Jeśli obawa dotyczy tego, że historia obrazu zawierała warstwę zawierającą sekret:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Tego rodzaju przegląd jest przydatny, ponieważ sekret mógł zostać usunięty z końcowego widoku systemu plików, pozostając jednak w jednej z wcześniejszych warstw lub w metadanych builda.

## Kontrole

Kontrole te mają na celu ustalenie, czy proces obsługi image i sekretów prawdopodobnie zwiększył powierzchnię ataku przed uruchomieniem.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Co jest tutaj interesujące:

- Podejrzana historia buildów może ujawnić skopiowane credentials, materiały SSH lub niebezpieczne kroki builda.
- Secrets w ścieżkach projected volumes mogą prowadzić do dostępu do clustra lub cloud, a nie tylko do lokalnego dostępu do aplikacji.
- Duża liczba plików konfiguracyjnych z credentials w plaintext zwykle wskazuje, że image lub model deploymentu przenosi więcej materiału zaufania, niż jest to konieczne.

## Domyślne ustawienia środowiska uruchomieniowego

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Typowe ręczne osłabienie |
| --- | --- | --- | --- |
| Docker / BuildKit | Obsługuje bezpieczne mounty secrets podczas builda, ale nie robi tego automatycznie | Secrets mogą być montowane efemerycznie podczas `build`; image signing i scanning wymagają jawnych decyzji dotyczących workflow | kopiowanie secrets do image, przekazywanie secrets przez `ARG` lub `ENV`, wyłączanie kontroli provenance |
| Podman / Buildah | Obsługuje buildy natywne dla OCI oraz workflow uwzględniające secrets | Dostępne są bezpieczne workflow buildów, ale operatorzy nadal muszą świadomie je wybrać | osadzanie secrets w Containerfiles, szerokie build contexts, nadmiernie liberalne bind mounty podczas buildów |
| Kubernetes | Natywne obiekty Secret i projected volumes | Dostarczanie secrets podczas runtime jest funkcją pierwszej klasy, ale ekspozycja zależy od RBAC, projektu poda i mountów hosta | nadmiernie szerokie mounty Secret, niewłaściwe użycie tokenów service account, dostęp `hostPath` do wolumenów zarządzanych przez kubelet |
| Registries | Integralność jest opcjonalna, chyba że jest wymuszana | Zarówno publiczne, jak i prywatne registries zależą od policy, signing oraz decyzji admission | swobodne pobieranie unsigned images, słaba kontrola admission, niewłaściwe zarządzanie kluczami |

{{#include ../../../banners/hacktricks-training.md}}
