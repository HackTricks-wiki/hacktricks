# Bezpieczeństwo obrazów, podpisywanie i sekrety

{{#include ../../../banners/hacktricks-training.md}}

## Rejestry obrazów i zaufanie

Bezpieczeństwo kontenerów zaczyna się, zanim workload zostanie uruchomiony. Obraz określa, które pliki binarne, interpretery, biblioteki, skrypty startowe i osadzona konfiguracja trafią do środowiska produkcyjnego. Jeśli obraz zawiera backdoor, jest nieaktualny lub zbudowano go z wbudowanymi sekretami, późniejsze hardening runtime już od początku działa na skompromitowanym artefakcie.

Dlatego image provenance, skanowanie pod kątem podatności, weryfikacja podpisów i obsługa sekretów powinny być omawiane razem z namespaces i seccomp. Chronią one inną fazę cyklu życia, ale występujące tu problemy często określają attack surface, który runtime musi później ograniczać.

## Rejestry obrazów i zaufanie

Obrazy mogą pochodzić z publicznych rejestrów, takich jak Docker Hub, lub z prywatnych rejestrów zarządzanych przez organizację. Kwestia bezpieczeństwa nie dotyczy wyłącznie tego, gdzie znajduje się obraz, ale również tego, czy zespół może potwierdzić jego provenance i integralność. Pobieranie niepodpisanych lub niewłaściwie śledzonych obrazów ze źródeł publicznych zwiększa ryzyko przedostania się do środowiska produkcyjnego złośliwej lub zmodyfikowanej zawartości. Nawet wewnętrznie hostowane rejestry wymagają jasno określonej odpowiedzialności, procesu review i polityki zaufania.

Docker Content Trust historycznie wykorzystywał koncepcje Notary i TUF do wymagania podpisanych obrazów. Dokładny ekosystem ewoluował, ale podstawowa lekcja pozostaje aktualna: tożsamość i integralność obrazu powinny być możliwe do zweryfikowania, a nie tylko zakładane.

Przykład historycznego workflow Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Celem przykładu nie jest stwierdzenie, że każdy zespół musi nadal korzystać z tych samych narzędzi, lecz pokazanie, że podpisywanie i zarządzanie kluczami to zadania operacyjne, a nie abstrakcyjna teoria.

## Skanowanie podatności

Skanowanie image pomaga odpowiedzieć na dwa różne pytania. Po pierwsze, czy image zawiera znane podatne pakiety lub biblioteki? Po drugie, czy image zawiera niepotrzebne oprogramowanie, które zwiększa attack surface? Image pełen narzędzi do debugowania, powłok, interpreterów i nieaktualnych pakietów jest zarówno łatwiejszy do wykorzystania, jak i trudniejszy do przeanalizowania.

Przykłady powszechnie używanych skanerów obejmują:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Wyniki działania tych narzędzi należy dokładnie interpretować. Podatność w nieużywanym pakiecie nie wiąże się z takim samym ryzykiem jak exposed RCE path, ale obie kwestie nadal mają znaczenie przy podejmowaniu decyzji dotyczących hardeningu.

## Sekrety podczas budowania

Jednym z najstarszych błędów w pipeline'ach budowania kontenerów jest umieszczanie sekretów bezpośrednio w obrazie lub przekazywanie ich przez zmienne środowiskowe, które później stają się widoczne za pośrednictwem `docker inspect`, logów budowania lub odzyskanych warstw. Sekrety używane podczas budowania powinny być montowane tymczasowo w trakcie budowania, zamiast kopiowania ich do systemu plików obrazu.

BuildKit ulepszył ten model, umożliwiając dedykowaną obsługę sekretów używanych podczas budowania. Zamiast zapisywać sekret w warstwie, krok budowania może użyć go tymczasowo:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Ma to znaczenie, ponieważ warstwy image są trwałymi artefaktami. Gdy secret trafi do zatwierdzonej warstwy, późniejsze usunięcie pliku w innej warstwie nie usuwa faktycznie pierwotnego ujawnienia z historii image.

## Sekrety w czasie działania

Sekrety wymagane przez działający workload również powinny, w miarę możliwości, unikać doraźnych wzorców, takich jak zwykłe zmienne środowiskowe. Volumes, dedykowane integracje z systemami zarządzania secretami, Docker secrets i Kubernetes Secrets to popularne mechanizmy. Żaden z nich nie eliminuje całkowicie ryzyka, szczególnie jeśli attacker ma już code execution w workloadzie, ale nadal są preferowane zamiast trwałego przechowywania credentials w image lub ich swobodnego ujawniania przez narzędzia inspekcyjne.

Prosta deklaracja secreta w stylu Docker Compose wygląda następująco:
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
W Kubernetes obiekty Secret, projected volumes, service-account tokens oraz cloud workload identities tworzą szerszy i potężniejszy model, ale zwiększają również liczbę możliwości przypadkowego ujawnienia danych przez host mounts, szerokie reguły RBAC lub słaby projekt Podów.

## Abuse

Podczas przeglądania celu należy ustalić, czy sekrety zostały wbudowane w image, wyciekły do layers lub zostały zamontowane w przewidywalnych lokalizacjach środowiska uruchomieniowego:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Te polecenia pomagają rozróżnić trzy różne problemy: wycieki konfiguracji aplikacji, wycieki w warstwie obrazu oraz pliki sekretów wstrzykiwane w czasie działania. Jeśli sekret pojawia się w `/run/secrets`, zamontowanym wolumenie projekcji lub ścieżce tokenu tożsamości chmurowej, następnym krokiem jest ustalenie, czy zapewnia dostęp wyłącznie do bieżącego workloadu, czy do znacznie większej control plane.

### Pełny przykład: sekret osadzony w systemie plików obrazu

Jeśli pipeline budowania skopiował pliki `.env` lub dane uwierzytelniające do finalnego obrazu, post-exploitation staje się proste:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Wpływ zależy od aplikacji, ale osadzone klucze podpisywania, sekrety JWT lub cloud credentials mogą łatwo przekształcić przejęcie kontenera w przejęcie API, lateral movement lub fałszowanie zaufanych tokenów aplikacji.

### Pełny przykład: sprawdzanie secret leak na etapie build

Jeśli problem dotyczy tego, że historia obrazu zawiera warstwę zawierającą sekret:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Ten rodzaj przeglądu jest przydatny, ponieważ sekret mógł zostać usunięty z końcowego widoku systemu plików, a mimo to nadal pozostawać we wcześniejszej warstwie lub w metadanych budowania.

## Kontrole

Celem tych kontroli jest ustalenie, czy potok obsługi image i sekretów prawdopodobnie zwiększył powierzchnię ataku przed uruchomieniem.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Co jest tutaj interesujące:

- Podejrzana historia buildów może ujawnić skopiowane credentials, materiały SSH lub niebezpieczne kroki builda.
- Secrets w ścieżkach projected volumes mogą prowadzić do dostępu do klastra lub cloud, a nie tylko do lokalnego dostępu do aplikacji.
- Duża liczba plików konfiguracyjnych z credentials w plaintext zwykle wskazuje, że image lub model deploymentu przenosi więcej materiału zaufania, niż jest to konieczne.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne działanie | Typowe ręczne osłabienie |
| --- | --- | --- | --- |
| Docker / BuildKit | Obsługuje bezpieczne secret mounts podczas builda, ale nie robi tego automatycznie | Secrets mogą być montowane efemerycznie podczas `build`; podpisywanie image i skanowanie wymagają jawnych decyzji dotyczących workflow | kopiowanie secrets do image, przekazywanie secrets przez `ARG` lub `ENV`, wyłączanie kontroli provenance |
| Podman / Buildah | Obsługuje buildy natywne dla OCI oraz workflows uwzględniające secrets | Dostępne są bezpieczne workflows builda, ale operatorzy nadal muszą świadomie ich użyć | osadzanie secrets w Containerfiles, szerokie build contexts, zbyt liberalne bind mounts podczas buildów |
| Kubernetes | Natywne obiekty Secret i projected volumes | Dostarczanie secrets w runtime jest obsługiwane natywnie, ale ekspozycja zależy od RBAC, projektu poda i mountów hosta | zbyt szerokie mountowanie Secret, niewłaściwe użycie tokenów service account, dostęp `hostPath` do wolumenów zarządzanych przez kubelet |
| Rejestry | Integralność jest opcjonalna, chyba że jest wymuszana | Zarówno publiczne, jak i prywatne rejestry zależą od zasad, podpisywania i decyzji admission | swobodne pobieranie niepodpisanych image, słaba kontrola admission, niewłaściwe zarządzanie kluczami |
{{#include ../../../banners/hacktricks-training.md}}
