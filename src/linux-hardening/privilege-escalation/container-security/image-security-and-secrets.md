# Bezpieczeństwo obrazów, podpisy i sekrety

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Bezpieczeństwo kontenerów zaczyna się zanim uruchomione zostanie workload. Obraz decyduje, które binaria, interpretery, biblioteki, skrypty startowe i wbudowana konfiguracja trafią do produkcji. Jeśli obraz jest z backdoorem, przestarzały lub zbudowany z zasobami (sekretami) w nim wypieczonymi, to kolejne etapy runtime hardening działają już na skompromitowanym artefakcie.

Dlatego provenance obrazu, vulnerability scanning, signature verification oraz secret handling powinny być rozważane razem z namespaces i seccomp. Chronią inną fazę cyklu życia, ale błędy tutaj często definiują powierzchnię ataku, którą runtime później musi ograniczyć.

## Rejestry obrazów i zaufanie

Obrazy mogą pochodzić z publicznych rejestrów, takich jak Docker Hub, albo z prywatnych rejestrów prowadzonych przez organizację. Pytanie bezpieczeństwa to nie tylko miejsce przechowywania obrazu, lecz czy zespół potrafi ustalić jego provenance i integralność. Pobieranie niepodpisanych lub słabo śledzonych obrazów z publicznych źródeł zwiększa ryzyko, że złośliwa lub zmanipulowana zawartość trafi do produkcji. Nawet wewnętrznie hostowane rejestry wymagają jasnego właścicielstwa, przeglądu i polityki zaufania.

Docker Content Trust historycznie wykorzystywał koncepcje Notary i TUF do wymuszania podpisanych obrazów. Dokładny ekosystem ewoluował, ale trwała lekcja pozostaje przydatna: tożsamość i integralność obrazu powinny być weryfikowalne, a nie zakładane.

Przykładowy historyczny workflow Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Sens przykładu nie polega na tym, że każdy zespół musi nadal używać tych samych narzędzi, lecz na tym, że podpisywanie i zarządzanie kluczami to zadania operacyjne, a nie abstrakcyjna teoria.

## Skanowanie podatności

Skanowanie obrazów pomaga odpowiedzieć na dwa różne pytania. Po pierwsze, czy obraz zawiera znane podatne pakiety lub biblioteki? Po drugie, czy obraz zawiera niepotrzebne oprogramowanie, które zwiększa powierzchnię ataku? Obraz pełen narzędzi debugujących, powłok, interpreterów i przestarzałych pakietów jest zarówno łatwiejszy do wykorzystania, jak i trudniejszy do analizowania.

Przykłady powszechnie używanych skanerów obejmują:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Wyniki tych narzędzi należy interpretować ostrożnie. Luka w nieużywanym pakiecie nie niesie takiego samego ryzyka jak odsłonięta ścieżka RCE, ale obie są nadal istotne przy decyzjach o hardeningu.

## Sekrety podczas budowania

Jednym z najstarszych błędów w potokach budowy obrazów kontenerowych jest osadzanie sekretów bezpośrednio w obrazie lub przekazywanie ich przez zmienne środowiskowe, które później stają się widoczne przez `docker inspect`, logi budowania lub odzyskane warstwy. Sekrety w czasie budowania powinny być montowane tymczasowo podczas budowania, zamiast kopiowane do systemu plików obrazu.

BuildKit poprawił ten model, umożliwiając dedykowane zarządzanie sekretami w czasie budowy. Zamiast zapisywać sekret w warstwie, krok budowania może zużyć go przejściowo:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Ma to znaczenie, ponieważ warstwy obrazu są trwałymi artefaktami. Gdy sekret trafi do zatwierdzonej warstwy, późniejsze usunięcie pliku w innej warstwie nie usuwa faktycznie pierwotnego ujawnienia z historii obrazu.

## Sekrety w czasie wykonywania

Sekrety potrzebne uruchomionemu workloadowi również powinny, gdy to możliwe, unikać ad hoc wzorców, takich jak zwykłe zmienne środowiskowe. Volumes, dedykowane integracje zarządzania sekretami, Docker secrets oraz Kubernetes Secrets to powszechne mechanizmy. Żadna z nich nie eliminuje wszystkich ryzyk, szczególnie jeśli atakujący już ma możliwość wykonania kodu w workloadzie, ale nadal są one preferowane zamiast trwale przechowywać poświadczenia w obrazie lub eksponować je swobodnie przez narzędzia inspekcyjne.

Proste deklarowanie sekretu w stylu Docker Compose wygląda tak:
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
W Kubernetes, Secret objects, projected volumes, service-account tokens i cloud workload identities tworzą szerszy i bardziej zaawansowany model, ale także stwarzają więcej okazji do przypadkowego ujawnienia przez host mounts, zbyt szerokie RBAC lub słaby projekt Pod.

## Nadużycia

Podczas przeglądu celu celem jest odkrycie, czy secrets zostały wbudowane w image, leaked into layers, lub zamontowane w przewidywalnych lokalizacjach czasu wykonywania:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Te polecenia pomagają rozróżnić trzy różne problemy: application configuration leaks, image-layer leaks oraz runtime-injected secret files. Jeśli sekret pojawi się w katalogu `/run/secrets`, w projected volume lub pod ścieżką cloud identity token, kolejnym krokiem jest ustalenie, czy zapewnia on dostęp tylko do bieżącego workloadu, czy do znacznie większego control plane.

### Pełny przykład: osadzony sekret w systemie plików obrazu

Jeśli build pipeline skopiował pliki `.env` lub poświadczenia do finalnego obrazu, post-exploitation staje się proste:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Wpływ zależy od aplikacji, ale embedded signing keys, JWT secrets lub cloud credentials mogą łatwo przekształcić kompromis kontenera w API compromise, lateral movement lub forgery of trusted application tokens.

### Pełny przykład: Build-Time Secret Leakage Check

Jeśli istnieje obawa, że image history uchwycił warstwę zawierającą sekrety:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Ten rodzaj przeglądu jest przydatny, ponieważ secret mógł zostać usunięty z końcowego widoku systemu plików, podczas gdy nadal pozostaje w wcześniejszej warstwie lub w metadanych builda.

## Sprawdzenia

Te sprawdzenia mają na celu ustalenie, czy image i pipeline obsługi secretów prawdopodobnie zwiększyły attack surface przed uruchomieniem.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Co jest tu interesujące:

- Podejrzana historia buildów może ujawnić skopiowane dane uwierzytelniające, materiały SSH lub niebezpieczne kroki budowania.
- Secrets znajdujące się pod ścieżkami projected volume mogą prowadzić do dostępu do cluster lub cloud, a nie tylko do lokalnej aplikacji.
- Duża liczba plików konfiguracyjnych zawierających poświadczenia w jawnym tekście zwykle wskazuje, że image lub model wdrożenia przenosi więcej materiałów zaufania niż to konieczne.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Supports secure build-time secret mounts, but not automatically | Secrets can be mounted ephemerally during `build`; image signing and scanning require explicit workflow choices | copying secrets into the image, passing secrets by `ARG` or `ENV`, disabling provenance checks |
| Podman / Buildah | Supports OCI-native builds and secret-aware workflows | Strong build workflows are available, but operators must still choose them intentionally | embedding secrets in Containerfiles, broad build contexts, permissive bind mounts during builds |
| Kubernetes | Native Secret objects and projected volumes | Runtime secret delivery is first-class, but exposure depends on RBAC, pod design, and host mounts | overbroad Secret mounts, service-account token misuse, `hostPath` access to kubelet-managed volumes |
| Registries | Integrity is optional unless enforced | Public and private registries both depend on policy, signing, and admission decisions | pulling unsigned images freely, weak admission control, poor key management |
{{#include ../../../banners/hacktricks-training.md}}
