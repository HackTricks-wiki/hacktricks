# Bezpieczeństwo obrazów, podpisywanie i sekrety

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Bezpieczeństwo kontenerów zaczyna się zanim uruchomiony zostanie workload. Obraz decyduje, które binaria, interpretery, biblioteki, skrypty startowe i osadzone konfiguracje trafią do produkcji. Jeśli obraz jest backdoored, przestarzały lub zbudowany z wbudowanymi sekretami, późniejsze hardening środowiska uruchomieniowego działa już na skompromitowanym artefakcie.

Dlatego pochodzenie obrazu, skanowanie podatności, weryfikacja podpisów i obsługa sekretów należą do tej samej dyskusji co namespaces i seccomp. Chronią inny etap cyklu życia, ale błędy tutaj często definiują powierzchnię ataku, którą runtime będzie musiał później ograniczyć.

Docker Content Trust historycznie wykorzystywał koncepcje Notary i TUF do wymuszania podpisanych obrazów. Dokładny ekosystem ewoluował, ale trwała lekcja pozostaje przydatna: tożsamość i integralność obrazu powinny być weryfikowalne, a nie zakładane.

Przykładowy historyczny workflow Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Chodzi w tym przykładzie nie o to, by każdy zespół musiał nadal używać tych samych narzędzi, lecz o to, że podpisywanie i zarządzanie kluczami to zadania operacyjne, a nie abstrakcyjna teoria.

## Skanowanie podatności

Skanowanie obrazów pomaga odpowiedzieć na dwa różne pytania. Po pierwsze: czy obraz zawiera znane podatne pakiety lub biblioteki? Po drugie: czy obraz zawiera niepotrzebne oprogramowanie, które zwiększa powierzchnię ataku? Obraz pełen narzędzi debugujących, powłok, interpreterów i przestarzałych pakietów jest zarówno łatwiejszy do wykorzystania, jak i trudniejszy do analizy.

Przykłady powszechnie używanych skanerów obejmują:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Wyniki tych narzędzi należy interpretować ostrożnie. Luka w nieużywanym pakiecie nie niesie takiego samego ryzyka jak odsłonięta ścieżka RCE, ale obie są istotne przy podejmowaniu decyzji dotyczących zabezpieczeń.

## Sekrety podczas budowy

Jednym z najstarszych błędów w pipeline'ach budowania kontenerów jest umieszczanie sekretów bezpośrednio w obrazie lub przekazywanie ich przez zmienne środowiskowe, które później stają się widoczne przez `docker inspect`, logi builda lub odzyskane warstwy. Sekrety używane podczas budowy powinny być montowane tymczasowo w trakcie procesu budowy, zamiast kopiowania ich do systemu plików obrazu.

BuildKit ulepszył ten model, umożliwiając dedykowane zarządzanie sekretami podczas budowy. Zamiast zapisywać sekret do warstwy, krok budowania może go zużyć tymczasowo:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
To ma znaczenie, ponieważ warstwy obrazu są trwałymi artefaktami. Gdy sekret trafi do zatwierdzonej warstwy, późniejsze usunięcie pliku w innej warstwie nie usuwa w rzeczywistości pierwotnego ujawnienia z historii obrazu.

## Sekrety w czasie wykonywania

Sekrety potrzebne uruchamianemu workloadowi powinny, kiedy to możliwe, unikać ad-hocowych wzorców, takich jak zwykłe zmienne środowiskowe. Volumes, dedykowane integracje do zarządzania sekretami, Docker secrets i Kubernetes Secrets są powszechnie stosowanyymi mechanizmami. Żaden z nich nie usuwa całego ryzyka, szczególnie jeśli atakujący ma już wykonanie kodu w workloadzie, ale i tak są one preferowane zamiast trwałego przechowywania poświadczeń w obrazie lub swobodnego ujawniania ich przez narzędzia do inspekcji.

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
W Kubernetes, Secret objects, projected volumes, service-account tokens i cloud workload identities tworzą szerszy i bardziej zaawansowany model, ale jednocześnie zwiększają możliwości przypadkowego ujawnienia poprzez host mounts, rozległe RBAC lub słabą konstrukcję Pod.

## Nadużycie

Podczas przeglądu celu celem jest ustalenie, czy secrets zostały wbudowane w image, leaked into layers, lub zamontowane w przewidywalnych runtime locations:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Te polecenia pomagają rozróżnić trzy różne problemy: application configuration leaks, image-layer leaks i runtime-injected secret files. Jeśli sekret pojawi się pod `/run/secrets`, w projected volume lub na ścieżce cloud identity token, następnym krokiem jest ustalenie, czy zapewnia dostęp tylko do bieżącego workloadu, czy do znacznie większego control plane.

### Pełny przykład: Wbudowany sekret w systemie plików obrazu

Jeśli build pipeline skopiował pliki `.env` lub poświadczenia do finalnego obrazu, post-exploitation staje się proste:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Wpływ zależy od aplikacji, ale osadzone klucze podpisywania, JWT secrets lub poświadczenia do chmury mogą łatwo przekształcić kompromitację kontenera w kompromitację API, lateral movement lub fałszowanie zaufanych tokenów aplikacji.

### Pełny przykład: Build-Time Secret Leakage Check

Jeśli obawą jest, że historia obrazu przechwyciła warstwę zawierającą sekret:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Taki przegląd jest przydatny, ponieważ sekret mógł zostać usunięty z ostatecznego widoku systemu plików, podczas gdy nadal pozostawał we wcześniejszej warstwie lub w metadanych kompilacji.

## Sprawdzenia

Te sprawdzenia mają na celu ustalenie, czy obraz i pipeline obsługi sekretów prawdopodobnie zwiększyły powierzchnię ataku przed uruchomieniem.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
- Podejrzana historia buildów może ujawnić skopiowane dane uwierzytelniające, materiały SSH lub niebezpieczne kroki buildowania.
- Secrets pod projected volume paths mogą prowadzić do dostępu do klastra lub chmury, a nie tylko do lokalnej aplikacji.
- Duża liczba plików konfiguracyjnych z poświadczeniami w formie plaintext zwykle wskazuje, że image lub deployment model przenosi więcej materiału zaufania niż jest to konieczne.

## Domyślne ustawienia środowiska uruchomieniowego

| Runtime / platform | Stan domyślny | Domyślne zachowanie | Typowe ręczne osłabienia |
| --- | --- | --- | --- |
| Docker / BuildKit | Obsługuje bezpieczne montowanie sekretów w czasie buildu, ale nie domyślnie | Secrets mogą być montowane efemerycznie podczas `build`; image signing and scanning wymagają jawnego wyboru workflowu | kopiowanie secrets do image'a, przekazywanie secrets przez `ARG` lub `ENV`, wyłączanie provenance checks |
| Podman / Buildah | Obsługuje OCI-native builds i workflowy świadome secretów | Dostępne są solidne build workflowy, ale operatorzy muszą je świadomie wybrać | osadzanie secrets w Containerfiles, szerokie build contexts, permissive bind mounts podczas buildów |
| Kubernetes | Natywne obiekty Secret i projected volumes | Dostarczanie Secretów w runtime jest traktowane priorytetowo, ale ekspozycja zależy od RBAC, projektu poda i host mounts | nadmiernie szerokie Secret mounts, niewłaściwe użycie tokenów service-account, `hostPath` access to kubelet-managed volumes |
| Registries | Integralność jest opcjonalna, jeśli nie jest wymuszona | Zarówno rejestry publiczne, jak i prywatne zależą od polityk, podpisywania i decyzji admission | swobodne pobieranie niepodpisanych image'ów, słaba kontrola admission, kiepskie zarządzanie kluczami |
