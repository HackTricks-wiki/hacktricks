# Przestrzeń nazw użytkownika

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw użytkownika zmienia znaczenie identyfikatorów użytkownika i grupy, pozwalając jądru mapować identyfikatory widziane wewnątrz przestrzeni nazw na inne identyfikatory poza nią. To jedna z najważniejszych współczesnych ochron dla kontenerów, ponieważ bezpośrednio rozwiązuje największy historyczny problem klasycznych kontenerów: **root wewnątrz kontenera był niewygodnie blisko roota na hoście**.

Dzięki przestrzeniom nazw użytkownika proces może działać jako UID 0 wewnątrz kontenera, a jednocześnie odpowiadać zakresowi UID bez uprawnień na hoście. Oznacza to, że proces może zachowywać się jak root dla wielu zadań wewnątrz kontenera, będąc jednak znacznie mniej potężnym z perspektywy hosta. Nie rozwiązuje to wszystkich problemów bezpieczeństwa kontenerów, ale znacząco zmienia konsekwencje przejęcia kontenera.

## Działanie

Przestrzeń nazw użytkownika posiada pliki mapujące takie jak `/proc/self/uid_map` i `/proc/self/gid_map`, które opisują, jak identyfikatory przestrzeni nazw tłumaczą się na identyfikatory nadrzędne. Jeśli root wewnątrz przestrzeni nazw mapuje się na nieuprzywilejowany UID na hoście, operacje wymagające prawdziwego roota hosta po prostu nie mają tej samej wagi. Dlatego przestrzenie nazw użytkownika są kluczowe dla kontenerów bez uprawnień root i stanowią jedną z największych różnic między starszymi domyślnymi konfiguracjami kontenerów działających z uprawnieniami root a nowocześniejszymi projektami opartymi na zasadzie najmniejszych uprawnień.

Sedno jest subtelne, ale kluczowe: root wewnątrz kontenera nie jest eliminowany, on jest **przekształcony**. Proces nadal doświadcza lokalnie środowiska przypominającego root, ale host nie powinien traktować go jako pełnego roota.

## Laboratorium

Test ręczny wygląda tak:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
To sprawia, że bieżący użytkownik jest widoczny jako root wewnątrz namespace, podczas gdy poza nim nadal nie jest rootem na hoście. Jest to jedno z najlepszych prostych demo wyjaśniających, dlaczego user namespaces są tak wartościowe.

W kontenerach możesz porównać widoczne mapowanie z:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Dokładny wynik zależy od tego, czy silnik używa user namespace remapping, czy bardziej tradycyjnej konfiguracji rootful.

Możesz także odczytać mapowanie po stronie hosta za pomocą:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Użycie w czasie wykonywania

Rootless Podman jest jednym z najczytelniejszych przykładów traktowania user namespaces jako mechanizmu bezpieczeństwa pierwszej klasy. Rootless Docker również od nich zależy. Obsługa userns-remap w Dockerze poprawia bezpieczeństwo także w wdrożeniach z rootful daemon, chociaż historycznie wiele instalacji pozostawiała ją wyłączoną ze względów kompatybilności. Wsparcie dla user namespaces w Kubernetes poprawiło się, ale adopcja i ustawienia domyślne różnią się w zależności od runtime, dystrybucji i polityki klastra. Systemy Incus/LXC również mocno polegają na przesuwaniu UID/GID i pomysłach idmapping.

Ogólny trend jest jasny: środowiska, które poważnie używają user namespaces, zazwyczaj lepiej odpowiadają na pytanie „co właściwie oznacza root w kontenerze?” niż środowiska, które tego nie robią.

## Zaawansowane szczegóły mapowania

Kiedy nieuprzywilejowany proces zapisuje do `uid_map` lub `gid_map`, jądro stosuje surowsze reguły niż wobec uprzywilejowanego piszącego w przestrzeni nazw nadrzędnej. Dozwolone są tylko ograniczone mapowania, a dla `gid_map` zazwyczaj trzeba najpierw wyłączyć `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Ta szczegółowość ma znaczenie, ponieważ wyjaśnia, dlaczego konfiguracja user-namespace czasami zawodzi w eksperymentach rootless i dlaczego runtimy potrzebują starannej logiki pomocniczej do delegowania UID/GID.

Kolejną zaawansowaną funkcją jest **ID-mapped mount**. Zamiast zmieniać własność na dysku, ID-mapped mount stosuje mapowanie user-namespace do mountu tak, że własność wydaje się być przetłumaczona w tym widoku mountu. Jest to szczególnie istotne w setupach rootless i nowoczesnych runtime'ach, ponieważ pozwala używać współdzielonych ścieżek hosta bez rekurencyjnych operacji `chown`. Z punktu widzenia bezpieczeństwa funkcja zmienia to, jak zapisywalny bind mount wygląda od środka namespace, mimo że nie przepisuje underlying filesystem metadata.

Na koniec pamiętaj, że kiedy proces tworzy lub wchodzi do nowego user namespace, otrzymuje pełny capability set **inside that namespace**. To nie znaczy, że nagle zyskał host-globalne uprawnienia. Oznacza to, że te capabilities mogą być używane tylko tam, gdzie model namespace i inne zabezpieczenia na to pozwalają. To jest powód, dla którego `unshare -U` może nagle umożliwić mounting lub operacje uprzywilejowane lokalne dla namespace bez bezpośredniego zniknięcia granicy host root.

## Błędne konfiguracje

Główną słabością jest po prostu nieużywanie user namespaces w środowiskach, gdzie byłyby możliwe. Jeśli container root mapuje się zbyt bezpośrednio do host root, zapisywalne host mounts i uprzywilejowane operacje kernela stają się znacznie bardziej niebezpieczne. Innym problemem jest wymuszanie współdzielenia host user namespace lub wyłączanie remappingu dla kompatybilności, bez rozpoznania, jak bardzo zmienia to trust boundary.

User namespaces powinny być także rozważane razem z resztą modelu. Nawet gdy są aktywne, szeroka ekspozycja runtime API lub bardzo słaba konfiguracja runtime może nadal pozwolić na privilege escalation innymi ścieżkami. Ale bez nich wiele starych klas breakout staje się dużo łatwiejszych do wykorzystania.

## Nadużycie

Jeśli container jest rootful bez separacji user namespace, zapisywalny host bind mount staje się zdecydowanie bardziej niebezpieczny, ponieważ proces faktycznie może zapisywać jako host root. Niebezpieczne capabilities również stają się bardziej znaczące. Atakujący nie musi już tak bardzo walczyć z translation boundary, ponieważ ta granica praktycznie nie istnieje.

Obecność lub brak user namespace powinien być sprawdzany wcześnie przy ocenianiu ścieżki container breakout. Nie odpowiada to na każde pytanie, ale od razu pokazuje, czy "root in container" ma bezpośrednie znaczenie dla hosta.

Najbardziej praktyczny wzorzec nadużycia to potwierdzić mapping, a następnie od razu przetestować, czy host-mounted content jest zapisywalny z uprawnieniami istotnymi dla hosta:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Jeśli plik zostanie utworzony jako real host root, user namespace isolation jest w praktyce nieobecna dla tej ścieżki. W tym momencie klasyczne host-file abuses stają się realistyczne:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Bezpieczniejszym potwierdzeniem podczas oceny na żywo jest zapisanie nieszkodliwego znacznika zamiast modyfikowania krytycznych plików:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Te kontrole mają znaczenie, ponieważ szybko odpowiadają na zasadnicze pytanie: czy root w tym containerze jest odwzorowany wystarczająco blisko host root, aby writable host mount od razu stał się ścieżką kompromitacji hosta?

### Pełny przykład: odzyskanie Namespace-Local Capabilities

Jeśli seccomp pozwala na `unshare`, a środowisko dopuszcza nowy user namespace, proces może odzyskać pełen zestaw capabilities wewnątrz tego nowego namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Samo w sobie nie jest to host escape. Istotne jest to, że user namespaces mogą ponownie włączać uprzywilejowane, lokalne dla namespace akcje, które później łączą się ze słabymi mounts, podatnymi kernels lub źle wystawionymi runtime surfaces.

## Sprawdzenia

Te polecenia mają na celu odpowiedzieć na najważniejsze pytanie na tej stronie: do czego root wewnątrz tego containera jest mapowany na hoście?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Co jest tutaj interesujące:

- Jeśli proces jest UID 0 i maps pokazują bezpośrednie lub bardzo bliskie host-root mapping, container jest znacznie bardziej niebezpieczny.
- Jeśli root maps to unprivileged host range, to znacznie bezpieczniejszy baseline i zwykle wskazuje na real user namespace isolation.
- mapping files są bardziej wartościowe niż `id` samo w sobie, ponieważ `id` pokazuje tylko namespace-local identity.

Jeśli workload działa jako UID 0 i mapping pokazuje, że odpowiada to blisko host root, powinieneś interpretować resztę container's privileges znacznie bardziej restrykcyjnie.
{{#include ../../../../../banners/hacktricks-training.md}}
