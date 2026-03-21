# Przestrzeń użytkownika

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

User namespace zmienia znaczenie identyfikatorów użytkownika i grupy, pozwalając kernelowi mapować ID widziane wewnątrz namespace na inne ID na zewnątrz. To jedna z ważniejszych współczesnych protekcji dla containerów, ponieważ bezpośrednio adresuje największy historyczny problem klasycznych containerów: **root wewnątrz kontenera był niebezpiecznie bliski rootowi na hoście**.

Dzięki user namespaces proces może działać jako UID 0 wewnątrz kontenera, a jednocześnie odpowiadać nieuprzywilejowanemu zakresowi UID na hoście. Oznacza to, że proces może zachowywać się jak root dla wielu zadań wewnątrz kontenera, podczas gdy z punktu widzenia hosta ma znacznie mniejsze uprawnienia. Nie rozwiązuje to wszystkich problemów bezpieczeństwa kontenerów, ale znacząco zmienia konsekwencje przejęcia kontenera.

## Działanie

User namespace posiada pliki mapowania, takie jak `/proc/self/uid_map` i `/proc/self/gid_map`, które opisują jak ID w namespace tłumaczą się na ID rodzica. Jeśli root wewnątrz namespace mapowany jest na nieuprzywilejowany UID hosta, operacje wymagające prawdziwego roota na hoście po prostu nie mają takiej samej wagi. Dlatego user namespaces są centralne dla **rootless containers** i dlaczego są jedną z największych różnic między starszymi domyślnymi konfiguracjami containerów z rootem a nowocześniejszymi projektami opartymi na zasadzie najmniejszych uprawnień.

Punkt jest subtelny, ale kluczowy: root wewnątrz kontenera nie jest wyeliminowany, jest **przetłumaczony**. Proces nadal doświadcza środowiska podobnego do root lokalnie, ale host nie powinien traktować go jako pełnego roota.

## Laboratorium

Przykładowy test ręczny to:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Dzięki temu bieżący użytkownik jest widziany jako root wewnątrz namespace, podczas gdy poza nim na hoście nadal nie jest rootem. To jedno z najlepszych prostych demo pokazujących, dlaczego user namespaces są tak wartościowe.

W kontenerach możesz porównać widoczne mapowanie z:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Dokładny wynik zależy od tego, czy silnik używa user namespace remapping, czy bardziej tradycyjnej rootful configuration.

Możesz również odczytać mapowanie po stronie hosta za pomocą:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Runtime Usage

Rootless Podman jest jednym z najjaśniejszych przykładów traktowania user namespaces jako pełnoprawnego mechanizmu bezpieczeństwa. Rootless Docker również od nich zależy. Docker's userns-remap poprawia bezpieczeństwo także w rootful daemon deployments, chociaż historycznie wiele wdrożeń wyłączało tę funkcję ze względów kompatybilności. Kubernetes support for user namespaces uległ poprawie, ale adopcja i ustawienia domyślne różnią się w zależności od runtime, distro i cluster policy. Systemy Incus/LXC również silnie polegają na UID/GID shifting i idmapping.

Ogólny trend jest jasny: środowiska, które poważnie wykorzystują user namespaces, zwykle lepiej odpowiadają na pytanie „co właściwie oznacza root w kontenerze?” niż środowiska, które tego nie robią.

## Advanced Mapping Details

Gdy proces bez uprawnień zapisuje do `uid_map` lub `gid_map`, kernel stosuje surowsze reguły niż wobec piszącego z uprzywilejowanej przestrzeni nazw rodzica. Dozwolone są tylko ograniczone mapowania, a w przypadku `gid_map` piszący zwykle musi najpierw wyłączyć `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Ten szczegół ma znaczenie, ponieważ wyjaśnia, dlaczego konfiguracja user-namespace czasami zawodzi w rootless eksperymentach i dlaczego runtimes potrzebują starannej logiki pomocniczej dotyczącej delegowania UID/GID.

Kolejną zaawansowaną funkcją jest **ID-mapped mount**. Zamiast zmieniać własność na dysku, ID-mapped mount aplikuje mapowanie user-namespace do mountu, tak że własność wydaje się być przetłumaczona w tym widoku mountu. Jest to szczególnie istotne w rootless i nowoczesnych runtimes, ponieważ pozwala używać współdzielonych ścieżek hosta bez potrzeby rekurencyjnego wykonywania `chown`. Z punktu widzenia bezpieczeństwa funkcja zmienia sposób, w jaki bind mount wydaje się być zapisywalny od wewnątrz namespace, mimo że nie przepisuje metadanych systemu plików.

Na koniec, pamiętaj, że gdy proces tworzy lub wchodzi do nowego user namespace, otrzymuje pełny zestaw capabilities **inside that namespace**. To nie oznacza, że nagle zyskał host-globalną władzę. Oznacza to, że te capabilities mogą być używane tylko tam, gdzie model namespace i inne zabezpieczenia na to pozwalają. Dlatego `unshare -U` może nagle umożliwić operacje uprzywilejowane związane z mountingiem lub lokalne dla namespace, bez bezpośredniego usuwania granicy roota hosta.

## Błędy konfiguracji

Główną słabością jest po prostu nieużywanie user namespaces w środowiskach, gdzie byłyby możliwe. Jeśli container root mapuje się zbyt bezpośrednio do host root, zapisywalne host mounts i uprzywilejowane operacje jądra stają się znacznie bardziej niebezpieczne. Innym problemem jest wymuszanie współdzielenia host user namespace lub wyłączanie remappingu dla kompatybilności bez uznania, jak bardzo zmienia to trust boundary.

User namespaces należy rozważać łącznie z resztą modelu. Nawet gdy są aktywne, szeroka ekspozycja runtime API lub bardzo słaba konfiguracja runtime może nadal umożliwić privilege escalation innymi ścieżkami. Ale bez nich wiele starych klas breakout staje się znacznie łatwiejszych do exploitowania.

## Nadużycia

Jeżeli container jest rootful bez separacji user namespace, zapisywalny host bind mount staje się znacznie bardziej niebezpieczny, ponieważ proces może rzeczywiście zapisywać jako host root. Niebezpieczne capabilities również nabierają większego znaczenia. Atakujący nie musi już tak bardzo walczyć z translation boundary, ponieważ ta granica praktycznie nie istnieje.

Obecność lub brak user namespace powinno być sprawdzone wcześnie przy ocenie ścieżki breakout z container. Nie odpowiada na wszystkie pytania, ale natychmiast pokazuje, czy "root in container" ma bezpośrednie znaczenie dla hosta.

Najbardziej praktyczny wzorzec nadużycia to potwierdzić mapowanie, a następnie natychmiast przetestować, czy zawartość zamontowana z hosta jest zapisywalna z uprawnieniami istotnymi dla hosta:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Jeśli plik zostanie utworzony jako prawdziwy host root, izolacja user namespace jest w praktyce nieobecna dla tej ścieżki. W tym momencie klasyczne nadużycia plików hosta stają się realistyczne:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Bardziej bezpiecznym potwierdzeniem podczas testu na żywo jest zapisanie nieszkodliwego znacznika zamiast modyfikowania krytycznych plików:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Te kontrole są istotne, ponieważ szybko odpowiadają na kluczowe pytanie: czy root w tym kontenerze mapuje się wystarczająco blisko rootowi hosta, że zapisywalny host mount natychmiast staje się ścieżką do kompromitacji hosta?

### Pełny przykład: Odzyskiwanie namespace-local capabilities

Jeśli seccomp pozwala na `unshare`, a środowisko dopuszcza utworzenie nowego user namespace, proces może odzyskać pełny capability set wewnątrz tego nowego namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Samo w sobie nie jest to host escape. Istotne jest to, że user namespaces mogą ponownie włączyć uprzywilejowane namespace-local actions, które później łączą się z weak mounts, vulnerable kernels lub badly exposed runtime surfaces.

## Sprawdzenia

Te polecenia mają odpowiedzieć na najważniejsze pytanie na tej stronie: do czego root wewnątrz tego container mapuje się na host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Co jest tu interesujące:

- Jeśli proces ma UID 0 i pliki maps pokazują bezpośrednie lub bardzo bliskie mapowanie host-root, kontener jest znacznie bardziej niebezpieczny.
- Jeśli root mapuje się na nieuprzywilejowany zakres hosta, to stanowi znacznie bezpieczniejszy punkt wyjścia i zazwyczaj wskazuje na rzeczywistą izolację user namespace.
- Pliki mapowań są bardziej wartościowe niż samo `id`, ponieważ `id` pokazuje tylko tożsamość lokalną w namespace.

Jeśli workload działa jako UID 0, a mapowanie pokazuje, że odpowiada to blisko host root, powinieneś interpretować pozostałe uprawnienia kontenera znacznie surowiej.
