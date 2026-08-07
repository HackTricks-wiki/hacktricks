# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

User namespace zmienia znaczenie identyfikatorów użytkowników i grup, pozwalając kernelowi mapować identyfikatory widoczne wewnątrz namespace na inne identyfikatory poza nim. Jest to jedna z najważniejszych współczesnych ochrony kontenerów, ponieważ bezpośrednio odpowiada na największy historyczny problem klasycznych kontenerów: **root wewnątrz kontenera był niepokojąco blisko roota na hoście**.

Dzięki user namespaces proces może działać jako UID 0 wewnątrz kontenera, a jednocześnie odpowiadać nieuprzywilejowanemu zakresowi UID na hoście. Oznacza to, że proces może zachowywać się jak root w przypadku wielu zadań wykonywanych wewnątrz kontenera, będąc jednocześnie znacznie mniej uprzywilejowanym z punktu widzenia hosta. Nie rozwiązuje to wszystkich problemów bezpieczeństwa kontenerów, ale znacząco zmienia konsekwencje przejęcia kontenera.

## Operation

User namespace posiada pliki mapowania, takie jak `/proc/self/uid_map` i `/proc/self/gid_map`, które opisują sposób tłumaczenia identyfikatorów namespace na identyfikatory nadrzędnego namespace. Jeśli root wewnątrz namespace jest mapowany na nieuprzywilejowany UID hosta, operacje wymagające rzeczywistego roota hosta nie mają już takiego samego znaczenia. Dlatego user namespaces są kluczowe dla **rootless containers** i stanowią jedną z największych różnic między starszymi domyślnymi konfiguracjami kontenerów rootful a bardziej nowoczesnymi projektami opartymi na zasadzie najmniejszych uprawnień.

Sedno jest subtelne, ale kluczowe: root wewnątrz kontenera nie zostaje wyeliminowany, lecz jest **tłumaczony**. Proces nadal lokalnie działa w środowisku przypominającym środowisko roota, ale host nie powinien traktować go jak pełnego roota.

## Lab

Ręczny test wygląda następująco:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Dzięki temu bieżący użytkownik pojawia się jako root wewnątrz namespace, nadal nie będąc host root poza nim. To jeden z najlepszych prostych przykładów pokazujących, dlaczego user namespaces są tak cenne.

W kontenerach możesz porównać widoczne mapowanie za pomocą:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Dokładny wynik zależy od tego, czy engine używa user namespace remapping, czy bardziej tradycyjnej konfiguracji rootful.

Mapowanie można również odczytać po stronie hosta za pomocą:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Użycie w środowiskach uruchomieniowych

Rootless Podman jest jednym z najwyraźniejszych przykładów traktowania user namespaces jako podstawowego mechanizmu bezpieczeństwa. Rootless Docker również od nich zależy. Obsługa `userns-remap` w Dockerze zwiększa bezpieczeństwo także w przypadku wdrożeń z rootful daemon, chociaż historycznie wiele wdrożeń pozostawiało ją wyłączoną ze względów kompatybilności. Obsługa user namespaces w Kubernetes uległa poprawie, ale adopcja i ustawienia domyślne różnią się w zależności od runtime, dystrybucji i polityki klastra. Systemy Incus/LXC również w dużym stopniu opierają się na przesuwaniu UID/GID oraz koncepcjach idmapping.

Ogólny trend jest jasny: środowiska, które poważnie wykorzystują user namespaces, zazwyczaj lepiej odpowiadają na pytanie „co faktycznie oznacza root w kontenerze?” niż środowiska, które tego nie robią.

## Zaawansowane szczegóły mapowania

Gdy nieuprzywilejowany proces zapisuje dane do `uid_map` lub `gid_map`, kernel stosuje bardziej rygorystyczne reguły niż w przypadku uprzywilejowanego procesu zapisującego z nadrzędnego namespace. Dozwolone są tylko ograniczone mapowania, a w przypadku `gid_map` zapisujący zwykle musi najpierw wyłączyć `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Ten szczegół ma znaczenie, ponieważ wyjaśnia, dlaczego konfiguracja user namespace czasami kończy się niepowodzeniem w eksperymentach rootless oraz dlaczego runtime'y wymagają starannej logiki pomocniczej w zakresie delegowania UID/GID.

Kolejną zaawansowaną funkcją jest **ID-mapped mount**. Zamiast zmieniać ownership na dysku, ID-mapped mount stosuje mapowanie user namespace do mounta, dzięki czemu ownership jest prezentowany jako przetłumaczony w ramach tego widoku mounta. Jest to szczególnie istotne w konfiguracjach rootless i nowoczesnych runtime'ach, ponieważ pozwala używać współdzielonych ścieżek hosta bez wykonywania rekurencyjnych operacji `chown`. Z punktu widzenia bezpieczeństwa funkcja ta zmienia sposób, w jaki writable bind mount wydaje się z wnętrza namespace, mimo że nie modyfikuje bazowych metadanych systemu plików.

Na koniec pamiętaj, że gdy proces tworzy nowy user namespace lub do niego wchodzi, otrzymuje pełny zestaw capabilities **wewnątrz tego namespace**. Nie oznacza to, że nagle uzyskał globalne uprawnienia na hoście. Oznacza to, że capabilities te mogą być używane wyłącznie tam, gdzie pozwalają na to model namespace oraz pozostałe zabezpieczenia. Z tego powodu `unshare -U` może nagle umożliwić mountowanie lub wykonywanie uprzywilejowanych operacji lokalnych dla namespace, nie powodując bezpośrednio zniknięcia granicy host root.

## Błędne konfiguracje

Główną słabością jest po prostu nieużywanie user namespaces w środowiskach, w których byłoby to możliwe. Jeśli container root jest mapowany zbyt bezpośrednio na host root, writable host mounts oraz uprzywilejowane operacje kernela stają się znacznie bardziej niebezpieczne. Innym problemem jest wymuszanie współdzielenia user namespace hosta lub wyłączanie remappingu ze względów zgodności bez rozpoznania, jak bardzo zmienia to granicę zaufania.

User namespaces również należy analizować razem z pozostałymi elementami modelu. Nawet gdy są aktywne, szeroka ekspozycja runtime API lub bardzo słaba konfiguracja runtime'u nadal może umożliwić privilege escalation innymi ścieżkami. Jednak bez nich wiele starszych klas breakoutów staje się znacznie łatwiejszych do wykorzystania.

## Nadużycie

Jeśli container działa jako root bez separacji user namespace, writable host bind mount staje się znacznie bardziej niebezpieczny, ponieważ proces może faktycznie zapisywać jako host root. Niebezpieczne capabilities również nabierają większego znaczenia. Attacker nie musi już tak intensywnie pokonywać granicy translacji, ponieważ ta granica praktycznie nie istnieje.

Obecność lub brak user namespace należy sprawdzić na wczesnym etapie analizy ścieżki container breakout. Nie daje to odpowiedzi na wszystkie pytania, ale od razu pokazuje, czy „root w containerze” ma bezpośrednie znaczenie dla hosta.

Najbardziej praktyczny wzorzec nadużycia polega na potwierdzeniu mapowania, a następnie natychmiastowym sprawdzeniu, czy zawartość zamontowana z hosta jest writable przy użyciu uprawnień istotnych z perspektywy hosta:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Jeśli plik zostanie utworzony jako rzeczywisty root hosta, izolacja user namespace jest dla tej ścieżki praktycznie nieobecna. W tym momencie klasyczne nadużycia plików hosta stają się realne:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Bezpieczniejszym potwierdzeniem podczas aktywnego assessmentu jest zapisanie nieszkodliwego znacznika zamiast modyfikowania krytycznych plików:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Te kontrole mają znaczenie, ponieważ szybko odpowiadają na rzeczywiste pytanie: czy root w tym containerze jest mapowany wystarczająco podobnie do host root, aby zapisywalny host mount natychmiast stał się ścieżką do kompromitacji hosta?

### Pełny przykład: odzyskiwanie capabilities lokalnych dla namespace

Jeśli seccomp zezwala na `unshare`, a środowisko pozwala na utworzenie nowego user namespace, proces może odzyskać pełny zestaw capabilities wewnątrz tego nowego namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
To samo w sobie nie jest ucieczką z hosta. Ma to znaczenie, ponieważ user namespaces mogą ponownie umożliwić uprzywilejowane działania lokalne dla namespace, które później łączą się ze słabymi mountami, podatnymi jądrami lub niewłaściwie zabezpieczonymi powierzchniami runtime.

## Sprawdzenia

Te polecenia mają odpowiedzieć na najważniejsze pytanie na tej stronie: na jakie konto na hoście mapuje się root wewnątrz tego kontenera?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Co jest tutaj interesujące:

- Jeśli proces ma UID 0, a mapowania pokazują bezpośrednie lub bardzo bliskie mapowanie do roota hosta, kontener jest znacznie bardziej niebezpieczny.
- Jeśli root jest mapowany na nieuprzywilejowany zakres hosta, jest to znacznie bezpieczniejsza konfiguracja bazowa i zwykle wskazuje na rzeczywistą izolację user namespace.
- Pliki mapowań są bardziej wartościowe niż samo `id`, ponieważ `id` pokazuje tylko tożsamość lokalną dla namespace.

Jeśli workload działa jako UID 0, a mapowanie wskazuje, że odpowiada to w przybliżeniu rootowi hosta, należy znacznie bardziej rygorystycznie interpretować pozostałe uprawnienia kontenera.

{{#include ../../../../../banners/hacktricks-training.md}}
