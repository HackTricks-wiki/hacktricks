# Nadużywanie modułów jądra i modprobe

{{#include ../../banners/hacktricks-training.md}}

## Błędne konfiguracje modułów jądra i ładowania modułów

Obsługa modułów jądra to obszar o dużym znaczeniu podczas przeglądu możliwości eskalacji uprawnień w systemie Linux. Nie traktuj każdego komunikatu o niepodpisanym module jako luki możliwej do wykorzystania, lecz użyj go do uzyskania odpowiedzi na praktyczne pytania.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Czy bieżący użytkownik może ładować moduły za pośrednictwem `sudo`, capabilities lub zapisywalnej ścieżki pomocniczej?
- Czy ładowanie modułów jest nadal włączone?
- Czy wymuszanie podpisów modułów jest wyłączone?
- Czy katalogi modułów lub pliki modułów są zapisywalne?
- Czy można odczytać logi jądra, aby potwierdzić, co się wydarzyło?

Szybka analiza rozpoczyna się od poniższych kontroli statusu modułów, podpisów, logowania i drzewa modułów.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Interpretacja:

- `modules_disabled=1` oznacza, że modułów nie można ani ładować, ani wyładowywać, a wartość nie może zostać zresetowana do `0` przed ponownym uruchomieniem systemu.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` w wierszu poleceń kernela lub `CONFIG_MODULE_SIG_FORCE=y` wymaga poprawnie podpisanych modułów; w przeciwnym razie niepodpisane moduły mogą zostać załadowane i oznaczyć kernel jako naruszony.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` nie nakłada żadnych ograniczeń na `dmesg`; gdy ma wartość `1`, dostęp wymaga `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Ścieżki z możliwością zapisu w `/lib/modules/$(uname -r)/` są niebezpieczne, ponieważ podczas ładowania modułów `modprobe` przeszukuje to drzewo oraz dane dotyczące ich zależności.<sup>[[8]](#references)</sup>

### Ładowanie modułu i odczytywanie danych wyjściowych kernela

Jeśli masz uzasadnione uprawnienia do załadowania lokalnego modułu, `insmod` wstawia dokładny plik `.ko`, który podasz. Funkcja init modułu jest uruchamiana jako część procesu ładowania, a komunikaty zapisywane za pomocą `printk()` trafiają do bufora logów kernela, który zwykle odczytuje się za pomocą `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Minimalny workflow weryfikacyjny używa `modinfo` do sprawdzania metadanych, `insmod` i `rmmod` do ładowania oraz usuwania modułu, `lsmod` do potwierdzania stanu załadowania, a `dmesg` do sprawdzania logów kernela.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Jeśli `sudo -l` zezwala na użycie `insmod`, `modprobe` lub wrappera wokół nich, należy uznać to za krytyczne: `sudo -l` wyświetla uprawnienia wywołującego użytkownika, a załadowanie kernel module wymaga `CAP_SYS_MODULE`.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` dozwolone przez sudo

Reguła sudo, która pozwala użytkownikowi uruchamiać `insmod`, nie jest porównywalna z zezwoleniem na użycie zwykłego helpera administracyjnego. Kod inicjalizacyjny modułu jest wykonywany w ramach jego wstawiania, więc praktyczne pytanie podczas przeglądu brzmi: czy ten użytkownik może wybrać lub zmodyfikować ładowany moduł?<sup>[[3]](#references)</sup>

Poniższy ogólny przebieg przeglądu powtarza kontrole inspekcji, ładowania, stanu, logów i usuwania dla kandydującego modułu.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Jeśli użytkownik może dostarczyć dowolny plik `.ko`, w autoryzowanym assessment należy traktować tę regułę jako pełne przejęcie systemu. Bezpieczniejszym wzorcem operacyjnym jest unikanie delegowania ładowania modułów za pośrednictwem sudo; jeśli jest to nieuniknione, należy ograniczyć dokładną ścieżkę, właściciela, uprawnienia, signing policy oraz procedurę usuwania.<sup>[[3]](#references)[[10]](#references)</sup>

Poniżej przedstawiono minimalny source i Makefile jako nieszkodliwy wzorzec budowania modułu w kontrolowanym labie; forma `make -C /lib/modules/$(uname -r)/build M=$PWD` jest zgodna z udokumentowanym przez kernel workflow kbuild dla external modules.<sup>[[5]](#references)[[7]](#references)</sup>
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
Buduj i ładuj wyłącznie w autoryzowanym laboratorium; kbuild buduje zewnętrzny moduł, a polecenia load/remove wywołują interfejsy modułów jądra.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Kontrole nadużycia `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` określa pomocniczy program userspace uruchamiany przez kernel na żądanie automatycznego ładowania modułu; ten sysctl wpływa na automatyczne ładowanie, a nie na jawne wstawianie modułów. Jeśli attacker może zmienić tę wartość na ścieżkę do zapisywalnego pliku wykonywalnego i wywołać żądanie modułu, ten helper staje się uprzywilejowaną ścieżką wykonywania kodu.<sup>[[1]](#references)</sup>

Sprawdź bieżącą ścieżkę helpera za pośrednictwem interfejsu sysctl kernela i sprawdź właściciela oraz tryb uprawnień wskazanego pliku.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Sprawdź, czy można wpływać na ustawienia sysctl, delegowane reguły sudo lub capabilities plików.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Poniższy wzorzec, przeznaczony wyłącznie do laboratorium, zmienia ścieżkę helpera i wywołuje udokumentowane żądanie automatycznego ładowania modułu; używaj go tylko w odizolowanym, autoryzowanym systemie.<sup>[[1]](#references)</sup>

W obecnych jądrach Linux nie używaj nieznanego pliku wykonywalnego jako ogólnego wyzwalacza: starszy mechanizm automatycznego ładowania modułów dla niestandardowych formatów binarnych został usunięty w Linux 6.14, natomiast dokumentacja jądra wskazuje nieznany typ systemu plików jako ścieżkę żądania automatycznego ładowania modułu.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
W systemach z zaostrzonymi zabezpieczeniami powinno to zakończyć się niepowodzeniem, gdy uprawnienia uniemożliwiają użytkownikom bez podwyższonych uprawnień zapis do `kernel.modprobe`, ścieżka pomocnicza nie jest zapisywalna lub automatyczne ładowanie modułów jest wyłączone.<sup>[[1]](#references)</sup>

### Przegląd zapisywalnego `/lib/modules`

Zapisywalne katalogi modułów mogą umożliwiać podmianę modułów, umieszczanie złośliwych modułów lub nadużywanie automatycznego ładowania, zależnie od tego, jak później wywoływany jest `modprobe`; `modprobe` przeszukuje `/lib/modules/$(uname -r)` i podczas rozwiązywania modułów korzysta z danych o ich zależnościach.<sup>[[8]](#references)</sup>

Sprawdź zapisywalne pliki modułów oraz metadane zależności/aliasów w drzewie modułów aktywnej wersji kernela.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Jeśli znajdziesz zapisywalną zawartość modułu, sprawdź, jak `modprobe` rozwiązuje zależności i jak `modinfo` raportuje metadane modułu.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Uwagi dotyczące ochrony:

- Utrzymuj `/lib/modules` jako własność `root:root` i bez możliwości zapisu przez użytkowników.<sup>[[8]](#references)</sup>
- Ustaw `kernel.modules_disabled=1` po uruchomieniu systemu, jeśli jest to możliwe z operacyjnego punktu widzenia.<sup>[[1]](#references)</sup>
- Wymuszaj podpisywanie modułów w systemach wymagających modułów ładowanych dynamicznie.<sup>[[2]](#references)</sup>
- Monitoruj zapisy do `/proc/sys/kernel/modprobe`, `/lib/modules` oraz nieoczekiwane uruchomienia `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)</sup>

## References

- [1] [Dokumentacja dla /proc/sys/kernel/ — dokumentacja jądra Linux](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
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
{{#include ../../banners/hacktricks-training.md}}
