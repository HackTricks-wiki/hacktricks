# Nadużywanie modułów jądra i modprobe

{{#include ../../banners/hacktricks-training.md}}

## Błędne konfiguracje modułów jądra i ładowania modułów

Obsługa modułów jądra to obszar o dużym znaczeniu podczas przeglądu pod kątem privilege escalation w systemie Linux. Nie traktuj każdego komunikatu o niepodpisanym module jako dowodu podatności, ale wykorzystaj go do uzyskania odpowiedzi na praktyczne pytania:

- Czy bieżący użytkownik może ładować moduły za pośrednictwem `sudo`, capabilities lub zapisywalnej ścieżki helpera?
- Czy ładowanie modułów jest nadal włączone?
- Czy wymuszanie podpisów modułów jest wyłączone?
- Czy katalogi modułów lub pliki modułów są zapisywalne?
- Czy można odczytywać logi jądra, aby potwierdzić, co się wydarzyło?

Szybki triage:
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
cat /proc/sys/kernel/module_sig_enforce 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Interpretacja:

- `modules_disabled=1` oznacza, że nie można ładować nowych modułów do czasu ponownego uruchomienia systemu.
- `module_sig_enforce=1` zwykle blokuje niepodpisane moduły.
- `dmesg_restrict=0` pozwala nieuprzywilejowanym użytkownikom odczytywać logi kernela w wielu systemach.
- Zapisywalne ścieżki w `/lib/modules/$(uname -r)/` są niebezpieczne, ponieważ mechanizmy wykrywania i automatycznego ładowania modułów mogą ufać temu drzewu.

### Ładowanie modułu i odczytywanie danych wyjściowych kernela

Jeśli masz uzasadnione uprawnienia do załadowania lokalnego modułu, `insmod` wstawia dokładnie podany przez Ciebie plik `.ko`. Funkcja init modułu uruchamia się natychmiast, a komunikaty zapisane za pomocą `printk()` pojawiają się w logach kernela.

Minimalny workflow do przeglądu lub w środowiskach laboratoryjnych:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Jeśli `sudo -l` zezwala na `insmod`, `modprobe` lub wrapper opakowujący te polecenia, potraktuj to jako krytyczne:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` dozwolone przez Sudo

Reguła sudo zezwalająca użytkownikowi na uruchamianie `insmod` nie jest porównywalna ze zezwoleniem na używanie zwykłego pomocniczego narzędzia administracyjnego. Kod inicjalizacyjny modułu jest wykonywany w kontekście kernela natychmiast po wstawieniu pliku `.ko`, dlatego praktyczne pytanie podczas przeglądu brzmi: „czy ten użytkownik może wybrać lub zmodyfikować ładowany moduł?”

Ogólny przebieg przeglądu:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Jeśli użytkownik może dostarczyć dowolny plik `.ko`, w autoryzowanej ocenie regułę należy traktować jako pełne przejęcie systemu. Bezpieczniejszym wzorcem operacyjnym jest unikanie delegowania ładowania modułów za pośrednictwem sudo; jeśli jest to nieuniknione, należy ograniczyć dokładną ścieżkę, właściciela, uprawnienia, zasady podpisywania oraz procedurę usuwania.

W przypadku nieszkodliwego wzorca budowania modułu w kontrolowanym laboratorium minimalny kod źródłowy i Makefile wyglądają następująco:
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
Buduj i ładuj wyłącznie w autoryzowanym laboratorium:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Kontrole nadużycia `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` określa helper userspace, którego kernel używa, gdy potrzebuje pomocy przy ładowaniu modułów. Jeśli attacker może zmienić go na ścieżkę do zapisywalnego pliku wykonywalnego i wywołać nieznany format binarny lub inną ścieżkę żądania modułu, może to doprowadzić do wykonania kodu jako root.

Sprawdź bieżący helper:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Sprawdź, czy możesz na to wpłynąć:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Ogólny wzorzec przeznaczony wyłącznie do laboratorium:
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger an unknown executable format so the kernel attempts helper logic
printf '\\xff\\xff\\xff\\xff' > /tmp/unknown
chmod +x /tmp/unknown
/tmp/unknown 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
W zahartowanych systemach powinno to zakończyć się niepowodzeniem, ponieważ nieuprzywilejowani użytkownicy nie mogą zapisywać do `kernel.modprobe`, ścieżka pomocnika nie jest zapisywalna lub ścieżki ładowania modułów są zablokowane.

### Przegląd zapisywalnych katalogów `/lib/modules`

Zapisywalne katalogi modułów mogą umożliwiać podmianę modułów, umieszczanie złośliwych modułów lub nadużywanie automatycznego ładowania, w zależności od tego, jak później wywoływane jest `modprobe`.

Sprawdź lokalizacje z możliwością zapisu:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Jeśli znajdziesz zapisywalną zawartość modułu, sprawdź, jak wykrywane są moduły:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Uwagi dotyczące obrony:

- Utrzymuj właściciela `/lib/modules` jako `root:root` i uniemożliwiaj użytkownikom zapis.
- Ustaw `kernel.modules_disabled=1` po uruchomieniu systemu, jeśli jest to możliwe operacyjnie.
- Wymuś podpisywanie modułów w systemach wymagających ładowalnych modułów.
- Monitoruj zapisy do `/proc/sys/kernel/modprobe`, `/lib/modules` oraz nieoczekiwane uruchomienia `insmod`/`modprobe`.
{{#include ../../banners/hacktricks-training.md}}
