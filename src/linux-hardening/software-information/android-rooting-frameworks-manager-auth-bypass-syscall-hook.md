# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks takie jak KernelSU, APatch, SKRoot i Magisk często modyfikują kernel Linux/Android i udostępniają uprzywilejowane funkcje nieuprzywilejowanej aplikacji userspace „manager” za pośrednictwem hookowanego syscalla. Jeśli etap uwierzytelniania managera jest wadliwy, dowolna lokalna aplikacja może uzyskać dostęp do tego kanału i eskalować uprawnienia na urządzeniach, które mają już root.

Ta strona abstrahuje techniki i problemy ujawnione w publicznych badaniach (w szczególności analizie KernelSU v0.5.7 przeprowadzonej przez Zimperium), aby pomóc zespołom red i blue zrozumieć attack surfaces, exploitation primitives oraz skuteczne mitigations.<sup>[[1]](#references)</sup>

---
## Wzorzec architektury: kanał managera oparty na syscall hook

- Moduł/patch kernela hookuje syscall (zwykle prctl), aby odbierać „commands” z userspace.
- Protokół zazwyczaj ma postać: magic_value, command_id, arg_ptr/len ...
- Aplikacja userspace manager najpierw przeprowadza authentication (np. CMD_BECOME_MANAGER). Gdy kernel oznaczy caller jako zaufanego managera, akceptowane są uprzywilejowane commands:
- Przyznanie root callerowi (np. CMD_GRANT_ROOT)
- Zarządzanie allowlists/deny-lists dla su
- Modyfikowanie polityki SELinux (np. CMD_SET_SEPOLICY)
- Sprawdzanie wersji/konfiguracji
- Ponieważ dowolna aplikacja może wywoływać syscalls, poprawność manager authentication ma kluczowe znaczenie.

Przykład (design KernelSU):
- Hooked syscall: prctl
- Magic value przekierowująca do handlera KernelSU: 0xDEADBEEF
- Commands obejmują: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT itd.

---
## Flow authentication KernelSU v0.5.7 (w zaimplementowanej postaci)

Gdy userspace wywołuje prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU weryfikuje:

1) Sprawdzenie prefiksu ścieżki
- Podana ścieżka musi zaczynać się od oczekiwanego prefiksu dla UID callera, np. /data/data/<pkg> lub /data/user/<id>/<pkg>.
- Reference: logika sprawdzania prefiksu ścieżki w core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Sprawdzenie ownership
- Właścicielem ścieżki musi być UID callera.
- Reference: logika sprawdzania ownership w core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) Sprawdzenie APK signature przez skanowanie FD table
- Iterowanie po otwartych file descriptors procesu wywołującego.
- Wybór pierwszego pliku, którego ścieżka pasuje do /data/app/*/base.apk.
- Parsowanie APK v2 signature i weryfikacja względem oficjalnego manager certificate.
- References: iterowanie po FDs w manager.c, weryfikacja APK v2 w apk_sign.c.<sup>[[3]](#references)[[4]](#references)</sup>

Jeśli wszystkie checks zakończą się powodzeniem, kernel tymczasowo cache’uje UID managera i akceptuje uprzywilejowane commands od tego UID aż do resetu.

---
## Klasa vulnerability: zaufanie do „pierwszego pasującego APK” podczas iteracji FD

Jeśli signature check jest powiązany z „pierwszym pasującym /data/app/*/base.apk” znalezionym w FD table procesu, w rzeczywistości nie weryfikuje on własnego package callera. Attacker może wcześniej umieścić poprawnie signed APK (prawdziwego managera) tak, aby pojawił się na liście FD wcześniej niż jego własny base.apk.

To trust-by-indirection pozwala nieuprzywilejowanej aplikacji podszyć się pod managera bez posiadania manager signing key.<sup>[[1]](#references)</sup>

Kluczowe właściwości wykorzystywane w exploit:<sup>[[1]](#references)</sup>
- FD scan nie wiąże tożsamości package z callerem; dopasowuje jedynie strings ścieżek za pomocą pattern matchingu.
- open() zwraca najniższy dostępny FD. Zamykając najpierw FDs o niższych numerach, attacker może kontrolować kolejność.
- Filter sprawdza wyłącznie, czy ścieżka pasuje do /data/app/*/base.apk – nie sprawdza, czy odpowiada zainstalowanemu package callerа.

---
## Preconditions attacku

- Urządzenie ma już root za pomocą podatnego rooting framework (np. KernelSU v0.5.7).
- Attacker może lokalnie uruchamiać dowolny nieuprzywilejowany code (proces aplikacji Android).
- Prawdziwy manager nie przeszedł jeszcze authentication (np. bezpośrednio po reboot). Niektóre frameworks cache’ują UID managera po pomyślnym uwierzytelnieniu; trzeba wygrać race.<sup>[[1]](#references)</sup>

---
## Zarys exploitation (KernelSU v0.5.7)

Kroki high-level:<sup>[[1]](#references)[[9]](#references)</sup>
1) Utworzenie poprawnej ścieżki do własnego app data directory w celu spełnienia checks prefiksu i ownership.
2) Zapewnienie, aby genuine KernelSU Manager base.apk był otwarty na FD o niższym numerze niż własny base.apk.
3) Wywołanie prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...), aby przejść checks.
4) Wydanie uprzywilejowanych commands, takich jak CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY, w celu utrzymania elevation.

Praktyczne uwagi dotyczące kroku 2 (FD ordering):<sup>[[1]](#references)</sup>
- Zidentyfikowanie FD procesu dla własnego /data/app/*/base.apk przez przejście po symlinkach /proc/self/fd.
- Zamknięcie niskiego FD (np. stdin, fd 0) i otwarcie najpierw legitimate manager APK, aby zajął fd 0 (lub dowolny indeks niższy niż FD własnego base.apk).
- Dołączenie legitimate manager APK do własnej aplikacji, aby jego ścieżka spełniała naiwny filter kernela. Na przykład umieszczenie go w subpath pasującym do /data/app/*/base.apk.

Przykładowe snippets kodu (Android/Linux, wyłącznie ilustracyjne):

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
Wymuś, aby deskryptor pliku o niższym numerze wskazywał na prawidłowy APK managera:
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
Uwierzytelnianie Managera przez hook prctl:
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
- CMD_GRANT_ROOT: awansuj bieżący proces do root
- CMD_ALLOW_SU: dodaj swój package/UID do allowlist dla trwałego su
- CMD_SET_SEPOLICY: dostosuj politykę SELinux zgodnie z możliwościami frameworka

Wskazówka dotycząca race/persistence:
- Zarejestruj receiver BOOT_COMPLETED w AndroidManifest (RECEIVE_BOOT_COMPLETED), aby uruchamiać się wcześnie po restarcie i próbować uwierzytelnić się przed prawdziwym managerem.<sup>[[1]](#references)</sup>

---
## Wskazówki dotyczące wykrywania i zabezpieczeń

Dla developerów frameworków:
- Powiąż uwierzytelnianie z package/UID wywołującego, a nie z dowolnymi FD:
- Ustal package wywołującego na podstawie jego UID i zweryfikuj go względem sygnatury zainstalowanego package (za pomocą PackageManager), zamiast skanować FD.
- Jeśli rozwiązanie działa wyłącznie w kernelu, użyj stabilnej tożsamości wywołującego (task creds) i przeprowadzaj walidację względem stabilnego źródła prawdy zarządzanego przez init/helper w userspace, a nie przez FD procesów.
- Unikaj sprawdzania prefiksu ścieżki jako tożsamości; wywołujący może je w prosty sposób spełnić.
- Użyj challenge–response opartego na nonce w kanale i wyczyść wszelką cache'owaną tożsamość managera podczas boot lub po kluczowych zdarzeniach.
- Jeśli to możliwe, rozważ uwierzytelnianie IPC oparte na binderze zamiast przeciążania generycznych syscalli.

Dla defenderów/blue team:
- Wykrywaj obecność rooting frameworks i procesów managerów; monitoruj wywołania prctl z podejrzanymi magic constants (np. 0xDEADBEEF), jeśli masz telemetrykę kernela.
- W zarządzanych flotach blokuj lub zgłaszaj boot receivers pochodzące z niezaufanych packages, które szybko próbują wykonywać uprzywilejowane commands managera po boot.
- Upewnij się, że urządzenia są zaktualizowane do poprawionych wersji frameworka; unieważniaj cache'owane ID managera po aktualizacji.

Ograniczenia ataku:
- Dotyczy wyłącznie urządzeń, które już zostały zrootowane za pomocą podatnego frameworka.
- Zwykle wymaga restartu/okna race przed uwierzytelnieniem prawdziwego managera (niektóre frameworki cache'ują UID managera do momentu resetu).

---
## Powiązane informacje dotyczące różnych frameworków

- Uwierzytelnianie oparte na haśle (np. historyczne buildy APatch/SKRoot) może być słabe, jeśli hasła można odgadnąć lub bruteforce'ować albo walidacje zawierają błędy.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Uwierzytelnianie oparte na package/sygnaturze (np. KernelSU) jest z założenia silniejsze, ale musi wiązać się z faktycznym wywołującym, a nie z pośrednimi artefaktami, takimi jak skanowanie FD.<sup>[[1]](#references)[[5]](#references)</sup>
- Magisk: CVE-2024-48336 (MagiskEoP) pokazał, że nawet dojrzałe ekosystemy mogą być podatne na spoofing tożsamości prowadzący do wykonania kodu z rootem w kontekście managera.<sup>[[1]](#references)[[8]](#references)</sup>

---
## Referencje

- [1] [Zimperium – The Rooting of All Evil: Luki bezpieczeństwa, które mogłyby narazić urządzenie mobilne na atak](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – sprawdzanie ścieżek w core_hook.c (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [3] [KernelSU v0.5.7 – iteracja FD i sprawdzanie sygnatury w manager.c (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [4] [KernelSU – weryfikacja APK v2 w apk_sign.c (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [5] [Projekt KernelSU](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [9] [Demo video PoC KSU (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
