# Użytkownicy, sesje i artefakty poświadczeń

{{#include ../../banners/hacktricks-training.md}}

Zacznij od ustalenia tożsamości właściciela bieżącej powłoki, a następnie wylistuj pozostałych użytkowników, grupy, aktywne sesje i magazyny poświadczeń. Strona [rzeczywistego, efektywnego i zapisanego identyfikatora użytkownika](euid-ruid-suid.md) wyjaśnia, dlaczego efektywne uprawnienia procesu mogą różnić się od uprawnień konta, na które się zalogowano.

## Wylistuj tożsamości i dostęp oparty na grupach

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` uwzględnia konta z katalogów, które mogą nie być widoczne przy zwykłym odczycie `/etc/passwd`. Sprawdź konta z UID 0, powłoki logowania, katalogi domowe, grupy uzupełniające oraz konta, których konfiguracja nieoczekiwanie pozwala na logowanie interaktywne. Strona [interesujące grupy](interesting-groups-linux-pe/README.md) opisuje delegowany dostęp, taki jak `sudo`, `docker`, `disk` i `shadow`. Zanim uznasz nazwę grupy za uprawnienie, sprawdź rzeczywiste listy ACL systemu plików i lokalne zasady.

Jeśli [NSS kieruje zapytania o `passwd`, `group` lub `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) do bazy danych, przed oceną tożsamości opartych na bazie sprawdź aktywnego dostawcę i ścieżkę jego konfiguracji. W przypadku wdrożeń PostgreSQL NSS pliki `/etc/nss-pgsql.conf` i `/etc/nss-pgsql-root.conf` są jedynie wskazówkami dotyczącymi ścieżek, ponieważ ustawienia połączenia mogą zawierać dane uwierzytelniające. Rola bazy danych ma znaczenie tylko wtedy, gdy może zmieniać rekordy faktycznie zwracane przez aktywnego dostawcę NSS, a konto może się przy ich użyciu uwierzytelnić. Główny GID równy 0 oznacza przynależność do grupy root, a nie UID 0; mapowanie na grupę sudo wymaga efektywnej [reguły grupowej sudoers](https://man7.org/linux/man-pages/man5/sudoers.5.html) oraz ewentualnego wymaganego uwierzytelnienia. Mapowanie na UID 0 stanowi odrębną granicę tożsamości. Podczas pasywnej enumeracji nie wyświetlaj ciągów połączenia ani nie zmieniaj rekordów kont.

Porównaj także numeryczne UID różnych nazw kont lokalnych. Dwie nazwy w pliku [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) mogą wskazywać tę samą tożsamość plikową Unix, choć ich rekordy uwierzytelniania przy logowaniu mogą się różnić. Nowo dodany alias ze współdzielonym, niezerowym UID może więc po pomyślnym uwierzytelnieniu dać dostęp do plików lub procesów innego użytkownika; nie zapewnia uprawnień roota, chyba że ten UID albo odrębna ścieżka uprawnień je zapewnia. Współdzielone UID mogą być używane celowo. Zweryfikuj źródło konta (`/etc/passwd` lub NSS), historię jego utworzenia, powłokę i katalog domowy, faktyczne zasady uwierzytelniania oraz to, czy konta mają uprawnienia do współdzielenia tożsamości. Kontrola duplikatów ograniczona do kont lokalnych nie wyklucza aliasu opartego na katalogu.

## Znajdź aktywne i niedawne sesje

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Socket `screen` lub `tmux` może udostępniać istniejącą powłokę, jeśli jego uprawnienia pozwalają bieżącemu użytkownikowi się do niej dołączyć. Przed próbą dostępu sprawdź właściciela i tryb socketu; sesja innego użytkownika nie jest automatycznie dostępna. Znaczenie może mieć również aktywny znacznik czasu sudo lub socket agenta SSH, ale możliwość ich ponownego użycia zależy od tożsamości użytkownika, uprawnień i zasad. Informacje o nadużyciach związanych z przekazywaniem agenta znajdziesz w artykule [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

[Socket kontrolny multipleksowania OpenSSH](https://man.openbsd.org/ssh_config#ControlMaster) jest czymś innym niż `SSH_AUTH_SOCK`: `ControlMaster` i `ControlPath` pozwalają kolejnym klientom SSH współdzielić istniejące, uwierzytelnione połączenie, a `ControlPersist` może utrzymać dostępność procesu master po zakończeniu pierwszej sesji. Sprawdź plik `.ssh/config` bieżącego użytkownika oraz płytko zagnieżdżone ścieżki socketów `.ssh`, uwzględniając właściciela i uprawnienia. Sama nazwa pliku socketu nie dowodzi, że proces master działa, że bieżący użytkownik może się połączyć ani z jakiego konta zdalnego korzysta.

## Przegląd artefaktów użytkownika

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Historia powłoki, pliki startowe, klucze SSH, konfiguracja aplikacji, pęki kluczy GPG i pamięci podręczne Kerberos mogą ujawnić dane uwierzytelniające lub miejsca zapisu umożliwiające utrwalenie dostępu. Warto sprawdzić zapisywalny plik `authorized_keys` lub plik startowy powłoki należący do konta o wyższych uprawnieniach. [Strona post-exploitation](../post-exploitation/README.md) omawia przenoszenie katalogu domowego GPG i wyszukiwanie danych uwierzytelniających; [Linux Active Directory](linux-active-directory.md) omawia ponowne użycie pamięci podręcznej Kerberos i plików keytab. [Strona PAM](../software-information/pam-pluggable-authentication-modules.md) wyjaśnia zagrożenia związane z polityką uwierzytelniania.
{{#include ../../banners/hacktricks-training.md}}
