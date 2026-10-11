# Użytkownicy, sesje i artefakty poświadczeń

{{#include ../../banners/hacktricks-training.md}}

Zacznij od tożsamości użytkownika, do którego należy bieżący shell, a następnie wylicz pozostałych użytkowników, grupy, aktywne sesje i magazyny poświadczeń. Strona [real, effective, and saved user ID](euid-ruid-suid.md) wyjaśnia, dlaczego efektywne uprawnienia procesu mogą różnić się od uprawnień jego konta logowania.

## Wyliczanie tożsamości i dostępu opartego na grupach

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` uwzględnia konta obsługiwane przez katalog, które mogą nie być widoczne przy zwykłym odczycie `/etc/passwd`. Sprawdź konta z UID 0, powłoki logowania, katalogi domowe, grupy dodatkowe oraz konta, których konfiguracja nieoczekiwanie pozwala na interaktywne logowanie. Strona [interesting groups](interesting-groups-linux-pe/README.md) omawia delegowany dostęp, taki jak `sudo`, `docker`, `disk` i `shadow`. Zanim uznasz nazwę grupy za oznakę uprawnień, sprawdź rzeczywiste listy ACL systemu plików i lokalną politykę.

Jeśli [NSS kieruje zapytania o `passwd`, `group` lub `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) do bazy danych, przed oceną tożsamości obsługiwanych przez bazę sprawdź aktywnego dostawcę i ścieżkę jego konfiguracji. W przypadku wdrożeń PostgreSQL NSS ścieżki `/etc/nss-pgsql.conf` i `/etc/nss-pgsql-root.conf` są jedynie wskazówkami, ponieważ ustawienia połączenia mogą zawierać dane uwierzytelniające. Rola bazy danych ma znaczenie tylko wtedy, gdy może zmieniać rekordy faktycznie zwracane przez aktywnego dostawcę NSS, a konto może się przy ich użyciu uwierzytelnić. Podstawowy GID równy 0 oznacza przynależność do grupy root, a nie UID 0; mapowanie na grupę sudo wymaga skutecznej [reguły grupowej sudoers](https://man7.org/linux/man-pages/man5/sudoers.5.html) oraz wszelkiego wymaganego uwierzytelnienia. Mapowanie na UID 0 stanowi odrębną granicę tożsamości. Podczas pasywnej enumeracji nie wyświetlaj ciągów połączeń ani nie zmieniaj rekordów kont.

Porównaj również numeryczne UID lokalnych nazw kont. Dwie nazwy w pliku [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) mogą wskazywać tę samą tożsamość systemu Unix, choć przypisane im rekordy uwierzytelniania logowania mogą się różnić. Nowo dodany alias ze współdzielonym niezerowym UID może więc po pomyślnym uwierzytelnieniu uzyskać dostęp do plików lub procesów innego użytkownika; nie zapewnia uprawnień roota, chyba że ten UID lub odrębna ścieżka eskalacji uprawnień je zapewnia. Współdzielone UID mogą być zamierzone. Zweryfikuj źródło konta (`/etc/passwd` czy NSS), historię utworzenia, powłokę i katalog domowy, faktyczną politykę uwierzytelniania oraz to, czy konta są uprawnione do współdzielenia tożsamości. Sprawdzenie obejmujące wyłącznie konta lokalne nie wyklucza aliasu obsługiwanego przez katalog.

## Znajdź aktywne i ostatnie sesje

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Gniazdo `screen` lub `tmux` może udostępniać istniejącą powłokę, jeśli jego uprawnienia pozwalają bieżącemu użytkownikowi się do niej podłączyć. Przed próbą dostępu sprawdź właściciela i tryb gniazda; nie można automatycznie podłączyć się do sesji innego użytkownika. Znaczenie może mieć również aktywny znacznik czasu sudo lub gniazdo agenta SSH, ale możliwość ich ponownego użycia zależy od tożsamości użytkownika, uprawnień i zasad. Informacje o nadużywaniu przekazywania agenta znajdziesz w artykule [Wykorzystywanie przekazywania agenta SSH](ssh-forward-agent-exploitation.md).

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster) jest odrębny od `SSH_AUTH_SOCK`: `ControlMaster` i `ControlPath` umożliwiają kolejnym klientom SSH współdzielenie istniejącego, uwierzytelnionego połączenia, a `ControlPersist` może utrzymywać dostępność połączenia nadrzędnego po zakończeniu pierwszej sesji. Sprawdź plik `.ssh/config` bieżącego użytkownika oraz gniazda w katalogu `.ssh` i jego bezpośrednich podkatalogach, w tym ich właściciela i uprawnienia. Sama nazwa pliku gniazda nie dowodzi, że połączenie nadrzędne jest aktywne, że bieżący użytkownik może się z nim połączyć ani z jakiego konta zdalnego korzysta.

## Przegląd artefaktów użytkownika

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Historia powłoki, pliki startowe, klucze SSH, konfiguracja aplikacji, magazyny kluczy GPG i pamięci podręczne Kerberos mogą ujawniać dane uwierzytelniające lub miejsca umożliwiające utrwalenie dostępu. Warto sprawdzić, czy plik `authorized_keys` lub plik startowy powłoki konta o wyższych uprawnieniach jest zapisywalny. Strona [post-exploitation](../post-exploitation/README.md) omawia zmianę lokalizacji katalogu domowego GPG i wyszukiwanie danych uwierzytelniających; strona [Linux Active Directory](linux-active-directory.md) omawia ponowne wykorzystanie pamięci podręcznej Kerberos i plików keytab. Strona [PAM](../software-information/pam-pluggable-authentication-modules.md) wyjaśnia zagrożenia związane z polityką uwierzytelniania.
{{#include ../../banners/hacktricks-training.md}}
