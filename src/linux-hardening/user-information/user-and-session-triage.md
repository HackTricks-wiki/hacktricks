# Użytkownicy, sesje i artefakty poświadczeń

{{#include ../../banners/hacktricks-training.md}}

Zacznij od ustalenia tożsamości, do której należy bieżąca powłoka, a następnie wylicz innych użytkowników, grupy, aktywne sesje i magazyny poświadczeń. Strona [rzeczywiste, efektywne i zapisane identyfikatory użytkownika](euid-ruid-suid.md) wyjaśnia, dlaczego efektywne uprawnienia procesu mogą różnić się od uprawnień jego konta logowania.

## Wyliczanie tożsamości i dostępu opartego na grupach

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` uwzględnia konta pochodzące z katalogu, które mogą być pominięte przy zwykłym odczycie `/etc/passwd`. Sprawdź konta z UID 0, powłoki logowania, katalogi domowe, grupy dodatkowe oraz konta, których konfiguracja nieoczekiwanie umożliwia logowanie interaktywne. Strona [interesting groups](interesting-groups-linux-pe/README.md) omawia delegowany dostęp, np. przez `sudo`, `docker`, `disk` i `shadow`. Zanim uznasz nazwę grupy za uprawnienie, sprawdź rzeczywiste ACL systemu plików i lokalną politykę.

Jeśli [NSS kieruje zapytania o `passwd`, `group` lub `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) do bazy danych, przed oceną tożsamości opartych na bazie sprawdź aktywnego dostawcę i ścieżkę jego konfiguracji. W przypadku wdrożeń PostgreSQL NSS pliki `/etc/nss-pgsql.conf` i `/etc/nss-pgsql-root.conf` są jedynie wskazówkami dotyczącymi ścieżek, ponieważ ustawienia połączenia mogą zawierać dane uwierzytelniające. Rola bazy danych ma znaczenie tylko wtedy, gdy może zmieniać rekordy faktycznie zwracane przez aktywnego dostawcę NSS, a konto może się przy ich użyciu uwierzytelnić. GID 0 jako podstawowy oznacza przynależność do grupy root, a nie UID 0; mapowanie na grupę sudo wymaga skutecznej [reguły grupowej sudoers](https://man7.org/linux/man-pages/man5/sudoers.5.html) i ewentualnego wymaganego uwierzytelnienia. Mapowanie UID 0 wyznacza inną granicę tożsamości. Podczas pasywnej enumeracji nie wyświetlaj ciągów połączeń ani nie zmieniaj rekordów kont.

Porównaj również numeryczne UID różnych nazw kont lokalnych. Dwie nazwy w pliku [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) mogą wskazywać tę samą tożsamość plikową Unix, mimo że ich rekordy uwierzytelniania przy logowaniu są różne. Nowo dodany alias ze współdzielonym, niezerowym UID może więc po pomyślnym uwierzytelnieniu uzyskać dostęp do plików lub procesów innego użytkownika; nie daje to uprawnień root, chyba że ten UID lub odrębna ścieżka uprawnień je zapewnia. Współdzielone UID mogą być zamierzone. Zweryfikuj źródło konta (`/etc/passwd` czy NSS), historię utworzenia, powłokę i katalog domowy, faktyczną politykę uwierzytelniania oraz to, czy konta mają uprawnienia do współdzielenia tożsamości. Sprawdzenie duplikatów wyłącznie lokalnie nie wyklucza aliasu z katalogu.

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

A `screen` lub `tmux` socket może udostępniać istniejący shell, jeśli jego uprawnienia pozwalają bieżącemu użytkownikowi się do niego dołączyć. Przed próbą dostępu sprawdź właściciela i tryb socketu; sesja innego użytkownika nie jest automatycznie dostępna. Aktywny znacznik czasu sudo lub socket SSH agent może również mieć znaczenie, ale możliwość ich ponownego użycia zależy od tożsamości użytkownika, uprawnień i zasad. Więcej informacji o nadużywaniu agent forwarding znajdziesz w sekcji [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster) różni się od `SSH_AUTH_SOCK`: `ControlMaster` i `ControlPath` pozwalają kolejnym klientom SSH współdzielić istniejące uwierzytelnione połączenie, a `ControlPersist` może utrzymać dostępność mastera po zakończeniu pierwszej sesji. Sprawdź `.ssh/config` bieżącego użytkownika oraz płytko zagnieżdżone ścieżki socketów `.ssh`, w tym ich właściciela i uprawnienia. Sama nazwa pliku socketu nie dowodzi, że master jest aktywny, że bieżący użytkownik może się z nim połączyć ani z którego zdalnego konta korzysta.

## Przegląd artefaktów użytkownika

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Historia powłoki, pliki startowe, klucze SSH, konfiguracja aplikacji, keyringi GPG i cache Kerberos mogą ujawnić dane uwierzytelniające lub miejsca umożliwiające utrwalenie dostępu. Warto sprawdzić, czy `authorized_keys` lub plik startowy powłoki konta o wyższych uprawnieniach są zapisywalne. [Strona post-exploitation](../post-exploitation/README.md) omawia przenoszenie katalogu domowego GPG i wyszukiwanie danych uwierzytelniających; [Linux Active Directory](linux-active-directory.md) omawia ponowne wykorzystanie cache Kerberos i keytabów. [Strona PAM](../software-information/pam-pluggable-authentication-modules.md) wyjaśnia zagrożenia związane z polityką uwierzytelniania.
{{#include ../../banners/hacktricks-training.md}}
