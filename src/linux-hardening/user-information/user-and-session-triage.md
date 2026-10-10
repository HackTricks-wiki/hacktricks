# Użytkownicy, sesje i artefakty poświadczeń

{{#include ../../banners/hacktricks-training.md}}

Zacznij od tożsamości, do której należy bieżąca powłoka, a następnie wylicz pozostałych użytkowników, grupy, aktywne sesje i magazyny poświadczeń. Strona [rzeczywisty, efektywny i zapisany identyfikator użytkownika](euid-ruid-suid.md) wyjaśnia, dlaczego efektywne uprawnienia procesu mogą różnić się od uprawnień jego konta logowania.

## Wyliczanie tożsamości i dostępu opartego na grupach

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` uwzględnia konta pochodzące z usług katalogowych, które mogą być pominięte przy zwykłym odczycie `/etc/passwd`. Sprawdź konta z UID 0, powłoki logowania, katalogi domowe, grupy dodatkowe oraz konta, których konfiguracja nieoczekiwanie umożliwia logowanie interaktywne. Strona [interesting groups](interesting-groups-linux-pe/README.md) opisuje delegowany dostęp, taki jak `sudo`, `docker`, `disk` i `shadow`. Zanim uznasz nazwę grupy za uprawnienie, sprawdź rzeczywiste ACL systemu plików i lokalne zasady.

Jeśli [NSS kieruje zapytania o `passwd`, `group` lub `shadow`](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html) do bazy danych, przed oceną tożsamości opartych na bazie sprawdź aktywny provider i ścieżkę do jego konfiguracji. W przypadku wdrożeń PostgreSQL NSS pliki `/etc/nss-pgsql.conf` i `/etc/nss-pgsql-root.conf` wskazują jedynie ścieżki, ponieważ ustawienia połączenia mogą zawierać dane uwierzytelniające. Rola bazy danych ma znaczenie tylko wtedy, gdy może zmieniać rekordy faktycznie zwracane przez aktywny provider NSS, a konto może się przy ich użyciu uwierzytelnić. Główny GID równy 0 oznacza przynależność do grupy root, a nie UID 0; mapowanie na grupę sudo wymaga obowiązującej [reguły grupowej sudoers](https://man7.org/linux/man-pages/man5/sudoers.5.html) oraz wszelkiego wymaganego uwierzytelnienia. Mapowanie na UID 0 stanowi odrębną granicę tożsamości. Podczas pasywnej enumeracji nie wyświetlaj ciągów połączeń ani nie zmieniaj rekordów kont.

Porównaj również numeryczne UID przypisane lokalnym nazwom kont. Dwie nazwy w [`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) mogą wskazywać tę samą tożsamość plikową Unix, choć ich rekordy uwierzytelniania logowania mogą się różnić. Dlatego nowo dodany alias ze współdzielonym, niezerowym UID może po pomyślnym uwierzytelnieniu zapewnić dostęp do plików lub procesów innego użytkownika; nie daje uprawnień root, chyba że ten UID lub odrębna ścieżka eskalacji uprawnień je zapewnia. Współdzielone UID mogą być zamierzone. Zweryfikuj źródło konta (`/etc/passwd` lub NSS), historię utworzenia, powłokę i katalog domowy, faktyczne zasady uwierzytelniania oraz to, czy konta są uprawnione do współdzielenia tożsamości. Sprawdzenie duplikatów wyłącznie lokalnie nie wyklucza aliasu pochodzącego z usługi katalogowej.

## Znajdowanie aktywnych i niedawnych sesji

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

Socket `screen` lub `tmux` może udostępniać istniejącą powłokę, jeśli jego uprawnienia pozwalają bieżącemu użytkownikowi się do niej podłączyć. Przed próbą dostępu sprawdź właściciela i tryb socketu; sesja innego użytkownika nie jest automatycznie dostępna. Aktywny znacznik czasu sudo lub socket SSH agent również mogą mieć znaczenie, ale możliwość ich ponownego użycia zależy od tożsamości użytkownika, uprawnień i zasad. Informacje o nadużyciach związanych z agent forwarding znajdziesz w artykule [SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md).

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster) jest oddzielny od `SSH_AUTH_SOCK`: `ControlMaster` i `ControlPath` pozwalają kolejnym klientom SSH współdzielić istniejące uwierzytelnione połączenie, a `ControlPersist` może utrzymywać dostępność mastera po zakończeniu pierwszej sesji. Sprawdź plik `.ssh/config` bieżącego użytkownika oraz płytko zagnieżdżone ścieżki socketów w `.ssh`, w tym właściciela i uprawnienia. Sama nazwa pliku socketu nie dowodzi, że master działa, że bieżący użytkownik może się połączyć ani z jakiego konta zdalnego korzysta.

## Przejrzyj artefakty użytkownika

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Historia powłoki, pliki startowe, klucze SSH, konfiguracja aplikacji, keyringi GPG i cache Kerberos mogą ujawnić dane uwierzytelniające lub zapisywalne punkty utrwalania dostępu. Warto sprawdzić, czy `authorized_keys` lub plik startowy powłoki należący do konta o wyższych uprawnieniach jest zapisywalny. [Strona post-exploitation](../post-exploitation/README.md) opisuje zmianę lokalizacji katalogu domowego GPG i wyszukiwanie danych uwierzytelniających; [Linux Active Directory](linux-active-directory.md) opisuje ponowne użycie cache Kerberos i keytabów. [Strona PAM](../software-information/pam-pluggable-authentication-modules.md) wyjaśnia zagrożenia związane z polityką uwierzytelniania.
{{#include ../../banners/hacktricks-training.md}}
