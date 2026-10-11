# Enumeracja procesów i ścieżki usług

{{#include ../../banners/hacktricks-training.md}}

Warto ustalić, który uprzywilejowany proces korzysta z danych lub kodu, na które może wpływać użytkownik o niższych uprawnieniach. Sprawdź drzewo procesów, bieżące środowisko, otwarte pliki oraz jednostkę lub skrypt, który uruchomił każdego kandydata.

## Mapowanie procesów i właścicieli

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Relacja rodzic-dziecko między różnymi użytkownikami może być normalna, ale nieoczekiwana zmiana wymaga sprawdzenia polecenia procesu nadrzędnego, argumentów, pliku wykonywalnego, katalogu roboczego i wskazanych plików. Skorzystaj z [users and sessions](../user-information/user-and-session-triage.md), aby zinterpretować właściciela procesu i kontekst logowania.

### Lokalne konsole maszyn wirtualnych

Sprawdź opcje `-spice` procesu QEMU wraz z adresem, na którym nasłuchuje. [QEMU documents](https://www.qemu.org/docs/master/system/qemu-manpage.html), że `disable-ticketing` umożliwia klientom SPICE łączenie się bez uwierzytelniania. Proces nasłuchujący na adresie loopback może być nadal potencjalnie osiągalny dla innych lokalnych użytkowników hosta. Zanim uznasz wiersz poleceń za ujawniający konsolę, sprawdź aktywny listener, opcje uwierzytelniania i lokalny dostęp. Kontrola konsoli dotyczy **gościa**; uzyskanie konta gościa lub zmiana jego stanu rozruchu wymaga spełnienia odrębnych warunków po stronie gościa i nie zapewnia uprawnień root na hoście wirtualizacji. Podczas pasywnej enumeracji odczytuj argumenty procesu i metadane gniazd bez łączenia się z gościem ani ponownego uruchamiania go.

Lokalnie dostępny interfejs webowy może wykonywać kod z uprawnieniami konta usługi, nawet jeśli początkowa powłoka nie ma dostępu do plików tego konta. Na przykład CVE-2023-0297 dotyczył obsługi `/flash/addcrypted2` w pyLoad, gdy niezaufany JavaScript trafiał do Js2Py z włączonymi importami Pythona; [upstream fix](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) wyłączył `pyimport`. Zanim uznasz proces pyLoad za możliwą ścieżkę eskalacji uprawnień, sprawdź właściciela działającego procesu, adres nasłuchiwania, dostępność endpointu oraz zainstalowaną poprawkę lub backport od dostawcy. Sama nazwa procesu, otwarty port lub wersja pakietu nie dowodzą podatności; pasywna enumeracja nie powinna wysyłać payloadu wykonującego kod.

### Uprzywilejowane powłoki logowania współdzielące terminal

Uprzywilejowana powłoka interaktywna, która uruchamia `su --login <user>` bez niezależnego pseudo-terminala, może pozostawić terminal współdzielony z powłoką logowania użytkownika o niższych uprawnieniach. Jeśli plik startowy tego użytkownika można kontrolować, a kod w nim może użyć `TIOCSTI` do wstrzyknięcia danych wejściowych do terminala, po wznowieniu pracy uprzywilejowanej powłoki dane te mogą do niej trafić. [The util-linux `su` manual](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) opisuje ryzyko związane ze współdzielonym terminalem i zaleca `su --pty`/`-P` do użytku interaktywnego; `su -c` uruchamia oddzielną sesję bez terminala sterującego. Ryzyko zależy od faktycznej powłoki nadrzędnej, relacji terminali, docelowego pliku startowego i polityki jądra. Sama nazwa procesu lub argument `su -l` to jedynie wskazówka wymagająca weryfikacji.

Sprawdź zaobserwowane drzewo procesów i kolumny TTY, a następnie możliwy do odczytania launcher oraz właściciela i uprawnienia pliku startowego. W Linuksie `/proc/sys/dev/tty/legacy_tiocsti`, jeśli istnieje, może pomóc w interpretacji polityki; jego brak nie dowodzi bezpieczeństwa. [The Linux `TIOCSTI` manual](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) informuje, że od Linuksa 6.2 ta operacja może wymagać `CAP_SYS_ADMIN`, gdy ten sysctl ma wartość false. Nie wywołuj ioctl wyłącznie na potrzeby enumeracji hosta.

Konto bazy danych może czasem zmienić plik startowy użytkownika docelowego bez bezpośredniego dostępu do zapisu w systemie plików. Po stronie serwera PostgreSQL `COPY ... TO 'filename'` zapisuje plik z uprawnieniami konta systemowego serwera bazy danych, ale [PostgreSQL limits](https://www.postgresql.org/docs/current/sql-copy.html) ogranicza tę postać zapisu do superużytkowników bazy danych lub ról takich jak `pg_write_server_files`. Sprawdź zarówno rolę bazy danych, jak i uprawnienia konta systemowego serwera do plików; sam connection string aplikacji nie przyznaje uprawnień do zapisu plików. Oceniając cały łańcuch, rozpatruj osobno uprzywilejowany launcher i możliwości konta bazy danych.

## Sprawdź artefakty środowiska uruchomieniowego

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Usunięte pliki wykonywalne i usunięte, ale nadal otwarte pliki, pozostają dostępne przez deskryptory, dopóki nie zostanie zamknięty ostatni z nich. Mogą zachować ślady lub dostępne sekrety. Środowiska procesów i pamięć mogą zawierać dane uwierzytelniające, ale odczyt danych innego procesu ograniczają właściciel, opcje montowania `/proc`, polityka Yama ptrace i inne mechanizmy bezpieczeństwa. Powiązane techniki opisano w sekcjach [deskryptory plików](../main-system-information/filesystem-links-and-file-descriptors.md) i [wyszukiwanie danych uwierzytelniających po uzyskaniu dostępu](../post-exploitation/README.md).

Zapisane ślady wywołań systemowych stanowią kolejną granicę uprawnień plików. [`strace` zapisuje argumenty wywołań systemowych do pliku wyjściowego](https://man7.org/linux/man-pages/man1/strace.1.html), więc czytelny ślad argumentów [`execve`](https://man7.org/linux/man-pages/man2/execve.2.html) może ujawnić hasło przekazane w wierszu poleceń przez zadanie uruchomione z podwyższonymi uprawnieniami. Najpierw ustal, czy bieżący użytkownik może odczytać dany ślad i czy argument faktycznie zawiera dane uwierzytelniające; późniejsza zmiana konta Unix wymaga osobnego potwierdzenia, że te dane są tam akceptowane. Metadane plików mogą być przydatną pasywną wskazówką bez skanowania wszystkich śladów ani wyświetlania ich zawartości podczas rutynowej enumeracji.

## Gniazda uprzywilejowanej automatyzacji biurowej

LibreOffice i OpenOffice mogą udostępniać swoje API UNO za pomocą argumentu `--accept=socket,host=<host>,port=<port>;urp;`. Proces pakietu biurowego należący do roota, który ma osiągalny punkt końcowy, może umożliwić lokalnemu użytkownikowi o niższych uprawnieniach wywoływanie usług API w kontekście bezpieczeństwa tego procesu. Usługa `SystemShellExecute` zawiera operację uruchamiania polecenia systemowego. Nasłuchiwanie na loopback ogranicza dostęp zdalny, ale gniazdo nadal jest osiągalne dla lokalnych użytkowników, chyba że inny mechanizm kontroli dostępu temu zapobiega.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Skoreluj właściciela procesu, dokładny argument `--accept` oraz aktualny adres i port nasłuchujący. Skonfigurowany akceptor, któremu nie udało się wykonać bind, to jedynie wskazówka; podczas pasywnego rozpoznania nie łącz się z API ani go nie wywołuj. Nie uruchamiaj uprzywilejowanej instancji pakietu biurowego tylko po to, by przetestować ten warunek.

## Pamięć współdzielona System V używana przez procesy uprzywilejowane

Pomocniczy proces należący do użytkownika root może utworzyć segment pamięci współdzielonej System V, do którego zapisu ma inny użytkownik. Jeśli pomocniczy proces później zaufa danym z tego segmentu podczas wykonywania polecenia powłoki lub innej wrażliwej operacji, segment przekracza granicę uprawnień, nawet jeśli plik wykonywalny i jego pliki są chronione. `shmget()` pobiera uprawnienia dostępu z dziewięciu najmłodszych bitów swoich flag; tryb `0666` pozwala innym użytkownikom na zapis, natomiast flaga `IPC_CREAT` nie ogranicza tych uprawnień. Pasywnie sprawdzaj aktywne segmenty za pomocą `ipcs -m` i koreluj ich właściciela, tryb oraz czas istnienia z uprzywilejowanym procesem i sposobem obsługi jego danych wejściowych. Sam segment z prawami zapisu dla wszystkich nie dowodzi możliwości wykonania polecenia.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

Segmenty System V różnią się od plików pamięci współdzielonej POSIX w `/dev/shm`. Segment utworzony tylko na chwilę może być nieobecny w pojedynczym zrzucie `ipcs`, więc pusty wynik nie wyklucza używania pamięci współdzielonej przez pomocniczy program. Sprawdź jego kod źródłowy lub zachowanie pliku binarnego oraz każdą regułę `sudo`, która go uruchamia; nie wywołuj uprzywilejowanego programu pomocniczego tylko po to, by podczas enumeracji utworzyć segment. [Przewodnik po przestrzeniach nazw IPC](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) wyjaśnia, jak przestrzenie nazw wpływają na widoczność.<sup>[[2]](#references)[[3]](#references)</sup>

## Kontrole skryptowe agenta Consul

Consul może uruchamiać skryptowe kontrole stanu z tożsamością systemu operacyjnego swojego agenta. Jeśli agent działa jako root, ma włączone `enable_script_checks` i pozwala użytkownikowi o niższych uprawnieniach zarejestrować usługę z kontrolą skryptową przez lokalne HTTP API, taki użytkownik może spowodować uruchomienie poleceń jako root. Powiązanie API wyłącznie z `127.0.0.1` nadal umożliwia lokalnym użytkownikom dostęp do niego. Ustawienie `enable_local_script_checks` jest bardziej restrykcyjne: wyklucza kontrole skryptowe przesyłane w ramach rejestracji przez HTTP API. Gdy włączone są ACL-e Consul, rejestracja usługi wymaga `service:write`; sama linia `acl.default_policy=allow` nie dowodzi, że anonimowy klient może dokonać rejestracji. Sprawdź łącznie faktyczną tożsamość agenta, załadowane ustawienia, powiązanie API i autoryzację.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Korzystając z argumentów `-config-dir` i `-config-file` uruchomionego agenta, odszukaj właściwą konfigurację i sprawdź tylko nazwy oraz ustawienia pól script-check i ACL. Pliki konfiguracyjne mogą też zawierać klucze lub tokeny gossip; nie wklejaj ich do współdzielonych logów. Nie rejestruj usługi ani nie uruchamiaj health check wyłącznie po to, by wyliczyć ten warunek.

Istnieje też osobna ścieżka przez plik lokalny, jeśli użytkownik o niższych uprawnieniach może **zapisywać w katalogu** wskazanym przez `-config-dir` agenta uruchomionego jako root oraz **przeszukiwać ten katalog**: może zostać z niego załadowana nowa definicja usługi `.hcl` lub `.json`. Możliwość przeszukiwania i zapisu w katalogu może pozwolić dodać plik nawet wtedy, gdy odmówiono prawa do wyświetlania jego zawartości. Aby potwierdzić możliwość wykonywania poleceń jako root, sprawdź, czy agent rzeczywiście ładuje ten katalog, czy jego **efektywne** ustawienie script-check zezwala na lokalne definicje, czy definicja została załadowana oraz czy agent zachowuje uprawnienia root. [Dokumentacja Consul](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) opisuje, które ustawienia i definicje health check można przeładować; włączenie script checks może wymagać ponownego uruchomienia, dlatego sprawdź zachowanie zainstalowanej wersji. Gdy ACL chronią agenta, [`consul reload` wymaga `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); same uprawnienia do zapisu KV tego nie zapewniają. Traktuj możliwość modyfikacji metadanych katalogu jako wskazówkę do weryfikacji, a nie dowód na dozwolone przeładowanie, ponowne uruchomienie lub wykonanie polecenia. Sprawdź ścieżki, uprawnienia i politykę, nie zapisując konfiguracji ani nie wywołując API.

## Prześledź łańcuch wykonywania usługi

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Sprawdź unit, drop-ins, `EnvironmentFile=`, skrypty pomocnicze, polecenia względne, katalogi z prawem zapisu i aktywację przez socket. Unit należący do roota nadal może być niebezpieczny, jeśli odczytuje konfigurację lub skrypt, które użytkownik może modyfikować. Strona [arbitrary file write](../interesting-files-permissions/write-to-root.md) opisuje typowe ścieżki nadużyć związane z usługami i unitami. Krótkotrwałe zadania monitoruj za pomocą [pspy](https://github.com/DominicBreuker/pspy) lub telemetrii audytowej/procesowej, gdy jednorazowe wywołanie `ps` ich nie wykryje.

W przypadku niestandardowej usługi **xinetd** powiąż włączoną sekcję z polami `server`, `user` i kontrolą dostępu, a także z aktywnym nasłuchującym socketem i dokładnym plikiem wykonywalnym. Ustawienie [`user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) określa tożsamość uruchomionego procesu, natomiast bit set-user-ID na pliku wykonywalnym może osobno zmienić jego efektywną tożsamość, jeśli [`execve` zezwala na taką zmianę](https://man7.org/linux/man-pages/man2/execve.2.html). Dostępny uprzywilejowany plik binarny przyjmujący niezaufane dane wejściowe warto przeanalizować offline pod kątem błędów bezpieczeństwa pamięci, takich jak nieograniczona konwersja ciągu znaków [`scanf`](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) do bufora o stałym rozmiarze. Mapowanie usługi i metadane set-user-ID są wskazówkami, a nie dowodem istnienia takiego błędu; podczas pasywnego rozpoznania nie wysyłaj danych wywołujących awarię ani nie debuguj aktywnej uprzywilejowanej usługi.

W przypadku niestandardowego uprzywilejowanego procesu nasłuchującego, którego kod źródłowy jest dostępny do odczytu, sprawdź każdą długość kontrolowaną przez wywołującego, używaną w operacji kopiowania, takiej jak [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Samo sprawdzenie, że bieżący indeks zapisu mieści się w stałym buforze, nie dowodzi, że **długość kopiowania** mieści się w pozostałym miejscu; po potwierdzeniu, że indeks jest prawidłowy, sprawdź, czy `copy_length <= capacity - index`, a także zweryfikuj znakowość i przepełnienie arytmetyczne. To tylko wskazówka do analizy — ma znaczenie, gdy dane wejściowe docierają do tej operacji, użytkownik o niższych uprawnieniach ma dostęp do procesu nasłuchującego, a proces zachowuje wyższą efektywną tożsamość. Analizuj kod źródłowy i metadane procesu offline; podczas rozpoznania nie wysyłaj do aktywnej usługi danych wywołujących awarię.

W systemach używających **Upstart** definicje zadań systemowych mogą znajdować się w `/etc/init/*.conf`. Plik zadania, który może modyfikować bieżący użytkownik, ma znaczenie, jeśli aktywny demon init ładuje właśnie to zadanie, jego sekcja `script` lub `exec` działa z wyższymi uprawnieniami, a użytkownik może je uruchomić za pomocą dozwolonego polecenia `initctl` lub innego rzeczywistego wyzwalacza. Samo uprawnienie sudo do `initctl` nie dowodzi, że jakikolwiek plik zadania można modyfikować ani że zmodyfikowane zadanie zostanie uruchomione. Sprawdź uprawnienia dokładnego pliku zadania, efektywne ustawienie konta uruchomieniowego, aktywny demon oraz wyzwalacz — nie edytuj ani nie uruchamiaj zadania podczas rozpoznania. Zobacz instrukcje [konfiguracji zadań Upstart](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) i [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Plik z hasłem do automatycznego logowania, dostępny do odczytu, na przykład `/etc/autologin/passwd` w systemach, w których [zadanie rozruchowe odczytuje dokładnie tę ścieżkę](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), wskazuje na możliwe ujawnienie danych uwierzytelniających. Potwierdź, że zadanie rozruchowe jest zainstalowane i używa tego pliku, a następnie osobno zweryfikuj, czy hasło jest prawidłowe dla innego lokalnego konta lub usługi. Sama nazwa pliku nie dowodzi ponownego użycia hasła; zapisuj ścieżkę i metadane dostępu, nie umieszczając hasła we współdzielonych wynikach rozpoznania.

`ExecStart=` unitu lub zaplanowane polecenie mogą ujawnić dokładną ścieżkę do skryptu w katalogu, którego zawartości nie można wyświetlić. [Prawo przeszukiwania katalogu](https://man7.org/linux/man-pages/man7/path_resolution.7.html) może nadal pozwalać bieżącej tożsamości przejść znaną ścieżką; sprawdź prawo przeszukiwania każdego katalogu nadrzędnego i prawo odczytu pliku, zamiast zakładać, że nieudane wyświetlenie zawartości katalogu chroni plik. Czytelny skrypt może zawierać dane uwierzytelniające do transferu, ale dostęp do innego konta wymaga, by te dane nadal były ważne i zostały niezależnie zaakceptowane. Zapisuj ścieżkę i dowody dotyczące uprawnień, nie ujawniając sekretów we współdzielonych logach.

W przypadku zaplanowanego skryptu CommonJS Node.js sprawdź niekwalifikowane importy, takie jak `require('package')`, nawet gdy sam skrypt jest tylko do odczytu. [Node wyszukuje `node_modules` obok importującego pliku, a następnie w katalogach nadrzędnych](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), zanim przejdzie do skonfigurowanych ścieżek globalnych. Użytkownik o niższych uprawnieniach, który może **zapisywać i przeszukiwać** jeden z tych katalogów nadrzędnych, może być w stanie utworzyć pakiet wyszukiwany wcześniej. Potwierdź, że wykonywany jest dokładny import, wybrany pakiet nie jest modułem wbudowanym, można utworzyć lub zmienić odpowiednią ścieżkę, moduł jest tam rozwiązywany w zainstalowanym środowisku uruchomieniowym, a zadanie o wyższych uprawnieniach załaduje go przy kolejnym uruchomieniu. Metadane katalogu nadrzędnego z prawem zapisu są tylko wskazówką do analizy; sprawdź skrypt i harmonogram pasywnie, nie umieszczając modułu ani nie wyzwalając zadania.

Prywatny indeks pakietów Python to kolejna granica zaufania, gdy zautomatyzowane zadanie instaluje pakiety z użyciem innej tożsamości systemu operacyjnego. Powiąż dokładne zadanie i konto uruchomieniowe ze skonfigurowanym indeksem, wybranymi nazwami pakietów oraz możliwością publikowania lub zastąpienia przez użytkownika o niższych uprawnieniach pakietu, który zadanie faktycznie zainstaluje. Budowanie dystrybucji źródłowej może uruchamiać backend kompilacji lub starszy `setup.py` z uprawnieniami instalatora; zaimportowanie zainstalowanego pakietu to osobna ścieżka wykonania. Sam listener indeksu, czytelny hash hasła do przesyłania plików lub nazwa pliku pakietu nie dowodzą istnienia takiego łańcucha. Sprawdź zadanie, autoryzację do indeksu i pochodzenie pakietu, nie przesyłając ani nie instalując niczego podczas rozpoznania. Zobacz [interfejs systemu kompilacji pip](https://pip.pypa.io/en/stable/reference/build-system/) i [wskazówki dotyczące bezpiecznej instalacji](https://pip.pypa.io/en/stable/topics/secure-installs/).

Uprzywilejowany agent może odpytywać kolejkę zadań zarządzaną przez osobną usługę webową lub kontener. Jeśli tożsamość o niższym poziomie zaufania może zapisywać bazę danych zadań tej usługi, ustal, czy te rekordy są faktycznie udostępniane agentowi i czy zadanie polecenia jest uruchamiane z tożsamością systemu operacyjnego agenta. Osobno potwierdź dostęp do zapisu w bazie danych, docelową sesję lub klucz routingu, aktywne odpytywanie, autoryzację zadań i efektywnego użytkownika agenta. Uprawnienia roota w kontenerze same w sobie nie oznaczają dostępu do roota hosta; granica zostaje przekroczona tylko wtedy, gdy konsument z uprawnieniami hosta wykonuje kontrolowane przez atakującego dane zadania. Sprawdź metadane procesów, pliku bazy danych i usługi, nie modyfikując kolejki ani nie wysyłając zadania podczas rozpoznania.

Zaplanowane zadanie może zamiast tego odczytywać polecenie z wiersza konfiguracji bazy danych aplikacji. Potwierdź, że rola bazy danych o niższych uprawnieniach może zmienić dokładnie ten wiersz, aktywne zadanie odczytuje go po zmianie, a wartość trafia do powłoki lub równoważnego mechanizmu uruchamiania poleceń działającego z wyższą tożsamością systemu operacyjnego. Dostęp do zapisu w bazie danych lub sama wartość przypominająca polecenie nie dowodzą wykonania; sprawdź zadanie i uprawnienia, nie zmieniając wiersza podczas pasywnego rozpoznania.

Kolejka może też zawierać URL zamiast kodu. Jeśli uprzywilejowany konsument pobiera ten URL i ładuje odpowiedź jako wtyczkę Lua lub inną wykonywalną wtyczkę, zweryfikuj uprawnienia nadawcy do dokładnej exchange i routing key, powiązanie z odczytywaną kolejką, ścieżkę pobrania i ładowania wtyczki oraz efektywną tożsamość workera. [RabbitMQ kieruje publikowane wiadomości przez exchanges](https://www.rabbitmq.com/docs/exchanges); sam listener brokera lub prawidłowe dane logowania nie dowodzą dostarczenia wiadomości do tego workera. Przechwycone jawne dane uwierzytelniające do brokera to osobna wskazówka, która wymaga faktycznego dostępu do przechwytywania pakietów i ruchu możliwego do odczytania; nie dowodzą one uprawnień do publikowania. Wtyczka Lua może uruchamiać polecenia powłoki przez [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) tylko wtedy, gdy to API jest dostępne w jej środowisku uruchomieniowym. Sprawdź konfigurację i kod, nie przechwytując ruchu, nie publikując wiadomości ani nie pobierając wtyczki podczas pasywnego rozpoznania.

Gdy uprzywilejowana usługa Python udostępnia lokalny endpoint HTTP lub socket, czytelny skrypt może ujawnić ścieżkę od danych wejściowych do kodu, nawet jeśli uprawnienia pliku uniemożliwiają jego modyfikację. Powiąż aktywny proces i tożsamość unitu z dokładnym skryptem, listenerem, autoryzacją trasy i polami kontrolowanymi przez wywołującego. Następnie prześledź te pola przez parsowanie i walidację aż do dynamicznego miejsca wykonania `eval()` lub `exec()`. W szczególności utworzenie nowego f-stringa z tekstu żądania i jego ewaluacja może zinterpretować podstawione przez atakującego pola jako wyrażenia Python ([ostrzeżenie dotyczące `eval` w Pythonie](https://docs.python.org/3/library/functions.html#eval); [semantyka f-stringów](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Samo znalezienie `eval` lub powiązanie z loopbackiem nie dowodzi, że niezaufany wywołujący może dotrzeć do miejsca wykonania; sprawdź rzeczywisty przepływ danych i kontrolę dostępu, nie wysyłając testowego payloadu podczas rozpoznania.

Bramka oparta na podpisanym żądaniu na tej trasie wymaga osobnej analizy. Jeśli czytelny kod źródłowy wyprowadza klucz podpisujący z wyraźnie małej lub przewidywalnej przestrzeni wyników, a usługa udostępnia prawidłową próbkę podpisanego żądania, podpis może już nie chronić uprzywilejowanego miejsca `eval()`. Zweryfikuj dokładny sposób wyprowadzania klucza i weryfikator, tożsamość aktywnej usługi i lokalny dostęp wywołującego oraz to, czy podpisane pole trafia do miejsca wykonania; samo zaimportowanie modułu [`random` w Pythonie](https://docs.python.org/3/library/random.html) lub przykładowy podpis nie dowodzą żadnego z tych warunków. Python ostrzega również, że ograniczenie `__builtins__` [nie stanowi granicy bezpieczeństwa dla niezaufanych danych wejściowych do `eval()`](https://docs.python.org/3/library/functions.html#eval). Analizuj klucze offline i nie wysyłaj sfałszowanych żądań podczas pasywnego rozpoznania.

Pusty, ale zapisywalny katalog `/etc/systemd/system/<unit>.service.d` ma znaczenie nawet wtedy, gdy plik unitu i wszystkie istniejące drop-ins są chronione: użytkownik może utworzyć nowe nadpisanie `.conf`. Sprawdź, czy bieżąca tożsamość może zapisywać i przeszukiwać katalog, czy unit jest załadowany i działa jako root oraz czy nastąpi ponowne załadowanie demona, a potem restart. Uprawnienie do przeładowania lub restartu, timer albo późniejszy rozruch mogą uaktywnić zmianę; sam dostęp do zapisu w katalogu nie powoduje jej natychmiastowego wykonania.

W przypadku działających usług sprawdzaj dosłowne ścieżki `EnvironmentFile=` z sekcji `[Service]` unitu, także pliki, których nazwy nie zaczynają się od `.env`. Jeśli użytkownik o niskich uprawnieniach może odczytać taki plik, wyświetl nazwy kluczy przypominające dane uwierzytelniające, takie jak `API_TOKEN` lub `APP_SECRET_KEY`, ale nie wypisuj ich wartości we współdzielonych logach. Przy ustalaniu efektywnego unitu sprawdź nadpisania drop-in i opcjonalne prefiksy `-`. Możliwość odczytu wskazuje na możliwe ujawnienie danych uwierzytelniających; aby doprowadzić do eskalacji, wartość musi być nadal prawidłowa dla uprzywilejowanej operacji.

### Uprzywilejowane przetwarzanie niezaufanych plików przesyłanych przez użytkowników

Watcher plików działający jako root może przekazywać pliki z zapisywalnego przez użytkownika katalogu przesyłania do krótkotrwałego parsera lub programu rozpakowującego. Prześledź skrypt nadrzędny lub usługę działającego watchera i potwierdź dokładny katalog, osoby mogące umieszczać w nim pliki, polecenie potomne wraz z argumentami oraz tożsamość, z jaką działa proces potomny. Migawka procesów może pokazać watchera, ale pominąć program rozpakowujący uruchamiany między przesłaniami. Podczas pasywnego rozpoznania nie umieszczaj testowego payloadu ani nie wyzwalaj watchera.

Konkretnym przykładem jest tryb rozpakowywania Binwalk (`-e`) przetwarzający kontrolowane przez atakującego dane PFS. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) umożliwiało ekstraktorowi PFS zapis poza przeznaczonym katalogiem, w tym do ścieżki wtyczek, którą Binwalk mógł później załadować. Poprawkę uwzględniono upstream w wersji [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), ale poprawki przeniesione do dystrybucji mogą oznaczać, że wyświetlana wersja jest starsza; zanim uznasz problem za dotyczący systemu, sprawdź status bezpieczeństwa zainstalowanego pakietu, na przykład w [trackerze Debiana](https://security-tracker.debian.org/tracker/CVE-2022-4510). Sama zainstalowana wersja Binwalk nie dowodzi istnienia ścieżki eskalacji uprawnień: bardziej uprzywilejowany proces musi faktycznie wywoływać rozpakowywanie na danych kontrolowanych przez użytkownika o niższych uprawnieniach.

### Zaplanowane kompilacje z lokalnymi zależnościami

Zaplanowane `cargo run` ponownie kompiluje kod źródłowy z uprawnieniami użytkownika, na którego konto uruchamiane jest zadanie. Sprawdź lokalne zależności `{ path = "..." }` w manifeście oraz uprawnienia do kodu źródłowego i katalogów nadrzędnych każdej zależności, a nie tylko głównego crate. Jeśli użytkownik o niższych uprawnieniach może zmodyfikować zależność kompilowaną przez Cargo, a zaplanowane zadanie uruchamia jej wynik, skompilowany kod może wykonać się z uprawnieniami tego użytkownika uruchomieniowego. Potwierdź efektywne polecenie harmonogramu, katalog roboczy, rozwiązywanie zależności i to, czy nastąpi ponowna kompilacja; plik źródłowy Rust z prawem zapisu w innym miejscu jest tylko wskazówką. Do wstępnej pasywnej analizy wystarczy odczytanie manifestu i metadanych ścieżek. Zobacz [dokumentację zależności ścieżkowych Cargo](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Pliki framebuffer Xvfb

`Xvfb -fbdir <directory>` używa plików mapowanych do pamięci o nazwach `Xvfb_screen<n>` dla swoich wirtualnych ekranów. Jeśli działający proces Xvfb innego użytkownika wskazuje katalog, którego pliki ekranu może odczytać bieżący użytkownik, framebuffer może ujawniać zawartość pulpitu tego użytkownika. Potwierdź jednocześnie proces, właściciela pliku i uprawnienia; sam fakt, że plik można odczytać, nie dowodzi, że ekran zawiera użyteczne dane. Najpierw sprawdź ścieżki i metadane, nie kopiując danych obrazu do współdzielonych wyników rozpoznania. [Instrukcja Xvfb](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) opisuje działanie `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Podręcznik Linuxa `shmget(2)`](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Podręcznik Linuxa `ipcs(1)`](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [Podręcznik OpenBSD `ipcs(1)`](https://man.openbsd.org/ipcs.1)
4. [Konfiguracja agenta Consul: sprawdzanie skryptów](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [API rejestracji usług agenta Consul](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Konfiguracja ACL w Consul](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [Pomoc LibreOffice: otwieranie socketu dla zewnętrznych klientów API](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
