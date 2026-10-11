# Inwentaryzacja procesów i ścieżki usług

{{#include ../../banners/hacktricks-training.md}}

Warto ustalić, który uprzywilejowany proces korzysta z danych lub kodu, na które może wpływać użytkownik o niższych uprawnieniach. Sprawdź drzewo procesów, bieżące środowisko, otwarte pliki oraz jednostkę lub skrypt, który uruchomił każdy z potencjalnych procesów.

## Mapowanie procesów i właścicieli

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Relacja rodzic–dziecko między różnymi użytkownikami może być normalna, ale nieoczekiwana zmiana wymaga sprawdzenia polecenia procesu nadrzędnego, argumentów, pliku wykonywalnego, katalogu roboczego i wskazanych plików. Skorzystaj z informacji o [użytkownikach i sesjach](../user-information/user-and-session-triage.md), aby zinterpretować właściciela procesu i kontekst logowania.

### Lokalne konsole maszyn wirtualnych

Sprawdź opcje `-spice` procesu QEMU wraz z adresem, na którym nasłuchuje. [Dokumentacja QEMU](https://www.qemu.org/docs/master/system/qemu-manpage.html) informuje, że `disable-ticketing` pozwala klientom SPICE łączyć się bez uwierzytelniania. Usługa nasłuchująca na loopback nadal może być dostępna dla innych lokalnych użytkowników hosta. Zanim uznasz wiersz poleceń za ujawniający konsolę, potwierdź aktywny nasłuch, opcje uwierzytelniania i lokalny dostęp. Sterowanie konsolą dotyczy **gościa**; uzyskanie konta gościa lub zmiana jego stanu rozruchu wymaga spełnienia odrębnych warunków po stronie gościa i nie daje uprawnień root na hoście wirtualizacji. Podczas pasywnej enumeracji odczytuj argumenty procesu i metadane gniazda, nie łącząc się z gościem ani go nie uruchamiając ponownie.

Lokalnie dostępny interfejs WWW może wykonywać kod z uprawnieniami konta usługi, nawet jeśli początkowa powłoka nie ma dostępu do plików tego konta. Na przykład CVE-2023-0297 dotyczył obsługi `/flash/addcrypted2` w pyLoad, gdy niezaufany JavaScript trafiał do Js2Py z włączonymi importami Pythona; [poprawka upstream](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) wyłączyła `pyimport`. Zanim uznasz proces pyLoad za ścieżkę eskalacji, sprawdź właściciela działającego procesu, adres nasłuchu, dostępność endpointu oraz zainstalowaną poprawkę lub backport od dostawcy. Sama nazwa procesu, otwarty port lub wersja pakietu nie dowodzą, że system jest podatny; pasywna enumeracja nie powinna wysyłać payloadu wykonującego kod.

### Uprzywilejowane powłoki logowania współdzielące terminal

Uprzywilejowana powłoka interaktywna, która uruchamia `su --login <user>` bez niezależnego pseudo-terminala, może współdzielić terminal z powłoką logowania użytkownika o niższych uprawnieniach. Jeśli plik startowy tego użytkownika można kontrolować, a kod w nim może użyć `TIOCSTI` do wstrzyknięcia danych wejściowych do terminala, mogą one trafić do uprzywilejowanej powłoki po jej wznowieniu. [Podręcznik `su` z util-linux](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) opisuje ryzyko współdzielonego terminala i zaleca `su --pty`/`-P` do użytku interaktywnego; `su -c` uruchamia osobną sesję bez terminala sterującego. Ryzyko zależy od faktycznej powłoki nadrzędnej, relacji terminali, docelowego pliku startowego i zasad jądra. Sama nazwa procesu lub argument `su -l` to jedynie wskazówka wymagająca sprawdzenia.

Sprawdź zaobserwowane drzewo procesów i kolumny TTY, a następnie możliwy do odczytu program uruchamiający oraz właściciela i uprawnienia pliku startowego. W Linuksie `/proc/sys/dev/tty/legacy_tiocsti`, jeśli istnieje, może pomóc w ustaleniu obowiązujących zasad; jego brak nie dowodzi, że system jest bezpieczny. [Podręcznik Linuksa dotyczący `TIOCSTI`](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) informuje, że od Linuksa 6.2 ta operacja może wymagać `CAP_SYS_ADMIN`, gdy ten sysctl ma wartość false. Nie wywołuj ioctl wyłącznie w celu enumeracji hosta.

Konto bazy danych może czasami zmienić plik startowy docelowego użytkownika bez bezpośredniego dostępu do zapisu w systemie plików. Serwerowe `COPY ... TO 'filename'` w PostgreSQL zapisuje plik z uprawnieniami konta systemowego serwera bazy danych, ale [ograniczenia PostgreSQL](https://www.postgresql.org/docs/current/sql-copy.html) dopuszczają tę postać tylko dla superużytkowników bazy danych lub ról takich jak `pg_write_server_files`. Potwierdź zarówno rolę bazy danych, jak i uprawnienia konta systemowego serwera do plików; sam ciąg połączenia aplikacji nie przyznaje uprawnień do zapisu plików. Oceniając łańcuch, traktuj możliwości uprzywilejowanego programu uruchamiającego i konta bazy danych oddzielnie.

## Sprawdź artefakty środowiska wykonawczego

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Usunięte pliki wykonywalne i usunięte, ale wciąż otwarte pliki pozostają dostępne, dopóki nie zostanie zamknięty ich ostatni deskryptor. Mogą zachowywać dowody lub dostępne sekrety. Środowisko procesów i ich pamięć mogą zawierać dane uwierzytelniające, ale odczyt innego procesu ograniczają właściciel, opcje montowania `/proc`, polityka Yama ptrace i inne mechanizmy bezpieczeństwa. Zobacz [deskryptory plików](../main-system-information/filesystem-links-and-file-descriptors.md) oraz [wyszukiwanie danych uwierzytelniających po uzyskaniu dostępu](../post-exploitation/README.md), aby poznać powiązane techniki.

Zapisane ślady syscalli stanowią kolejną granicę uprawnień do plików. [`strace` zapisuje argumenty syscalli w pliku wyjściowym](https://man7.org/linux/man-pages/man1/strace.1.html), więc czytelny ślad [argumentów `execve`](https://man7.org/linux/man-pages/man2/execve.2.html) może ujawnić hasło, które uprzywilejowane zadanie przekazało w wierszu poleceń. Najpierw ustal, czy bieżący użytkownik może odczytać dany ślad i czy argument rzeczywiście zawiera dane uwierzytelniające; późniejsza próba przejścia na konto Unix wymaga osobnego potwierdzenia, że te dane są akceptowane. Metadane plików mogą stanowić przydatną, pasywną wskazówkę, bez skanowania wszystkich śladów ani wyświetlania ich zawartości podczas rutynowej enumeracji.

## Uprzywilejowane gniazda automatyzacji pakietu biurowego

LibreOffice i OpenOffice mogą udostępniać swoje API UNO za pomocą argumentu `--accept=socket,host=<host>,port=<port>;urp;`. Proces pakietu biurowego należący do roota z osiągalnym punktem końcowym może umożliwić lokalnemu użytkownikowi o niższych uprawnieniach wywoływanie usług API w kontekście bezpieczeństwa tego procesu. Usługa `SystemShellExecute` obejmuje operację uruchamiania polecenia systemowego. Nasłuchiwanie na interfejsie loopback ogranicza dostęp zdalny, ale gniazdo nadal pozostaje osiągalne dla lokalnych użytkowników, o ile inny mechanizm nie blokuje dostępu.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Skoreluj właściciela procesu, dokładny argument `--accept` oraz aktualny adres i port nasłuchujący. Skonfigurowany akceptor, któremu nie udało się powiązać z adresem, to tylko trop; podczas pasywnego rozpoznania nie łącz się z API ani go nie wywołuj. Unikaj uruchamiania uprzywilejowanej instancji office wyłącznie po to, by przetestować ten warunek.

## Pamięć współdzielona System V używana przez uprzywilejowane procesy

Pomocniczy program działający jako root może utworzyć segment pamięci współdzielonej System V, do którego inny użytkownik może zapisywać dane. Jeśli program później zaufa danym z tego segmentu podczas wykonywania polecenia powłoki lub innej wrażliwej operacji, segment przekracza granicę uprawnień, nawet jeśli plik wykonywalny i jego pliki są chronione. `shmget()` pobiera uprawnienia dostępu z dolnych dziewięciu bitów swoich flag; tryb `0666` pozwala innym użytkownikom na zapis, natomiast flaga `IPC_CREAT` nie zawęża tych uprawnień. Aktywne segmenty sprawdzaj pasywnie za pomocą `ipcs -m` i koreluj ich właściciela, tryb oraz czas istnienia z uprzywilejowanym procesem i sposobem obsługi jego danych wejściowych. Sam segment z prawem zapisu dla wszystkich nie dowodzi możliwości wykonania poleceń.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

Segmenty System V różnią się od plików pamięci współdzielonej POSIX w `/dev/shm`. Segment utworzony tylko na chwilę może być nieobecny w pojedynczym zrzucie `ipcs`, dlatego pusty wynik nie wyklucza działania pomocniczego programu korzystającego z pamięci współdzielonej. Sprawdź jego kod źródłowy lub zachowanie pliku binarnego oraz każdą regułę `sudo`, która go uruchamia; nie wywołuj uprzywilejowanego programu pomocniczego tylko po to, by segment pojawił się podczas enumeracji. [Przewodnik po przestrzeniach nazw IPC](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) wyjaśnia, jak przestrzenie nazw wpływają na widoczność.<sup>[[2]](#references)[[3]](#references)</sup>

## Kontrole skryptowe agenta Consul

Consul może uruchamiać skryptowe kontrole stanu z tożsamością systemu operacyjnego swojego agenta. Jeśli agent działa jako root, ma włączone `enable_script_checks` i pozwala użytkownikowi o niższych uprawnieniach zarejestrować usługę z kontrolą skryptową za pośrednictwem lokalnego HTTP API, użytkownik ten może doprowadzić do uruchomienia poleceń z uprawnieniami root. Powiązanie API tylko z `127.0.0.1` nadal pozwala lokalnym użytkownikom na dostęp. Ustawienie `enable_local_script_checks` ma węższy zakres: wyklucza kontrole skryptowe przesyłane przez rejestracje w HTTP API. Gdy włączone są ACL-e Consul, rejestracja usługi wymaga uprawnienia `service:write`; sam wpis `acl.default_policy=allow` nie dowodzi, że anonimowy użytkownik może zarejestrować usługę. Zweryfikuj łącznie rzeczywistą tożsamość agenta, załadowane ustawienia, powiązanie API i autoryzację.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Podążaj za argumentami `-config-dir` i `-config-file` działającego agenta, aby znaleźć odpowiednią konfigurację, i sprawdzaj wyłącznie nazwy oraz ustawienia pól dotyczących kontroli skryptów i ACL. Pliki konfiguracyjne mogą też zawierać klucze gossip lub tokeny; nie wklejaj ich do współdzielonych logów. Nie rejestruj usługi ani nie uruchamiaj kontroli stanu wyłącznie po to, by wyliczyć ten warunek.

Istnieje osobna ścieżka wykorzystująca lokalny plik, jeśli użytkownik z niższymi uprawnieniami może **zapisywać w katalogu** wskazanym przez `-config-dir` agenta uruchomionego jako root i **przeszukiwać ten katalog**: z tego katalogu może zostać wczytana nowa definicja usługi `.hcl` lub `.json`. Uprawnienia do przeszukiwania i zapisu katalogu mogą pozwalać na dodanie pliku, nawet gdy odmówiono wyświetlania jego zawartości. Aby potwierdzić możliwość wykonywania poleceń jako root, sprawdź, czy agent faktycznie wczytuje ten katalog, czy **efektywne** ustawienie kontroli skryptów zezwala na lokalne definicje, czy definicja została wczytana oraz czy agent zachowuje uprawnienia roota. [Dokumentacja Consul](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) opisuje, które ustawienia i definicje kontroli stanu można wczytać ponownie; samo włączenie kontroli skryptów może wymagać ponownego uruchomienia, dlatego sprawdź zachowanie zainstalowanej wersji. Gdy agent jest chroniony przez ACL, [`consul reload` wymaga `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); samo uprawnienie do zapisu KV go nie zapewnia. Potraktuj możliwość modyfikacji metadanych katalogu jako sygnał wymagający weryfikacji, a nie dowód na uprawniony przeładunek, ponowne uruchomienie lub wykonanie polecenia. Sprawdź ścieżki, uprawnienia i politykę bez zapisywania konfiguracji ani wywoływania API.

## Prześledź łańcuch wykonywania usługi

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Sprawdź jednostkę, drop-iny, `EnvironmentFile=`, skrypty pomocnicze, polecenia względne, zapisywalne katalogi i aktywację przez gniazdo. Jednostka należąca do roota nadal może być niebezpieczna, jeśli odczytuje konfigurację lub skrypt, do którego użytkownik ma prawo zapisu. Strona [arbitrary file write](../interesting-files-permissions/write-to-root.md) opisuje typowe ścieżki nadużyć związane z usługami i jednostkami. Krótkotrwałe zadania monitoruj za pomocą [pspy](https://github.com/DominicBreuker/pspy) lub telemetrii audytowej/procesowej, jeśli jednorazowe wywołanie `ps` ich nie wykrywa.

W przypadku własnej usługi **xinetd** zestaw aktywną sekcję konfiguracji (`server`, `user` i kontrolę dostępu) z aktywnym nasłuchem i dokładnym plikiem wykonywalnym. Ustawienie [`user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) określa tożsamość uruchamianego procesu, natomiast bit set-user-ID pliku wykonywalnego może niezależnie zmienić jego efektywną tożsamość, jeśli [`execve` zezwala na takie przejście](https://man7.org/linux/man-pages/man2/execve.2.html). Dostępny z sieci uprzywilejowany plik binarny, który przyjmuje niezaufane dane wejściowe, warto przeanalizować offline pod kątem błędów bezpieczeństwa pamięci, takich jak nieograniczona konwersja ciągu w [`scanf`](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) do bufora o stałym rozmiarze. Mapowanie usługi i metadane set-user-ID są wskazówkami, a nie dowodem istnienia takiego błędu; podczas pasywnej enumeracji nie wysyłaj danych powodujących awarię ani nie debuguj działającej, uprzywilejowanej usługi.

W przypadku własnego uprzywilejowanego procesu nasłuchującego, którego kod źródłowy można odczytać, sprawdź każdą długość kontrolowaną przez wywołującego, używaną przez operację kopiowania, taką jak [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Samo sprawdzenie, że bieżący indeks zapisu mieści się w buforze o stałym rozmiarze, nie dowodzi, że **długość kopiowania** mieści się w pozostałej przestrzeni; po potwierdzeniu, że indeks jest w zakresie, sprawdź `copy_length <= capacity - index` oraz uwzględnij znakowość i przepełnienie arytmetyczne. To jedynie wskazówka do analizy, jeśli dane wejściowe docierają do tej operacji, proces nasłuchujący jest dostępny dla użytkownika o niższych uprawnieniach, a proces zachowuje wyższą efektywną tożsamość. Analizuj kod źródłowy i metadane procesu offline; podczas enumeracji nie wysyłaj do działającej usługi danych powodujących awarię.

W systemach korzystających z **Upstart** definicje zadań systemowych mogą znajdować się w `/etc/init/*.conf`. Plik zadania, do którego bieżący użytkownik ma prawo zapisu, ma znaczenie, jeśli aktywny demon init ładuje właśnie to zadanie, jego sekcja `script` lub `exec` działa z wyższymi uprawnieniami, a użytkownik może je uruchomić za pomocą dozwolonego polecenia `initctl` lub innego rzeczywistego wyzwalacza. Samo uprawnienie sudo do `initctl` nie dowodzi, że którykolwiek plik zadania jest zapisywalny ani że zmodyfikowane zadanie zostanie uruchomione. Sprawdź uprawnienia dokładnego pliku zadania, efektywne ustawienie run-as, aktywny demon i wyzwalacz; podczas enumeracji nie edytuj ani nie uruchamiaj zadania. Zobacz dokumentację [konfiguracji zadań Upstart](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) i [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Czytelny plik hasła autologowania, taki jak `/etc/autologin/passwd` w systemach, których [zadanie rozruchowe odczytuje dokładnie tę ścieżkę](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), wskazuje na możliwe ujawnienie poświadczeń. Potwierdź, że zadanie rozruchowe jest zainstalowane i korzysta z tego pliku, a następnie osobno sprawdź, czy hasło jest prawidłowe dla innego konta lokalnego lub usługi. Sama nazwa pliku nie dowodzi ponownego użycia hasła; zapisuj ścieżkę i metadane dostępu, nie umieszczając hasła we współdzielonych wynikach enumeracji.

`ExecStart=` jednostki lub zaplanowane polecenie może ujawnić dokładną ścieżkę skryptu w katalogu, którego zawartości nie można wyświetlić. [Uprawnienie do przeszukiwania katalogu](https://man7.org/linux/man-pages/man7/path_resolution.7.html) może mimo to pozwalać bieżącej tożsamości przejść znaną ścieżką; sprawdź uprawnienia do przeszukiwania każdego katalogu nadrzędnego oraz uprawnienia do odczytu pliku, zamiast zakładać, że nieudane wyświetlenie zawartości katalogu chroni jego pliki. Czytelny skrypt może zawierać poświadczenie transferowe, ale użycie go do uzyskania dostępu do innego konta wymaga, by nadal było ważne i było niezależnie akceptowane przez to konto. Zapisuj ścieżkę i informacje o uprawnieniach, nie umieszczając tajnych wartości we współdzielonych logach.

W przypadku zaplanowanego skryptu CommonJS Node.js sprawdź niekwalifikowane importy, takie jak `require('package')`, nawet jeśli sam skrypt jest tylko do odczytu. [Node szuka `node_modules` obok pliku importującego, a następnie w jego katalogach nadrzędnych](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), zanim przejdzie do skonfigurowanych ścieżek globalnych. Użytkownik o niższych uprawnieniach, który może **zapisywać w jednym z tych katalogów nadrzędnych i go przeszukiwać**, może być w stanie utworzyć pakiet, który zostanie znaleziony wcześniej. Potwierdź, że dany import jest wykonywany, wybrany pakiet nie jest modułem wbudowanym, można utworzyć lub zmienić odpowiednią ścieżkę, moduł zostanie tam odnaleziony przez zainstalowane środowisko uruchomieniowe, a zadanie o wyższych uprawnieniach załaduje go przy przyszłym uruchomieniu. Zapisowalne metadane katalogu nadrzędnego to tylko wskazówka do analizy; sprawdź skrypt i harmonogram pasywnie, nie umieszczając modułu ani nie wyzwalając zadania.

Prywatny indeks pakietów Python stanowi kolejną granicę zaufania, gdy zautomatyzowane zadanie instaluje pakiety z użyciem innej tożsamości systemu operacyjnego. Powiąż dokładne zadanie i konto run-as ze skonfigurowanym indeksem, wybranymi nazwami pakietów oraz możliwością publikowania lub zastępowania pakietu przez użytkownika o niższych uprawnieniach, który zadanie faktycznie zainstaluje. Budowanie dystrybucji źródłowej może uruchomić backend budowania lub starszy `setup.py` z uprawnieniami instalatora; import zainstalowanego pakietu to odrębna ścieżka wykonania. Sam nasłuchujący indeks, czytelny hash hasła do przesyłania plików lub nazwa pliku pakietu nie dowodzą istnienia takiego łańcucha. Przeanalizuj zadanie, autoryzację indeksu i pochodzenie pakietu, nie przesyłając ani nie instalując niczego podczas enumeracji. Zobacz [interfejs systemu budowania pip](https://pip.pypa.io/en/stable/reference/build-system/) i [wskazówki dotyczące bezpiecznej instalacji](https://pip.pypa.io/en/stable/topics/secure-installs/).

Uprzywilejowany agent może odpytywać kolejkę zadań zarządzaną przez osobną usługę WWW lub kontener. Jeśli tożsamość o niższym poziomie zaufania może zapisywać bazę danych zadań tej usługi, ustal, czy te rekordy są faktycznie udostępniane agentowi i czy zadanie polecenia działa z tożsamością systemu operacyjnego agenta. Osobno potwierdź dostęp do zapisu w bazie danych, docelową sesję lub klucz routingu, aktywne odpytywanie, autoryzację zadań i efektywnego użytkownika agenta. Uprawnienia roota wewnątrz kontenera same w sobie nie oznaczają dostępu roota do hosta; granica zostaje przekroczona tylko wtedy, gdy uprzywilejowany proces hosta wykonuje kontrolowane przez atakującego dane zadania. Sprawdź metadane procesów, pliku bazy danych i usługi, nie modyfikując kolejki ani nie wysyłając zadania podczas enumeracji.

Zamiast tego cykliczne zadanie może odczytywać polecenie z wiersza konfiguracji w bazie danych aplikacji. Potwierdź, że rola bazy danych o niższych uprawnieniach może zmienić dokładnie ten wiersz, aktywne zadanie odczytuje go po zmianie, a wartość trafia do powłoki lub równoważnego mechanizmu uruchamiania poleceń działającego z wyższą tożsamością systemu operacyjnego. Sam dostęp do zapisu w bazie danych lub wartość wyglądająca jak polecenie nie dowodzą wykonania; analizuj zadanie i uprawnienia, nie zmieniając wiersza podczas pasywnej enumeracji.

Kolejka może też zawierać adres URL zamiast kodu. Jeśli uprzywilejowany konsument pobiera ten adres URL i ładuje odpowiedź jako plugin Lua lub inny wykonywalny plugin, zweryfikuj uprawnienia wydawcy do dokładnego exchange i klucza routingu, powiązanie z odbieraną kolejką, ścieżkę pobierania i ładowania pluginu oraz efektywną tożsamość workera. [RabbitMQ kieruje opublikowane wiadomości przez exchanges](https://www.rabbitmq.com/docs/exchanges); sam nasłuch brokera lub prawidłowe dane logowania nie dowodzą dostarczenia wiadomości do tego workera. Przechwycone jawne dane logowania do brokera to osobna wskazówka, która wymaga rzeczywistego dostępu do przechwytywania pakietów i czytelnego ruchu; nie dowodzą one uprawnień do publikowania. Plugin Lua może wywoływać polecenia powłoki przez [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) tylko wtedy, gdy to API jest dostępne w jego środowisku uruchomieniowym. Analizuj konfigurację i kod, nie przechwytując ruchu, nie publikując wiadomości ani nie pobierając pluginu podczas pasywnej enumeracji.

Gdy uprzywilejowana usługa Python udostępnia lokalny punkt końcowy HTTP lub gniazdo, czytelny skrypt może ujawnić ścieżkę od danych wejściowych do kodu, nawet jeśli uprawnienia pliku uniemożliwiają jego modyfikację. Powiąż aktywny proces i tożsamość jednostki z dokładnym skryptem, nasłuchem, autoryzacją trasy i polami kontrolowanymi przez wywołującego. Następnie prześledź te pola przez parsowanie i walidację aż do dynamicznego miejsca wywołania `eval()` lub `exec()`. W szczególności utworzenie nowego f-stringa z tekstu żądania i jego ewaluacja może interpretować podstawiane pola dostarczone przez atakującego jako wyrażenia Python ([ostrzeżenie dotyczące Python `eval`](https://docs.python.org/3/library/functions.html#eval); [semantyka f-stringów](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Samo wystąpienie `eval` lub nasłuch na loopback nie dowodzą, że niezaufany wywołujący dociera do tego miejsca; analizuj rzeczywisty przepływ danych i kontrolę dostępu, nie wysyłając testowego payloadu podczas enumeracji.

Bramka oparta na podpisanym żądaniu na tej trasie wymaga osobnej analizy. Jeśli czytelny kod źródłowy wyznacza klucz podpisu z demonstracyjnie małej lub przewidywalnej przestrzeni wyników, a usługa udostępnia prawidłowo podpisaną próbkę, podpis może już nie chronić uprzywilejowanego miejsca `eval()`. Zweryfikuj dokładne wyznaczanie klucza i weryfikator, tożsamość działającej usługi i lokalny dostęp wywołującego oraz to, czy podpisane pole trafia do tego miejsca; sam import modułu Python [`random`](https://docs.python.org/3/library/random.html) ani próbny podpis niczego z tych warunków nie dowodzą. Python ostrzega również, że ograniczenie `__builtins__` [nie stanowi granicy bezpieczeństwa dla niezaufanych danych wejściowych `eval()`](https://docs.python.org/3/library/functions.html#eval). Analizuj klucze offline i nie wysyłaj sfałszowanych żądań podczas pasywnej enumeracji.

Pusty, ale zapisywalny katalog `/etc/systemd/system/<unit>.service.d` ma znaczenie, nawet jeśli plik jednostki i wszystkie istniejące drop-iny są chronione: użytkownik może utworzyć nowe nadpisanie `.conf`. Sprawdź, czy bieżąca tożsamość może zapisywać w katalogu i go przeszukiwać, czy jednostka jest załadowana i działa jako root oraz czy nastąpi ponowne załadowanie demona, a następnie restart. Uprawnienie do ponownego załadowania lub restartu, timer albo późniejszy rozruch mogą uaktywnić zmianę; sam dostęp do zapisu w katalogu nie powoduje jej natychmiastowego wykonania.

W przypadku działających usług sprawdź literalne ścieżki `EnvironmentFile=` z sekcji `[Service]` jednostki, także te, których nazwy nie zaczynają się od `.env`. Jeśli użytkownik o niskich uprawnieniach może odczytać któryś z tych plików, wypisz nazwy kluczy przypominających poświadczenia, takie jak `API_TOKEN` lub `APP_SECRET_KEY`, ale nie umieszczaj ich wartości we współdzielonych logach. Przy ustalaniu efektywnej konfiguracji jednostki sprawdź nadpisania drop-in i opcjonalny prefiks `-`. Możliwość odczytu wskazuje na możliwe ujawnienie poświadczeń; wartość musi być nadal ważna i umożliwiać uprzywilejowane działanie, by prowadziła do eskalacji.

### Uprzywilejowane przetwarzanie niezaufanych przesłanych plików

Watcher plików działający jako root może przekazywać pliki z zapisywalnego przez użytkownika katalogu przesyłania do krótkotrwałego parsera lub programu rozpakowującego. Prześledź skrypt nadrzędny lub usługę działającego watchera i potwierdź dokładny katalog, kto może umieszczać w nim pliki, polecenie potomne wraz z argumentami oraz tożsamość, z jaką działa proces potomny. Migawka procesów może pokazać watchera, ale nie wykryć procesu rozpakowującego między przesłaniami. Podczas pasywnej enumeracji nie umieszczaj testowego payloadu ani nie wyzwalaj watchera.

Konkretnym przykładem jest tryb rozpakowywania Binwalk (`-e`) przetwarzający kontrolowane przez atakującego dane PFS. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) pozwalał ekstraktorowi PFS zapisywać pliki poza przeznaczonym katalogiem, w tym w ścieżce pluginu, który Binwalk mógł później załadować. Projekt macierzysty uwzględnił poprawkę w wersji [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), ale poprawki backportowane przez dystrybucje mogą występować w starszej wyświetlanej wersji; przed oceną podatności sprawdź status bezpieczeństwa zainstalowanego pakietu, na przykład w [trackerze Debiana](https://security-tracker.debian.org/tracker/CVE-2022-4510). Sama zainstalowana wersja Binwalk nie dowodzi istnienia ścieżki eskalacji uprawnień: bardziej uprzywilejowany proces musi faktycznie uruchamiać rozpakowywanie na danych, które użytkownik o niższych uprawnieniach może kontrolować.

### Zaplanowane kompilacje z lokalnymi zależnościami

Zaplanowane `cargo run` ponownie kompiluje kod źródłowy jako użytkownik run-as zadania. Sprawdź lokalne zależności `{ path = "..." }` w manifeście oraz uprawnienia do kodu źródłowego i katalogów nadrzędnych każdej zależności, a nie tylko głównego crate. Jeśli użytkownik o niższych uprawnieniach może zmodyfikować zależność kompilowaną przez Cargo, a zaplanowane zadanie uruchamia wynik kompilacji, skompilowany kod może działać jako ten użytkownik run-as. Potwierdź efektywne polecenie harmonogramu, katalog roboczy, rozwiązywanie zależności i to, czy nastąpi ponowna kompilacja; zapisywalny plik źródłowy Rust w innym miejscu to tylko wskazówka. Do wstępnej pasywnej analizy wystarczy odczytanie manifestu i metadanych ścieżek. Zobacz [dokumentację zależności ścieżkowych Cargo](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Pliki framebuffera Xvfb

`Xvfb -fbdir <directory>` używa plików mapowanych do pamięci o nazwach `Xvfb_screen<n>` dla swoich wirtualnych ekranów. Jeśli działający proces Xvfb innego użytkownika wskazuje katalog, którego pliki ekranów są czytelne dla bieżącego użytkownika, framebuffer może ujawniać zawartość pulpitu tego użytkownika. Potwierdź jednocześnie proces, właściciela plików i uprawnienia; sama możliwość odczytu pliku nie dowodzi, że na ekranie znajduje się użyteczna zawartość. Najpierw sprawdź ścieżki i metadane, nie kopiując danych obrazu do współdzielonych wyników enumeracji. [Podręcznik Xvfb](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) opisuje działanie opcji `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Podręcznik Linux `shmget(2)`](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Podręcznik Linux `ipcs(1)`](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [Podręcznik OpenBSD `ipcs(1)`](https://man.openbsd.org/ipcs.1)
4. [Konfiguracja agenta Consul: kontrole skryptowe](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [API rejestracji usług agenta Consul](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Konfiguracja ACL Consul](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [Pomoc LibreOffice: otwieranie gniazda dla zewnętrznych klientów API](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
