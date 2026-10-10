# Enumerowanie procesów i ścieżki usług

{{#include ../../banners/hacktricks-training.md}}

Przydatne pytanie brzmi: który proces z podwyższonymi uprawnieniami przetwarza dane lub kod, na które może wpływać użytkownik o niższych uprawnieniach? Sprawdź drzewo procesów, aktywne środowisko, otwarte pliki oraz jednostkę lub skrypt, który uruchomił każdy z potencjalnych procesów.

## Mapowanie procesów i właścicieli

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Relacja rodzic–dziecko między różnymi użytkownikami może być normalna, ale nieoczekiwana zmiana wymaga sprawdzenia polecenia procesu nadrzędnego, argumentów, pliku wykonywalnego, katalogu roboczego i wskazanych plików. Skorzystaj z informacji o [użytkownikach i sesjach](../user-information/user-and-session-triage.md), aby zinterpretować właściciela i kontekst logowania.

### Lokalne konsole maszyn wirtualnych

Sprawdź opcje `-spice` procesu QEMU wraz z adresem nasłuchu. [Dokumentacja QEMU](https://www.qemu.org/docs/master/system/qemu-manpage.html) informuje, że `disable-ticketing` pozwala klientom SPICE łączyć się bez uwierzytelniania. Listener nasłuchujący na loopback nadal może być dostępny dla innych lokalnych użytkowników hosta. Przed uznaniem wiersza poleceń za odsłoniętą konsolę potwierdź aktywny listener, opcje uwierzytelniania i lokalny dostęp. Sterowanie konsolą dotyczy **maszyny gościa**; uzyskanie konta w systemie gościa lub zmiana jego stanu rozruchu wymaga odrębnych warunków po stronie gościa i nie zapewnia uprawnień root na hoście wirtualizacji. Podczas pasywnej enumeracji odczytuj argumenty procesu i metadane gniazda, nie łącząc się z maszyną gościa ani jej nie uruchamiając ponownie.

Lokalnie dostępny interfejs WWW może wykonywać kod z uprawnieniami konta usługi, nawet jeśli początkowa powłoka nie ma dostępu do plików tego konta. Na przykład CVE-2023-0297 dotyczyło obsługi `/flash/addcrypted2` w pyLoad, gdy niezaufany JavaScript trafiał do Js2Py z włączonymi importami Pythona; [poprawka upstream](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) wyłączyła `pyimport`. Zanim uznasz proces pyLoad za potencjalną ścieżkę eskalacji, zestaw informacje o właścicielu działającego procesu, adresie nasłuchu, dostępności endpointu oraz zainstalowanej poprawce lub poprawce backportowanej przez dostawcę. Sama nazwa procesu, otwarty port lub wersja pakietu nie dowodzą podatności; podczas pasywnej enumeracji nie wysyłaj payloadu wykonującego kod.

### Uprzywilejowane powłoki logowania współdzielące terminal

Uprzywilejowana powłoka interaktywna, która uruchamia `su --login <user>` bez niezależnego pseudo-terminala, może współdzielić terminal z powłoką logowania użytkownika o niższych uprawnieniach. Jeśli ten użytkownik może modyfikować swój plik startowy, a kod w nim może używać `TIOCSTI` do wstrzykiwania danych wejściowych do terminala, dane te mogą dotrzeć do uprzywilejowanej powłoki po jej wznowieniu. [Podręcznik util-linux `su`](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) opisuje ryzyko współdzielonego terminala i zaleca `su --pty`/`-P` do użytku interaktywnego; `su -c` rozpoczyna osobną sesję bez terminala sterującego. Ryzyko zależy od rzeczywistej powłoki nadrzędnej, relacji terminali, docelowego pliku startowego i polityki jądra. Sama nazwa procesu lub argument `su -l` to jedynie wskazówka do dalszej analizy.

Sprawdź zaobserwowane drzewo procesów i kolumny TTY, a następnie czytelny skrypt uruchamiający oraz właściciela i uprawnienia pliku startowego. W Linuksie `/proc/sys/dev/tty/legacy_tiocsti`, jeśli istnieje, może pomóc w interpretacji polityki; jego brak nie dowodzi bezpieczeństwa. [Podręcznik Linuksa `TIOCSTI`](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) wskazuje, że od Linuksa 6.2 ta operacja może wymagać `CAP_SYS_ADMIN`, gdy ten sysctl ma wartość false. Nie wywołuj ioctl wyłącznie w celu enumeracji hosta.

Konto bazy danych może czasem zmienić plik startowy docelowego użytkownika bez bezpośredniego dostępu do zapisu w systemie plików. Po stronie serwera PostgreSQL `COPY ... TO 'filename'` zapisuje plik z uprawnieniami konta systemowego serwera bazy danych, ale [ograniczenia PostgreSQL](https://www.postgresql.org/docs/current/sql-copy.html) pozwalają na tę postać polecenia tylko superużytkownikom bazy danych lub rolom takim jak `pg_write_server_files`. Potwierdź zarówno rolę bazy danych, jak i uprawnienia do plików po stronie systemu operacyjnego serwera; sam ciąg połączenia aplikacji nie zapewnia uprawnień do zapisu plików. Oceniając tę ścieżkę, traktuj uprawnienia uprzywilejowanego skryptu uruchamiającego i możliwości konta bazy danych jako odrębne kwestie.

## Inspect runtime artifacts

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Usunięte pliki wykonywalne i usunięte, ale nadal otwarte pliki pozostają dostępne aż do zamknięcia ostatniego deskryptora. Mogą zachowywać ślady lub dostępne sekrety. Środowiska procesów i pamięć mogą zawierać dane uwierzytelniające, ale odczytanie danych innego procesu podlega ograniczeniom wynikającym z właściciela, opcji montowania `/proc`, polityki Yama ptrace i innych mechanizmów bezpieczeństwa. Zobacz [deskryptory plików](../main-system-information/filesystem-links-and-file-descriptors.md) i [wyszukiwanie danych uwierzytelniających po eksploatacji](../post-exploitation/README.md), aby poznać powiązane techniki.

Zapisane ślady wywołań systemowych podlegają również ograniczeniom uprawnień do plików. [`strace` zapisuje argumenty wywołań systemowych do pliku wyjściowego](https://man7.org/linux/man-pages/man1/strace.1.html), więc czytelny ślad argumentów [`execve`](https://man7.org/linux/man-pages/man2/execve.2.html) może ujawnić hasło przekazane w wierszu poleceń przez zadanie z podwyższonymi uprawnieniami. Najpierw ustal, czy bieżący użytkownik może odczytać konkretny ślad i czy argument rzeczywiście zawiera dane uwierzytelniające; osobno trzeba potwierdzić, że te dane są akceptowane przy późniejszym przejściu na konto Unix. Metadane plików mogą być użyteczną, pasywną wskazówką, bez skanowania wszystkich śladów ani wyświetlania ich zawartości podczas rutynowej enumeracji.

## Gniazda uprzywilejowanej automatyzacji biurowej

LibreOffice i OpenOffice mogą udostępniać swoje API UNO za pomocą argumentu `--accept=socket,host=<host>,port=<port>;urp;`. Proces pakietu biurowego działający jako root i mający osiągalny endpoint może pozwolić lokalnemu użytkownikowi o niższych uprawnieniach na wywoływanie usług API w kontekście bezpieczeństwa tego procesu. Usługa `SystemShellExecute` obejmuje operację uruchamiania polecenia systemowego. Powiązanie z loopback ogranicza dostępność zdalną, ale gniazdo nadal jest dostępne dla lokalnych użytkowników, chyba że inny mechanizm kontroli blokuje dostęp.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Skoreluj właściciela procesu, dokładny argument `--accept` oraz aktualny nasłuchujący adres i port. Skonfigurowany acceptor, który nie zdołał powiązać się z adresem, jest jedynie wskazówką; podczas pasywnego rozpoznania nie łącz się z API ani go nie wywołuj. Unikaj uruchamiania uprzywilejowanej instancji pakietu biurowego wyłącznie po to, by sprawdzić ten warunek.

## Pamięć współdzielona System V używana przez uprzywilejowane procesy

Pomocnik działający jako root może utworzyć segment pamięci współdzielonej System V, do którego zapisu może dokonywać inny użytkownik. Jeśli pomocnik później zaufa danym z tego segmentu podczas wykonywania polecenia powłoki lub innej wrażliwej operacji, segment przekracza granicę uprawnień, nawet jeśli plik wykonywalny i jego pliki są chronione. `shmget()` pobiera uprawnienia dostępu z dziewięciu najmłodszych bitów swoich flag; tryb `0666` zezwala innym użytkownikom na zapis, podczas gdy flaga `IPC_CREAT` nie ogranicza tych uprawnień. Pasywnie sprawdzaj aktywne segmenty za pomocą `ipcs -m` i koreluj ich właściciela, tryb oraz czas istnienia z uprzywilejowanym procesem i sposobem obsługi jego danych wejściowych. Sam segment z prawem zapisu dla wszystkich nie dowodzi możliwości wykonania polecenia.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

Segmenty System V różnią się od plików pamięci współdzielonej POSIX w `/dev/shm`. Segment utworzony tylko na chwilę może nie być widoczny w pojedynczym zrzucie `ipcs`, więc pusty wynik nie wyklucza używania pamięci współdzielonej przez program pomocniczy. Sprawdź kod źródłowy lub zachowanie pliku binarnego oraz wszelkie reguły `sudo`, które go uruchamiają; nie uruchamiaj uprzywilejowanego programu pomocniczego tylko po to, by podczas enumeracji pojawił się segment. [Przewodnik po przestrzeniach nazw IPC](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) wyjaśnia, jak przestrzenie nazw wpływają na widoczność.<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent script checks

Consul może uruchamiać skryptowe kontrole kondycji z tożsamością systemową swojego agenta. Jeśli agent działa jako root, ma włączone `enable_script_checks` i pozwala użytkownikowi o niższych uprawnieniach zarejestrować usługę z kontrolą skryptową za pośrednictwem lokalnego HTTP API, taki użytkownik może spowodować uruchomienie poleceń jako root. Powiązanie API tylko z `127.0.0.1` nadal pozwala lokalnym użytkownikom uzyskać do niego dostęp. Ustawienie `enable_local_script_checks` ma węższy zakres: wyklucza kontrole skryptowe przesyłane w ramach rejestracji przez HTTP API. Gdy ACL Consul są włączone, rejestracja usługi wymaga uprawnienia `service:write`; sam wpis `acl.default_policy=allow` nie dowodzi, że anonimowy użytkownik może zarejestrować usługę. Sprawdź łącznie tożsamość agenta, załadowane ustawienia, powiązanie API i autoryzację.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Śledź argumenty `-config-dir` i `-config-file` działającego agenta, aby dotrzeć do odpowiedniej konfiguracji, i sprawdź wyłącznie nazwy pól oraz ustawienia dotyczące kontroli skryptów i ACL. Pliki konfiguracyjne mogą również zawierać klucze gossip lub tokeny; nie wklejaj ich do udostępnianych logów. Nie rejestruj usługi ani nie uruchamiaj kontroli stanu wyłącznie po to, by wykryć tę możliwość.

Istnieje też lokalny wariant wykorzystujący plik, gdy użytkownik o niższych uprawnieniach może **zapisywać w katalogu wskazanym przez `-config-dir` agenta uruchomionego jako root i przeszukiwać ten katalog**: nowa definicja usługi `.hcl` lub `.json` może zostać wczytana z tego katalogu. Możliwość przeszukiwania i zapisu w katalogu może pozwolić na dodanie pliku, nawet gdy odmawia się wyświetlenia jego zawartości. Aby doszło do wykonania polecenia z uprawnieniami roota, potwierdź, że agent rzeczywiście wczytuje ten katalog, jego **efektywne** ustawienie `script-check` zezwala na lokalne definicje, definicja została wczytana, a agent zachowuje uprawnienia roota. [Dokumentacja Consul](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) opisuje, które ustawienia i definicje kontroli stanu można przeładować; samo włączenie kontroli skryptów może wymagać ponownego uruchomienia, więc zweryfikuj zachowanie zainstalowanej wersji. Gdy agenta chronią ACL, [`consul reload` wymaga `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); samo uprawnienie do zapisu KV go nie zapewnia. Potraktuj informację o zapisywalności katalogu jako wskazówkę do weryfikacji, a nie dowód na autoryzowane przeładowanie, ponowne uruchomienie lub wykonanie polecenia. Sprawdź ścieżki, uprawnienia i politykę bez zapisywania konfiguracji ani wywoływania API.

## Prześledź łańcuch wykonywania usługi

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Sprawdź unit, drop-ins, `EnvironmentFile=`, skrypty pomocnicze, polecenia względne, zapisywalne katalogi i aktywację przez socket. Unit należący do roota nadal może być niebezpieczny, jeśli odczytuje konfigurację lub skrypt, który użytkownik może modyfikować. Strona [arbitrary file write](../interesting-files-permissions/write-to-root.md) omawia typowe ścieżki nadużyć związane z usługami i unitami. Monitoruj krótkotrwałe zadania za pomocą [pspy](https://github.com/DominicBreuker/pspy) lub telemetrii audytowej/procesowej, gdy pojedyncze wywołanie `ps` ich nie wykrywa.

W przypadku niestandardowej usługi **xinetd** skoreluj włączony wpis `server`, `user` i ustawienia kontroli dostępu z aktywnym listenerem oraz dokładnym plikiem wykonywalnym. Ustawienie [`user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) określa tożsamość uruchamianego procesu, a bit set-user-ID pliku wykonywalnego może niezależnie zmienić jego efektywną tożsamość, jeśli [`execve` zezwala na taką zmianę](https://man7.org/linux/man-pages/man2/execve.2.html). Dostępny z sieci uprzywilejowany plik binarny, który przyjmuje niezaufane dane wejściowe, warto przeanalizować offline pod kątem błędów bezpieczeństwa pamięci, takich jak nieograniczona konwersja ciągu znaków przez [`scanf`](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) do bufora o stałym rozmiarze. Mapowanie usługi i metadane set-user-ID są wskazówkami, a nie dowodem istnienia takiego błędu; podczas pasywnej enumeracji nie wysyłaj danych powodujących awarię ani nie debuguj działającej uprzywilejowanej usługi.

W przypadku niestandardowego uprzywilejowanego listenera, którego kod źródłowy jest dostępny do odczytu, przeanalizuj każdą długość kontrolowaną przez wywołującego, używaną przez operację kopiowania, taką jak [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Samo sprawdzenie, że bieżący indeks zapisu mieści się w buforze o stałym rozmiarze, nie dowodzi, że **długość kopiowania** mieści się w pozostałym miejscu; po potwierdzeniu, że indeks mieści się w zakresie, sprawdź warunek `copy_length <= capacity - index`, a także znakowość typów i przepełnienie arytmetyczne. Ta wskazówka ma znaczenie wyłącznie wtedy, gdy dane wejściowe docierają do tej operacji, listener jest dostępny dla użytkownika o niższych uprawnieniach, a proces zachowuje wyższą efektywną tożsamość. Analizuj kod źródłowy i metadane procesu offline; podczas enumeracji nie wysyłaj do działającej usługi danych powodujących awarię.

W systemach korzystających z **Upstart** definicje zadań systemowych mogą znajdować się w `/etc/init/*.conf`. Plik zadania, który może modyfikować bieżący użytkownik, ma znaczenie, jeśli aktywny demon init ładuje dokładnie ten plik, jego wpis `script` lub `exec` działa z wyższymi uprawnieniami, a użytkownik może uruchomić zadanie za pomocą dozwolonego polecenia `initctl` lub innego rzeczywistego wyzwalacza. Samo uprawnienie sudo do `initctl` nie dowodzi, że jakikolwiek plik zadania można modyfikować ani że zmodyfikowane zadanie zostanie uruchomione. Sprawdź uprawnienia dokładnego pliku zadania, efektywne ustawienie użytkownika uruchamiającego, aktywny demon i wyzwalacz, nie edytując ani nie uruchamiając zadania podczas enumeracji. Zobacz podręczniki [konfiguracji zadań Upstart](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) i [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Plik z hasłem autologin dostępnym do odczytu, taki jak `/etc/autologin/passwd` w systemach, których [zadanie rozruchowe odczytuje dokładnie tę ścieżkę](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), może wskazywać na ujawnienie poświadczeń. Potwierdź, że zadanie rozruchowe jest zainstalowane i korzysta z tego pliku, a następnie osobno sprawdź, czy hasło jest prawidłowe dla innego konta lokalnego lub usługi. Sama nazwa pliku nie dowodzi ponownego użycia hasła; zapisuj ścieżkę i metadane dostępu, nie umieszczając hasła we współdzielonych wynikach enumeracji.

`ExecStart=` w unicie lub zaplanowane polecenie może ujawnić dokładną ścieżkę do skryptu w katalogu, którego nie można wylistować. [Uprawnienie do przeszukiwania katalogu](https://man7.org/linux/man-pages/man7/path_resolution.7.html) może nadal pozwalać bieżącej tożsamości przejść do tej znanej ścieżki; sprawdź uprawnienie do przeszukiwania każdego katalogu nadrzędnego oraz uprawnienie do odczytu pliku, zamiast zakładać, że nieudane wylistowanie katalogu chroni jego zawartość. Czytelny skrypt może zawierać poświadczenie transferowe, ale dostęp do innego konta wymaga, by poświadczenie nadal było ważne i zostało niezależnie zaakceptowane na tym koncie. Zapisuj ścieżkę i dowody dotyczące uprawnień, nie ujawniając poufnych wartości we współdzielonych logach.

W przypadku zaplanowanego skryptu CommonJS Node.js sprawdzaj niekwalifikowane importy, takie jak `require('package')`, nawet jeśli sam skrypt jest tylko do odczytu. [Node szuka katalogów `node_modules` obok pliku importującego, a następnie w jego katalogach nadrzędnych](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), zanim przejdzie do skonfigurowanych ścieżek globalnych. Użytkownik o niższych uprawnieniach, który może **zapisywać i przeszukiwać** jeden z tych katalogów nadrzędnych, może być w stanie utworzyć pakiet, który zostanie znaleziony wcześniej. Potwierdź, że dany import jest wykonywany, wybrany pakiet nie jest modułem wbudowanym, odpowiednią ścieżkę można utworzyć lub zmienić, moduł zostanie tam znaleziony przez zainstalowane środowisko uruchomieniowe, a zadanie z wyższymi uprawnieniami załaduje go przy przyszłym uruchomieniu. Zapisowalne metadane katalogu nadrzędnego to tylko wskazówka do analizy; sprawdź pasywnie skrypt i harmonogram, nie umieszczając modułu ani nie wyzwalając zadania.

Prywatny indeks pakietów Python to kolejna granica zaufania, gdy zautomatyzowane zadanie instaluje pakiety z użyciem innej tożsamości systemu operacyjnego. Powiąż dokładne zadanie i konto, z którego jest uruchamiane, ze skonfigurowanym indeksem, wybranymi nazwami pakietów oraz możliwością publikowania lub podmieniania pakietu przez użytkownika o niższych uprawnieniach — pod warunkiem, że zadanie faktycznie go zainstaluje. Budowanie dystrybucji źródłowej może uruchomić jej backend kompilacji lub starszy `setup.py` z uprawnieniami instalatora; import zainstalowanego pakietu to osobna ścieżka wykonania. Listener indeksu, czytelny hash hasła do przesyłania lub sama nazwa pliku pakietu nie dowodzą istnienia takiego łańcucha. Przeanalizuj zadanie, autoryzację indeksu i pochodzenie pakietu, nie przesyłając ani nie instalując niczego podczas enumeracji. Zobacz [interfejs systemu kompilacji pip](https://pip.pypa.io/en/stable/reference/build-system/) i [wskazówki dotyczące bezpiecznej instalacji](https://pip.pypa.io/en/stable/topics/secure-installs/).

Uprzywilejowany agent może odpytywać kolejkę zadań zarządzaną przez oddzielną usługę webową lub kontener. Jeśli tożsamość o niższym poziomie zaufania może zapisywać bazę danych zadań usługi, ustal, czy te rekordy są faktycznie udostępniane agentowi i czy zadanie typu command działa z tożsamością systemu operacyjnego agenta. Osobno potwierdź dostęp do zapisu bazy danych, docelową sesję lub klucz routingu, aktywne odpytywanie, autoryzację zadań i efektywnego użytkownika agenta. Root wewnątrz kontenera sam w sobie nie oznacza dostępu do hosta jako root; granica zostaje przekroczona dopiero wtedy, gdy uprzywilejowany względem hosta konsument wykonuje dane zadania kontrolowane przez atakującego. Sprawdź metadane procesów, pliku bazy danych i usługi, nie modyfikując kolejki ani nie wysyłając zadań podczas enumeracji.

Zamiast tego cykliczne zadanie może odczytywać polecenie z wiersza konfiguracji w bazie danych aplikacji. Potwierdź, że rola bazy danych o niższych uprawnieniach może zmienić dokładnie ten wiersz, aktywne zadanie odczyta go po zmianie, a wartość trafi do powłoki lub równoważnego mechanizmu uruchamiania poleceń z uprawnieniami wyższej tożsamości systemu operacyjnego. Dostęp do zapisu w bazie danych ani sama wartość przypominająca polecenie nie dowodzą wykonania; przeanalizuj zadanie i uprawnienia, nie zmieniając wiersza podczas pasywnej enumeracji.

Kolejka może też zawierać URL zamiast kodu. Jeśli uprzywilejowany konsument pobiera ten URL i ładuje odpowiedź jako plugin Lua lub inny plugin wykonywalny, sprawdź uprawnienia wydawcy dotyczące dokładnego exchange i routing key, powiązanie z konsumowaną kolejką, ścieżkę pobierania i ładowania pluginu oraz efektywną tożsamość workera. [RabbitMQ routuje publikowane wiadomości przez exchange](https://www.rabbitmq.com/docs/exchanges); sam listener brokera lub prawidłowe dane logowania nie dowodzą dostarczenia wiadomości do tego workera. Przechwycone jawne poświadczenia brokera to osobna wskazówka, która wymaga faktycznego dostępu do przechwytywania pakietów i czytelnego ruchu; nie dowodzą one uprawnień do publikowania. Plugin Lua może uruchamiać polecenia powłoki za pomocą [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) tylko wtedy, gdy to API jest dostępne w jego środowisku uruchomieniowym. Sprawdź konfigurację i kod bez przechwytywania ruchu, publikowania wiadomości ani pobierania pluginu podczas pasywnej enumeracji.

Gdy uprzywilejowana usługa Python udostępnia lokalny endpoint HTTP lub socket, czytelny skrypt może ujawniać ścieżkę od danych wejściowych do kodu, nawet jeśli jego uprawnienia uniemożliwiają modyfikację. Powiąż aktywny proces i tożsamość unitu z dokładnym skryptem, listenerem, autoryzacją trasy i polami kontrolowanymi przez wywołującego. Następnie prześledź te pola przez parsowanie i walidację aż do dynamicznego miejsca użycia `eval()` lub `exec()`. W szczególności utworzenie nowego f-stringa z tekstu żądania i jego ewaluacja może zinterpretować dostarczone przez atakującego pola podstawień jako wyrażenia Python ([ostrzeżenie dotyczące `eval` w Pythonie](https://docs.python.org/3/library/functions.html#eval); [semantyka f-stringów](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Samo znalezienie `eval` lub powiązanie z loopbackiem nie dowodzi, że niezaufany wywołujący dociera do tego miejsca; przeanalizuj faktyczny przepływ danych i mechanizmy kontroli dostępu, nie wysyłając testowego payloadu podczas enumeracji.

Bramka podpisanych żądań na tej trasie wymaga osobnej analizy. Jeśli czytelny kod źródłowy pokazuje, że klucz podpisujący jest wyprowadzany z przestrzeni wyników, która jest wyraźnie mała lub przewidywalna, a usługa udostępnia prawidłowy podpisany przykład, podpis może już nie chronić uprzywilejowanego miejsca użycia `eval()`. Zweryfikuj dokładny sposób wyprowadzania klucza i weryfikator, tożsamość działającej usługi i dostęp lokalnego wywołującego oraz to, czy podpisane pole dociera do miejsca użycia; samo zaimportowanie modułu Python [`random`](https://docs.python.org/3/library/random.html) lub podpis przykładowego żądania nie dowodzi spełnienia żadnego z tych warunków. Python ostrzega też, że ograniczenie `__builtins__` [nie stanowi granicy bezpieczeństwa dla niezaufanych danych wejściowych `eval()`](https://docs.python.org/3/library/functions.html#eval). Analizuj klucz offline i nie wysyłaj sfałszowanych żądań podczas pasywnej enumeracji.

Pusty, ale zapisywalny katalog `/etc/systemd/system/<unit>.service.d` ma znaczenie, nawet jeśli plik unitu i wszystkie istniejące drop-ins są chronione: użytkownik może utworzyć nowe nadpisanie `.conf`. Sprawdź, czy bieżąca tożsamość może zapisywać i przeszukiwać katalog, czy unit jest załadowany i działa jako root oraz czy nastąpi ponowne przeładowanie demona, a następnie restart. Uprawnienie do przeładowania lub restartu, timer albo późniejszy rozruch mogą sprawić, że zmiana zacznie obowiązywać; sam dostęp do zapisu w katalogu nie wykonuje jej natychmiast.

W przypadku działających usług sprawdzaj literalne ścieżki `EnvironmentFile=` z sekcji `[Service]` unitu, także pliki, których nazwy nie zaczynają się od `.env`. Jeśli użytkownik o niskich uprawnieniach może odczytać taki plik, wypisz nazwy kluczy przypominających dane uwierzytelniające, takie jak `API_TOKEN` lub `APP_SECRET_KEY`, nie ujawniając ich wartości we współdzielonych logach. Podczas ustalania efektywnej konfiguracji unitu sprawdź drop-iny i opcjonalne prefiksy `-`. Możliwość odczytu wskazuje na potencjalne ujawnienie poświadczeń; aby doprowadzić do eskalacji, wartość musi nadal być prawidłowa i umożliwiać wykonanie uprzywilejowanej operacji.

### Uprzywilejowane przetwarzanie niezaufanych przesłanych plików

Watcher plików uruchomiony jako root może przekazywać pliki z zapisywalnego przez użytkownika katalogu przesyłania do krótkotrwałego parsera lub narzędzia do rozpakowywania. Prześledź nadrzędny skrypt lub usługę działającego watchera i ustal dokładny katalog, osoby mogące umieszczać w nim pliki, polecenie potomne i jego argumenty oraz tożsamość, z którą działa proces potomny. Migawka procesów może pokazać watchera, ale nie wykryć procesu rozpakowującego działającego między przesłaniami. Podczas pasywnej enumeracji nie umieszczaj testowego payloadu ani nie wyzwalaj watchera.

Konkretnym przykładem jest tryb rozpakowywania Binwalk (`-e`) przetwarzający dane PFS kontrolowane przez atakującego. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) umożliwiało extractorowi PFS zapis poza przeznaczonym dla niego katalogiem, w tym do ścieżki pluginu, który Binwalk mógł później załadować. Projekt upstream wprowadził poprawkę w wersji [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), ale backporty dystrybucji mogą zawierać poprawkę mimo wyświetlania starszej wersji; przed oceną możliwości wykorzystania sprawdź status bezpieczeństwa zainstalowanego pakietu, na przykład w [trackerze Debiana](https://security-tracker.debian.org/tracker/CVE-2022-4510). Sama zainstalowana wersja Binwalk nie dowodzi istnienia ścieżki eskalacji uprawnień: rozpakowywanie musi być faktycznie uruchamiane przez proces z wyższymi uprawnieniami na danych wejściowych kontrolowanych przez użytkownika o niższych uprawnieniach.

### Zaplanowane kompilacje z lokalnymi zależnościami

Zaplanowane polecenie `cargo run` ponownie kompiluje kod źródłowy jako użytkownik, z którego uprawnieniami uruchamiane jest zadanie. Sprawdź lokalne zależności `{ path = "..." }` w manifeście oraz uprawnienia do kodu źródłowego każdej zależności i jej katalogów nadrzędnych, a nie tylko głównego crate’a. Jeśli użytkownik o niższych uprawnieniach może zmodyfikować zależność, którą Cargo kompiluje, a zaplanowane zadanie uruchamia wynik tej kompilacji, skompilowany kod może działać z uprawnieniami użytkownika uruchamiającego zadanie. Potwierdź efektywne polecenie harmonogramu, katalog roboczy, rozwiązywanie zależności i to, czy nastąpi ponowna kompilacja; zapisywalny plik źródłowy Rust w innym miejscu to tylko wskazówka. Do wstępnej pasywnej analizy wystarczy odczytanie manifestu i metadanych ścieżek. Zobacz [dokumentację Cargo dotyczącą zależności ścieżkowych](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Pliki framebuffer Xvfb

`Xvfb -fbdir <directory>` używa plików mapowanych w pamięci o nazwach `Xvfb_screen<n>` dla swoich wirtualnych ekranów. Jeśli działający proces Xvfb innego użytkownika wskazuje katalog, którego pliki ekranów są czytelne dla bieżącego użytkownika, framebuffer może ujawniać zawartość pulpitu tego użytkownika. Potwierdź jednocześnie proces, właściciela pliku i jego uprawnienia; sam czytelny plik nie dowodzi, że na ekranie znajdują się przydatne dane. Najpierw sprawdź ścieżki i metadane, nie kopiując danych obrazu do współdzielonych wyników enumeracji. [Podręcznik Xvfb](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) opisuje działanie opcji `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Podręcznik Linux `shmget(2)`](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Podręcznik Linux `ipcs(1)`](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [Podręcznik OpenBSD `ipcs(1)`](https://man.openbsd.org/ipcs.1)
4. [Konfiguracja agenta Consul: kontrole skryptów](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [API rejestracji usług agenta Consul](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Konfiguracja ACL Consul](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [Pomoc LibreOffice: otwieranie gniazda dla zewnętrznych klientów API](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
