# Enumerowanie procesów i ścieżki usług

{{#include ../../banners/hacktricks-training.md}}

Warto ustalić, który proces z podwyższonymi uprawnieniami korzysta z danych lub kodu, na które może wpływać użytkownik o niższych uprawnieniach. Sprawdź drzewo procesów, bieżące środowisko, otwarte pliki oraz jednostkę lub skrypt, który uruchomił każdy z rozpatrywanych procesów.

## Mapowanie procesów i właścicieli

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

Relacja rodzic–dziecko między różnymi użytkownikami może być normalna, ale nieoczekiwana zmiana wymaga sprawdzenia polecenia rodzica, argumentów, pliku wykonywalnego, katalogu roboczego i wskazanych plików. Skorzystaj z informacji o [użytkownikach i sesjach](../user-information/user-and-session-triage.md), aby ustalić właściciela i kontekst logowania.

### Lokalne konsole maszyn wirtualnych

Sprawdź opcje `-spice` procesu QEMU w zestawieniu z adresem, na którym nasłuchuje. [Dokumentacja QEMU](https://www.qemu.org/docs/master/system/qemu-manpage.html) informuje, że `disable-ticketing` pozwala klientom SPICE łączyć się bez uwierzytelniania. Nasłuchiwanie na interfejsie loopback może być nadal osiągalne dla innych lokalnych użytkowników hosta. Zanim uznasz wiersz poleceń za ujawniający konsolę, potwierdź aktywne nasłuchiwanie, opcje uwierzytelniania i lokalny dostęp. Sterowanie konsolą wpływa na **guest**; uzyskanie konta w guest lub zmiana jego stanu rozruchu wymaga odrębnych warunków po stronie guest i nie daje uprawnień root na hoście wirtualizacji. Podczas pasywnego enumerowania odczytuj argumenty procesów i metadane gniazd, nie łącząc się z guest ani nie uruchamiając go ponownie.

Lokalnie dostępny interfejs webowy może wykonywać kod z uprawnieniami konta usługi, nawet jeśli pierwsza powłoka nie ma dostępu do plików tego konta. Na przykład CVE-2023-0297 dotyczyło obsługi `/flash/addcrypted2` w pyLoad, gdy niezaufany JavaScript trafiał do Js2Py z włączonym importowaniem modułów Pythona; [poprawka w upstreamie](https://github.com/pyload/pyload/commit/7d73ba7919e594d783b3411d7ddb87885aea782d) wyłączała `pyimport`. Zanim uznasz proces pyLoad za ścieżkę eskalacji uprawnień, skoreluj właściciela działającego procesu, adres nasłuchiwania, dostępność endpointu oraz zainstalowaną poprawkę lub backport dostawcy. Sama nazwa procesu, otwarty port ani wersja pakietu nie dowodzą podatności; pasywne enumerowanie nie powinno wysyłać payloadu wykonującego kod.

### Uprzywilejowane powłoki logowania współdzielące terminal

Uprzywilejowana powłoka interaktywna, która uruchamia `su --login <user>` bez niezależnego pseudo-terminala, może współdzielić terminal z powłoką logowania użytkownika o niższych uprawnieniach. Jeśli plik startowy tego użytkownika można kontrolować, a zawarty w nim kod może używać `TIOCSTI` do wstrzykiwania danych wejściowych do terminala, mogą one trafić do uprzywilejowanej powłoki po jej wznowieniu. [Podręcznik util-linux `su`](https://man7.org/linux/man-pages/man1/su.1.html#SECURITY_NOTES) opisuje ryzyko związane ze współdzielonym terminalem i zaleca `su --pty`/`-P` do użytku interaktywnego; `su -c` uruchamia oddzielną sesję bez terminala sterującego. Ryzyko zależy od faktycznej powłoki nadrzędnej, relacji terminali, pliku startowego użytkownika docelowego i polityki jądra. Sama nazwa procesu lub argument `su -l` to jedynie wskazówka do dalszej weryfikacji.

Sprawdź zaobserwowane drzewo procesów i kolumny TTY, a następnie czytelny plik uruchamiający oraz właściciela i uprawnienia pliku startowego. W Linuksie `/proc/sys/dev/tty/legacy_tiocsti`, jeśli istnieje, może pomóc w interpretacji polityki; jego brak nie dowodzi bezpieczeństwa. [Podręcznik Linuksa `TIOCSTI`](https://man7.org/linux/man-pages/man2/TIOCSTI.2const.html) informuje, że od Linuksa 6.2 ta operacja może wymagać `CAP_SYS_ADMIN`, gdy ten sysctl ma wartość false. Nie wywołuj ioctl wyłącznie w celu enumerowania hosta.

Konto bazy danych może czasem zmienić plik startowy użytkownika docelowego bez bezpośredniego dostępu do zapisu w systemie plików. Serwerowe `COPY ... TO 'filename'` w PostgreSQL zapisuje plik z uprawnieniami konta systemowego OS serwera bazy danych, ale [ograniczenia PostgreSQL](https://www.postgresql.org/docs/current/sql-copy.html) dopuszczają tę formę zapisu do pliku tylko dla superużytkowników bazy danych lub ról takich jak `pg_write_server_files`. Potwierdź zarówno rolę w bazie danych, jak i uprawnienia konta OS serwera do plików; sam connection string aplikacji nie daje uprawnień do zapisu plików. Oceniając łańcuch, traktuj możliwości uprzywilejowanego procesu uruchamiającego i konta bazy danych oddzielnie.

## Sprawdź artefakty środowiska wykonawczego

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Usunięte pliki wykonywalne i usunięte, ale wciąż otwarte pliki pozostają dostępne, dopóki nie zostanie zamknięty ich ostatni deskryptor. Mogą zachowywać ślady lub dostępne sekrety. Środowisko i pamięć procesu mogą zawierać dane uwierzytelniające, ale odczyt innego procesu podlega ograniczeniom związanym z własnością, opcjami montowania `/proc`, polityką Yama ptrace i innymi mechanizmami bezpieczeństwa. Powiązane techniki opisano w sekcjach [deskryptory plików](../main-system-information/filesystem-links-and-file-descriptors.md) i [wyszukiwanie danych uwierzytelniających po uzyskaniu dostępu](../post-exploitation/README.md).

Zapisane ślady wywołań systemowych stanowią kolejną granicę uprawnień do plików. [`strace` zapisuje argumenty wywołań systemowych do pliku wyjściowego](https://man7.org/linux/man-pages/man1/strace.1.html), więc odczytywalny ślad [argumentów `execve`](https://man7.org/linux/man-pages/man2/execve.2.html) może ujawnić hasło przekazane w wierszu poleceń przez zadanie działające z podwyższonymi uprawnieniami. Najpierw upewnij się, że bieżący użytkownik może odczytać dany ślad i że argument rzeczywiście zawiera dane uwierzytelniające; późniejsza zmiana konta Unix wymaga osobnego potwierdzenia, że dane te są tam akceptowane. Metadane plików mogą być użyteczną wskazówką pasywną, bez skanowania wszystkich śladów ani wyświetlania ich zawartości podczas rutynowej enumeracji.

## Gniazda automatyzacji biurowej z podwyższonymi uprawnieniami

LibreOffice i OpenOffice mogą udostępniać swoje API UNO za pomocą argumentu `--accept=socket,host=<host>,port=<port>;urp;`. Proces pakietu biurowego działający jako root i udostępniający osiągalny punkt końcowy może umożliwić lokalnemu użytkownikowi o niższych uprawnieniach wywoływanie usług API w kontekście bezpieczeństwa tego procesu. Usługa `SystemShellExecute` zawiera operację uruchamiania polecenia systemowego. Powiązanie z interfejsem loopback ogranicza dostęp zdalny, ale nie uniemożliwia lokalnym użytkownikom dostępu do gniazda, chyba że blokuje go inny mechanizm.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
ps -eo user,args | grep -E '[s]office|[l]ibreoffice|[o]penoffice'
ss -ltn 2>/dev/null
```

Skoreluj właściciela procesu, dokładny argument `--accept` oraz aktualny adres i port nasłuchujący. Skonfigurowany acceptor, któremu nie udało się powiązać z adresem, to jedynie trop; podczas pasywnej enumeracji nie łącz się z API ani go nie wywołuj. Nie uruchamiaj uprzywilejowanej instancji pakietu biurowego tylko po to, by sprawdzić ten warunek.

## Pamięć współdzielona System V używana przez uprzywilejowane procesy

Narzędzie pomocnicze działające z uprawnieniami roota może utworzyć segment pamięci współdzielonej System V, do którego zapisu może dokonywać inny użytkownik. Jeśli narzędzie później zaufa danym z tego segmentu podczas wykonywania polecenia powłoki lub innej wrażliwej operacji, segment przekracza granicę uprawnień, nawet jeśli plik wykonywalny i jego pliki są chronione. `shmget()` pobiera uprawnienia dostępu z dziewięciu najmłodszych bitów swoich flag; tryb `0666` pozwala innym użytkownikom na zapis, natomiast flaga `IPC_CREAT` nie ogranicza tych uprawnień. Pasywnie sprawdź aktywne segmenty za pomocą `ipcs -m` i skoreluj ich właściciela, tryb oraz czas istnienia z uprzywilejowanym procesem i sposobem obsługi jego danych wejściowych. Sam fakt, że segment jest zapisywalny przez wszystkich, nie dowodzi możliwości wykonania poleceń.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ipcs -m
```

Segmenty System V różnią się od plików pamięci współdzielonej POSIX w `/dev/shm`. Segment utworzony tylko na chwilę może nie być widoczny w pojedynczym zrzucie `ipcs`, więc pusty wynik nie wyklucza użycia pamięci współdzielonej przez helper. Sprawdź jego kod źródłowy lub działanie pliku binarnego oraz wszelkie reguły `sudo`, które go uruchamiają; nie uruchamiaj uprzywilejowanego helpera tylko po to, by segment pojawił się podczas enumeracji. [Przewodnik po przestrzeniach nazw IPC](../containers-namespaces/container-security/protections/namespaces/ipc-namespace.md) wyjaśnia, jak przestrzenie nazw wpływają na widoczność.<sup>[[2]](#references)[[3]](#references)</sup>

## Consul agent script checks

Consul może uruchamiać skryptowe testy stanu z tożsamością systemową swojego agenta. Jeśli agent działa jako root, ma włączone `enable_script_checks` i pozwala użytkownikowi o niższych uprawnieniach zarejestrować usługę z testem skryptowym za pośrednictwem lokalnego HTTP API, użytkownik ten może doprowadzić do uruchomienia poleceń jako root. Powiązanie API wyłącznie z `127.0.0.1` nadal pozwala lokalnym użytkownikom na dostęp. Ustawienie `enable_local_script_checks` ma węższy zakres: wyklucza testy skryptowe przesyłane w ramach rejestracji przez HTTP API. Gdy włączone są ACL Consula, rejestracja usługi wymaga uprawnienia `service:write`; sama linia `acl.default_policy=allow` nie dowodzi, że anonimowy użytkownik może zarejestrować usługę. Sprawdź łącznie rzeczywistą tożsamość agenta, załadowane ustawienia, powiązanie API oraz autoryzację.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
ps -eo user,args | grep '[c]onsul agent'
ls -l /etc/consul.d 2>/dev/null
```

Podążaj za argumentami `-config-dir` i `-config-file` uruchomionego agenta, aby znaleźć odpowiednią konfigurację, i sprawdzaj wyłącznie nazwy oraz ustawienia pól dotyczących script-check i ACL. Pliki konfiguracyjne mogą też zawierać klucze lub tokeny gossip; nie wklejaj ich do współdzielonych logów. Nie rejestruj usługi ani nie uruchamiaj health checku tylko po to, by wykryć ten warunek.

Istnieje osobna ścieżka oparta na plikach lokalnych, jeśli użytkownik o niższych uprawnieniach może **zapisywać w katalogu wskazanym przez `-config-dir` agenta uruchomionego przez roota i go przeszukiwać**: z tego katalogu może zostać wczytana nowa definicja usługi `.hcl` lub `.json`. Prawo przeszukiwania katalogu i zapisu w nim może pozwolić na dodanie pliku nawet wtedy, gdy odmawia się prawa do wyświetlenia zawartości katalogu. W przypadku wykonywania poleceń jako root potwierdź, że agent faktycznie wczytuje ten katalog, jego **efektywne** ustawienie script-check zezwala na lokalne definicje, definicja została wczytana, a agent zachowuje uprawnienia roota. [Dokumentacja Consul](https://developer.hashicorp.com/consul/docs/fundamentals/agent#reloadable-configurations) opisuje ustawienia i definicje health checków, które można wczytać ponownie; samo włączenie script checków może wymagać restartu, dlatego zweryfikuj zachowanie zainstalowanej wersji. Gdy agenta chronią ACL, [`consul reload` wymaga `agent:write`](https://developer.hashicorp.com/consul/api-docs/agent#reload-agent); uprawnienie do zapisu KV samo w sobie nie zapewnia tego uprawnienia. Potraktuj możliwość zapisu w katalogu jako wskazówkę do weryfikacji, a nie dowód na autoryzowane ponowne wczytanie konfiguracji, restart lub wykonanie polecenia. Sprawdź ścieżki, uprawnienia i politykę, nie zapisując konfiguracji ani nie wywołując API.

## Śledź łańcuch wykonywania usługi

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Sprawdź unit, drop-ins, `EnvironmentFile=`, helper scripts, relative commands, writable directories i socket activation. Unit należący do roota nadal może być niebezpieczny, jeśli odczytuje konfigurację lub skrypt zapisywalny przez użytkownika. Strona [arbitrary file write](../interesting-files-permissions/write-to-root.md) opisuje typowe ścieżki nadużyć związane z usługami i unitami. Krótkotrwałe zadania monitoruj za pomocą [pspy](https://github.com/DominicBreuker/pspy) lub telemetryki audit/procesów, gdy jednorazowe wywołanie `ps` ich nie wykrywa.

W przypadku niestandardowej usługi **xinetd** zestaw włączoną sekcję `server`, `user` i reguły kontroli dostępu z aktywnym listenerem i dokładnym plikiem wykonywalnym. Ustawienie [`user`](https://manpages.debian.org/testing/xinetd/xinetd.conf.5.en.html) określa tożsamość uruchamianego procesu, natomiast bit set-user-ID pliku wykonywalnego może niezależnie zmienić jego efektywną tożsamość, jeśli [`execve` zezwala na taką zmianę](https://man7.org/linux/man-pages/man2/execve.2.html). Dostępny z sieci uprzywilejowany plik binarny przyjmujący niezaufane dane wejściowe warto przeanalizować offline, przeglądając kod źródłowy lub deasemblację pod kątem błędów bezpieczeństwa pamięci, takich jak nieograniczona konwersja ciągu przez [`scanf`](https://www.gnu.org/software/libc/manual/html_node/String-Input-Conversions.html) do bufora o stałym rozmiarze. Mapowanie usługi i metadane set-user-ID są wskazówkami, a nie dowodem występowania takiego błędu; podczas pasywnego rozpoznania nie wysyłaj danych powodujących awarię ani nie debuguj aktywnej uprzywilejowanej usługi.

W przypadku niestandardowego uprzywilejowanego listenera z dostępnym kodem źródłowym przeanalizuj każdą długość kontrolowaną przez wywołującego, używaną w operacji kopiowania, takiej jak [`memcpy`](https://man7.org/linux/man-pages/man3/memcpy.3.html). Samo sprawdzenie, że bieżący indeks zapisu mieści się w buforze o stałym rozmiarze, nie dowodzi, że **długość kopiowania** mieści się w pozostałej przestrzeni; po potwierdzeniu, że indeks jest w zakresie, sprawdź `copy_length <= capacity - index`, a także znakowość i przepełnienie arytmetyczne. To tylko wskazówka do analizy, jeśli dane wejściowe docierają do tej operacji, listener jest dostępny dla użytkownika o niższych uprawnieniach, a proces zachowuje wyższą efektywną tożsamość. Przeanalizuj kod źródłowy i metadane procesu offline; podczas rozpoznania nie wysyłaj do aktywnej usługi danych powodujących awarię.

W systemach korzystających z **Upstart** definicje zadań systemowych mogą znajdować się w `/etc/init/*.conf`. Plik zadania zapisywalny przez bieżącego użytkownika ma znaczenie, gdy aktywny demon init ładuje właśnie to zadanie, jego sekcja `script` lub `exec` działa z wyższymi uprawnieniami, a użytkownik może je uruchomić za pomocą dozwolonego polecenia `initctl` lub innego rzeczywistego wyzwalacza. Samo przyznanie `initctl` przez sudo nie dowodzi, że którykolwiek plik zadania jest zapisywalny ani że zmodyfikowane zadanie zostanie uruchomione. Sprawdź uprawnienia dokładnego pliku zadania, efektywne ustawienie tożsamości uruchomieniowej, aktywny demon i wyzwalacz — nie edytuj ani nie uruchamiaj zadania podczas rozpoznania. Zobacz podręczniki [konfiguracji zadań Upstart](https://manpages.ubuntu.com/manpages/trusty/man5/init.5.html) i [`initctl`](https://manpages.ubuntu.com/manpages/xenial/man8/initctl.8.html).

Czytelny plik hasła autologin, taki jak `/etc/autologin/passwd` w systemach, w których [zadanie rozruchowe odczytuje dokładnie tę ścieżkę](https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/master/chromeos-base/autologin/files/init/autologin.conf), wskazuje na możliwe ujawnienie poświadczeń. Potwierdź, że zadanie rozruchowe jest zainstalowane i korzysta z tego pliku, a następnie osobno sprawdź, czy hasło jest poprawne dla innego lokalnego konta lub usługi. Sama nazwa pliku nie dowodzi ponownego użycia hasła; odnotuj ścieżkę i metadane dostępu, nie umieszczając hasła we wspólnych wynikach rozpoznania.

`ExecStart=` w unicie lub zaplanowane polecenie może ujawnić dokładną ścieżkę do skryptu w katalogu, którego nie można wylistować. [Uprawnienie do przeszukiwania katalogu](https://man7.org/linux/man-pages/man7/path_resolution.7.html) może nadal pozwalać bieżącej tożsamości przejść znaną ścieżkę; sprawdź uprawnienie do przeszukiwania każdego katalogu nadrzędnego oraz uprawnienie do odczytu pliku, zamiast zakładać, że nieudane listowanie katalogu chroni jego zawartość. Czytelny skrypt może zawierać poświadczenie transferowe, ale dostęp do innego konta wymaga, by poświadczenie nadal było ważne i było tam niezależnie akceptowane. Zapisz ścieżkę i dowody dotyczące uprawnień, nie wypisując wartości sekretów we wspólnych logach.

W przypadku zaplanowanego skryptu CommonJS Node.js przeanalizuj nierozwinięte importy, takie jak `require('package')`, nawet jeśli sam skrypt jest tylko do odczytu. [Node szuka katalogów `node_modules` obok pliku importującego, a następnie w jego katalogach nadrzędnych](https://nodejs.org/api/modules.html#loading-from-node_modules-folders), zanim przejdzie do skonfigurowanych ścieżek globalnych. Użytkownik o niższych uprawnieniach, który może **zapisywać i przeszukiwać** jeden z tych katalogów nadrzędnych, może być w stanie utworzyć pakiet dopasowywany wcześniej. Potwierdź, że dokładny import jest osiągany, wybrany pakiet nie jest wbudowanym modułem, w odpowiedniej ścieżce można utworzyć lub zmienić pliki, moduł zostanie tam znaleziony przez zainstalowane środowisko wykonawcze, a zadanie o wyższych uprawnieniach załaduje go przy przyszłym uruchomieniu. Zapisywalne metadane katalogu nadrzędnego są jedynie wskazówką do analizy; sprawdź skrypt i harmonogram pasywnie, nie umieszczając modułu ani nie wyzwalając zadania.

Prywatny indeks pakietów Python to kolejna granica zaufania, gdy zautomatyzowane zadanie instaluje pakiety z użyciem innej tożsamości systemu operacyjnego. Zestaw dokładne zadanie i konto, jako które jest uruchamiane, ze skonfigurowanym indeksem i wybranymi nazwami pakietów, a także sprawdź, czy użytkownik o niższych uprawnieniach może opublikować lub zastąpić pakiet, który zadanie faktycznie zainstaluje. Budowanie dystrybucji źródłowej może uruchomić backend kompilacji lub starszy `setup.py` z tożsamością instalatora; import zainstalowanego pakietu to osobna ścieżka wykonania. Listener indeksu, czytelny hash hasła do wysyłania plików lub sama nazwa pliku pakietu nie dowodzą istnienia takiego łańcucha. Przeanalizuj zadanie, uprawnienia w indeksie i pochodzenie pakietu, nie wysyłając ani nie instalując niczego podczas rozpoznania. Zobacz [interfejs systemu kompilacji pip](https://pip.pypa.io/en/stable/reference/build-system/) i [wskazówki dotyczące bezpiecznej instalacji](https://pip.pypa.io/en/stable/topics/secure-installs/).

Uprzywilejowany agent może odpytywać kolejkę zadań zarządzaną przez oddzielną usługę webową lub kontener. Jeśli tożsamość o niższym poziomie zaufania może zapisywać bazę danych zadań usługi, ustal, czy te rekordy są faktycznie udostępniane temu agentowi i czy zadanie typu command działa z tożsamością systemu operacyjnego agenta. Osobno potwierdź dostęp do zapisu w bazie danych, docelową sesję lub klucz routingu, aktywne odpytywanie, autoryzację zadań i efektywnego użytkownika agenta. Root wewnątrz kontenera sam w sobie nie oznacza dostępu do hosta z uprawnieniami roota; granica zostaje przekroczona tylko wtedy, gdy uprzywilejowany na hoście konsument wykonuje dane zadania kontrolowane przez atakującego. Sprawdź metadane procesów, pliku bazy danych i usługi, nie modyfikując kolejki ani nie wysyłając zadania podczas rozpoznania.

Zamiast tego cykliczne zadanie może odczytywać polecenie z wiersza konfiguracji bazy danych aplikacji. Potwierdź, że rola bazy danych o niższych uprawnieniach może zmienić dokładnie ten wiersz, że aktywne zadanie odczytuje go po zmianie i że wartość trafia do powłoki lub równoważnego mechanizmu uruchamiania poleceń z wyższą tożsamością systemu operacyjnego. Dostęp do zapisu w bazie danych ani sama wartość przypominająca polecenie nie dowodzą wykonania; przeanalizuj zadanie i uprawnienia, nie zmieniając wiersza podczas pasywnego rozpoznania.

Kolejka może też zawierać URL zamiast kodu. Jeśli uprzywilejowany konsument pobiera spod tego URL-a dane i ładuje odpowiedź jako plugin Lua lub inny wykonywalny plugin, sprawdź uprawnienia nadawcy do dokładnego exchange i klucza routingu, powiązanie z konsumowaną kolejką, ścieżkę pobrania i załadowania pluginu oraz efektywną tożsamość workera. [RabbitMQ routuje publikowane wiadomości za pośrednictwem exchanges](https://www.rabbitmq.com/docs/exchanges); listener brokera ani poprawne dane logowania same w sobie nie dowodzą dostarczenia wiadomości do tego workera. Przechwycone jawne poświadczenia brokera to osobna wskazówka, która wymaga faktycznego dostępu do przechwytywania pakietów i czytelnego ruchu; nie dowodzą one uprawnień do publikowania. Plugin Lua może uruchamiać polecenia powłoki za pomocą [`os.execute`](https://www.lua.org/manual/5.4/manual.html#pdf-os.execute) tylko wtedy, gdy to API jest dostępne w jego środowisku wykonawczym. Przeanalizuj konfigurację i kod, nie przechwytując ruchu, nie publikując wiadomości ani nie pobierając pluginu podczas pasywnego rozpoznania.

Gdy uprzywilejowana usługa Python udostępnia lokalny endpoint HTTP lub socket, czytelny skrypt może ujawnić ścieżkę od danych wejściowych do kodu, nawet jeśli jego uprawnienia uniemożliwiają modyfikację. Zestaw aktywny proces i tożsamość unitu z dokładnym skryptem, listenerem, autoryzacją trasy i polami kontrolowanymi przez wywołującego. Następnie prześledź te pola przez parsowanie i walidację aż do dynamicznego punktu użycia `eval()` lub `exec()`. W szczególności utworzenie nowego f-stringa z tekstu żądania i jego ewaluacja może zinterpretować dostarczone przez atakującego pola podstawiania jako wyrażenia Python ([ostrzeżenie dotyczące Python `eval`](https://docs.python.org/3/library/functions.html#eval); [semantyka f-stringów](https://docs.python.org/3/reference/lexical_analysis.html#f-strings)). Samo wystąpienie `eval` lub powiązanie z loopback nie dowodzi, że niezaufany wywołujący dociera do tego punktu; przeanalizuj rzeczywisty przepływ danych i kontrolę dostępu, nie wysyłając testowego payloadu podczas rozpoznania.

Bramka podpisanych żądań na tej trasie wymaga osobnej analizy. Jeśli czytelny kod źródłowy wyznacza klucz podpisujący z możliwego do wykazania, małego lub przewidywalnego zbioru wartości, a usługa udostępnia poprawnie podpisany przykład, podpis może już nie chronić uprzywilejowanego punktu `eval()`. Sprawdź dokładny sposób wyznaczania klucza i weryfikator, tożsamość aktywnej usługi oraz dostęp lokalnych wywołujących, a także to, czy podpisane pole trafia do tego punktu; import modułu Python [`random`](https://docs.python.org/3/library/random.html) ani sam przykładowy podpis niczego z tego nie dowodzą. Python ostrzega również, że ograniczenie `__builtins__` [nie stanowi granicy bezpieczeństwa dla niezaufanych danych wejściowych `eval()`](https://docs.python.org/3/library/functions.html#eval). Analizuj klucze offline i nie wysyłaj sfałszowanych żądań podczas pasywnego rozpoznania.

Pusty, ale zapisywalny katalog `/etc/systemd/system/<unit>.service.d` ma znaczenie nawet wtedy, gdy plik unitu i wszystkie istniejące drop-ins są chronione: użytkownik może utworzyć nowy override `.conf`. Sprawdź, czy katalog jest zapisywalny i przeszukiwalny przez bieżącą tożsamość, czy unit jest załadowany i działa jako root oraz czy nastąpi przeładowanie demona, a następnie restart. Uprawnienie do przeładowania lub restartu, timer albo późniejszy rozruch mogą uaktywnić zmianę; sam dostęp do zapisu w katalogu nie wykonuje jej natychmiast.

W przypadku działających usług sprawdź dosłowne ścieżki `EnvironmentFile=` z sekcji `[Service]` unitu, także pliki, których nazwy nie zaczynają się od `.env`. Jeśli użytkownik o niskich uprawnieniach może odczytać taki plik, wypisz nazwy kluczy przypominających poświadczenia, takich jak `API_TOKEN` lub `APP_SECRET_KEY`, nie umieszczając ich wartości we wspólnych logach. Przy ocenie efektywnego unitu sprawdź drop-iny i opcjonalny prefiks `-`. Możliwość odczytu wskazuje na możliwe ujawnienie poświadczeń; aby uzyskać eskalację, wartość nadal musi być ważna dla uprzywilejowanej operacji.

### Uprzywilejowane przetwarzanie niezaufanych plików

Uruchomiony jako root watcher plików może przekazywać pliki z zapisywalnego przez użytkownika katalogu uploadów do krótkotrwałego parsera lub programu rozpakowującego. Prześledź skrypt nadrzędny lub usługę działającego watchera i potwierdź dokładny katalog, osoby mogące umieszczać w nim pliki, polecenie potomne wraz z argumentami oraz tożsamość, z którą działa proces potomny. Migawka procesów może pokazać watchera, ale pominąć program rozpakowujący uruchamiany między kolejnymi uploadami. Podczas pasywnego rozpoznania nie umieszczaj testowego payloadu ani nie wyzwalaj watchera.

Konkretnym przykładem jest tryb rozpakowywania Binwalk (`-e`) przetwarzający kontrolowane przez atakującego dane PFS. [CVE-2022-4510](https://github.com/ReFirmLabs/binwalk/pull/617) umożliwiało ekstraktorowi PFS zapis poza przeznaczonym katalogiem, także do ścieżki pluginu, który Binwalk mógł później załadować. Poprawkę uwzględniono upstream w wersji [2.3.4](https://github.com/ReFirmLabs/binwalk/releases/tag/v2.3.4), ale backporty dystrybucji mogą zachowywać starszy wyświetlany numer wersji; przed oceną podatności sprawdź stan bezpieczeństwa zainstalowanego pakietu, na przykład w [trackerze Debiana](https://security-tracker.debian.org/tracker/CVE-2022-4510). Sama zainstalowana wersja Binwalk nie dowodzi istnienia ścieżki eskalacji uprawnień: bardziej uprzywilejowany proces musi faktycznie uruchamiać ekstrakcję na danych kontrolowanych przez użytkownika o niższych uprawnieniach.

### Zaplanowane kompilacje z lokalnymi zależnościami

Zaplanowane `cargo run` ponownie kompiluje kod źródłowy jako użytkownik, z którego uprawnieniami uruchamiane jest zadanie. Sprawdź lokalne zależności `{ path = "..." }` w manifeście oraz uprawnienia do kodu źródłowego i katalogów nadrzędnych każdej zależności, a nie tylko głównego crate'a. Jeśli użytkownik o niższych uprawnieniach może zmodyfikować zależność kompilowaną przez Cargo, a zaplanowane zadanie uruchamia jej wynik, skompilowany kod może działać z uprawnieniami tego użytkownika. Potwierdź efektywne polecenie harmonogramu, katalog roboczy, rozwiązywanie zależności i to, czy nastąpi ponowna kompilacja; zapisywalny plik źródłowy Rust w innym miejscu jest tylko wskazówką. Do wstępnej analizy pasywnej wystarczy odczytanie manifestu i metadanych ścieżek. Zobacz [dokumentację zależności ścieżkowych Cargo](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies).

## Pliki framebuffer Xvfb

`Xvfb -fbdir <directory>` używa plików mapowanych do pamięci o nazwach `Xvfb_screen<n>` dla swoich wirtualnych ekranów. Jeśli działający proces Xvfb innego użytkownika wskazuje katalog, którego pliki ekranów są czytelne dla bieżącego użytkownika, framebuffer może ujawniać zawartość pulpitu tego użytkownika. Potwierdź jednocześnie proces, właściciela pliku i uprawnienia; sam czytelny plik nie dowodzi, że na ekranie znajdują się przydatne informacje. Najpierw sprawdź ścieżki i metadane, nie kopiując danych obrazu do wspólnych wyników rozpoznania. Podręcznik [Xvfb](https://xorg.freedesktop.org/archive/X11R7.5/doc/man/man1/Xvfb.1.html) opisuje działanie opcji `-fbdir`.

```bash
pgrep -a -x Xvfb
ls -l /path/from/-fbdir/Xvfb_screen*
```

## References

1. [Podręcznik Linuxa `shmget(2)`](https://man7.org/linux/man-pages/man2/shmget.2.html)
2. [Podręcznik Linuxa `ipcs(1)`](https://man7.org/linux/man-pages/man1/ipcs.1.html)
3. [Podręcznik OpenBSD `ipcs(1)`](https://man.openbsd.org/ipcs.1)
4. [Konfiguracja agenta Consul: kontrole skryptów](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/general)
5. [API rejestrowania usług agenta Consul](https://developer.hashicorp.com/consul/api-docs/agent/service)
6. [Konfiguracja ACL w Consul](https://developer.hashicorp.com/consul/docs/reference/agent/configuration-file/acl)
7. [Pomoc LibreOffice: otwieranie gniazda dla zewnętrznych klientów API](https://help.libreoffice.org/latest/en-US/text/sbasic/shared/03/sf_intro.html)
8. [LibreOffice SDK: `XSystemShellExecute`](https://api.libreoffice.org/docs/idl/ref/interfacecom_1_1sun_1_1star_1_1system_1_1XSystemShellExecute.html)

{{#include ../../banners/hacktricks-training.md}}
