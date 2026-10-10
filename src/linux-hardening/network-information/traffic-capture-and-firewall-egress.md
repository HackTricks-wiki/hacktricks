# Przechwytywanie ruchu, zapora sieciowa i analiza ruchu wychodzącego

{{#include ../../banners/hacktricks-training.md}}

Po zlokalizowaniu [lokalnych usług nasłuchujących i gniazd Unix](local-network-and-socket-triage.md) sprawdź, które interfejsy przenoszą ich ruch oraz które reguły zapory sieciowej lub serwera proxy wpływają na dostępność. Usługa dostępna tylko przez loopback może przesyłać poufne nagłówki HTTP, nawet jeśli nie jest osiągalna z innego hosta.

## Sprawdź uprawnienia do przechwytywania i wybierz interfejs

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` może mieć uprawnienia do przechwytywania pakietów, nawet jeśli bieżący użytkownik nie ma dostępu do sudo. Sprawdź rzeczywiste capabilities pliku wykonywalnego i uprawnienia grupy. Przechwytuj ruch na najmniejszej użytecznej liczbie interfejsów, przez najkrótszy czas i z użyciem filtra; przechwycone dane mogą zawierać dane uwierzytelniające lub dane osobowe.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` rekonstruuje strumienie TCP w postaci tekstu jawnego; `tshark` może filtrować przechwycone dane i wyodrębniać z nich pola. W przypadku ruchu TLS odszyfrowanie wymaga kluczy endpointu lub obsługiwanego klienta skonfigurowanego do używania `SSLKEYLOGFILE` przed nawiązaniem połączenia. [Strona poświęcona analizie lokalnej sieci i gniazd](local-network-and-socket-triage.md#tls-key-logging) opisuje tę procedurę. Nie traktuj zaszyfrowanego przechwycenia jako czytelnego tekstu jawnego.

Zapisane artefakty incydentu mogą zmienić tę ocenę. [Zrzut pamięci procesu w systemie Linux jest obrazem pamięci procesu](https://man7.org/linux/man-pages/man5/core.5.html), w którym może pozostać klucz sesji; jeśli czytelny zrzut i przechwycone pakiety pochodzą z tego samego procesu i sesji, analityk może być w stanie odszyfrować ten ruch. Najpierw zinwentaryzuj ścieżki artefaktów i uprawnienia, a następnie osobno zweryfikuj tożsamość procesu, czas przechwycenia, protokół i format klucza. Odszyfrowany ruch lub odzyskane archiwum to trop wskazujący na ujawnienie danych, a nie dowód dostępu do konta innej osoby: wszelkie częściowe dane klucza SSH nadal trzeba zrekonstruować, dopasować do odpowiadającego mu klucza publicznego i sprawdzić, czy zaakceptuje je polityka SSH danego konta. Unikaj umieszczania zawartości zrzutów pamięci lub przechwyconych pakietów w wynikach szeroko zakrojonej enumeracji.

## Zidentyfikuj warstwy zapory

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` i `iptables` mogą być udostępniane za pośrednictwem wrapperów dystrybucji, takich jak UFW lub firewalld. Odczytaj aktywne reguły i utrwaloną konfigurację wrappera; reguła widoczna w jednym miejscu mogła zostać wygenerowana przez inne narzędzie. Przed przypisaniem blokady usługi do konkretnej reguły sprawdź interfejs, kierunek, źródło, cel, protokół, port i stan połączenia. Zobacz [przegląd reguł nftables](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes), gdzie znajdziesz konkretny przykład.

## Testowanie ruchu wychodzącego i działania proxy

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Oddziel awarię DNS od awarii TCP, TLS lub proxy. Testuj konkretny cel i protokół istotne dla oceny; osiągalność przez ICMP nie oznacza, że TCP lub UDP jest dozwolone. Jeśli skonfigurowano proxy, porównaj zamierzone żądanie przez proxy z żądaniem do tego samego celu z uwzględnieniem właściwych reguł `no_proxy`. Lokalne przekierowanie portu może również udostępnić usługę loopback w innym miejscu, dlatego sprawdź aktywne nasłuchujące porty i tunele SSH, gdy konfiguracja firewalla i zaobserwowana ekspozycja są rozbieżne.
{{#include ../../banners/hacktricks-training.md}}
