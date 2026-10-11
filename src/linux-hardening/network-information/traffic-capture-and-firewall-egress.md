# Przechwytywanie ruchu, firewall i analiza egress

{{#include ../../banners/hacktricks-training.md}}

Po zlokalizowaniu [lokalnych listenerów i gniazd Unix](local-network-and-socket-triage.md) sprawdź, które interfejsy przenoszą ich ruch oraz które reguły firewall lub proxy wpływają na dostępność. Usługa dostępna tylko przez loopback może przesyłać poufne nagłówki HTTP, nawet jeśli nie można się z nią połączyć z innego hosta.

## Sprawdź uprawnienia do przechwytywania i wybierz interfejs

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` może mieć uprawnienia do przechwytywania pakietów, nawet jeśli bieżący użytkownik nie ma dostępu do sudo. Sprawdź rzeczywiste capabilities pliku wykonywalnego oraz uprawnienia grup. Przechwytuj dane z jak najmniejszej liczby interfejsów, przez jak najkrótszy czas i z użyciem odpowiedniego filtra; przechwycone dane mogą zawierać dane uwierzytelniające lub osobowe.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` odtwarza strumienie TCP w postaci jawnego tekstu; `tshark` może filtrować przechwycony ruch i wyodrębniać z niego pola. W przypadku ruchu TLS odszyfrowanie wymaga kluczy endpointu lub obsługiwanego klienta skonfigurowanego do używania `SSLKEYLOGFILE` przed nawiązaniem połączenia. [Strona poświęcona analizie lokalnej sieci i gniazd](local-network-and-socket-triage.md#tls-key-logging) opisuje ten proces. Nie traktuj zaszyfrowanego przechwyconego ruchu jak czytelnego tekstu jawnego.

Zapisane artefakty incydentu mogą zmienić tę ocenę. [Zrzut pamięci procesu Linux to obraz jego pamięci](https://man7.org/linux/man-pages/man5/core.5.html), który może zawierać klucz sesji; jeśli czytelny zrzut i przechwycony ruch pochodzą z tego samego procesu i sesji, analityk może być w stanie odszyfrować ten ruch. Najpierw zinwentaryzuj ścieżki i uprawnienia artefaktów, a następnie osobno zweryfikuj tożsamość procesu, czas przechwycenia, protokół i format klucza. Odszyfrowany ruch lub odzyskane archiwum stanowią wskazówkę o możliwym ujawnieniu danych, a nie dowód dostępu do konta innej osoby: każdy częściowy materiał klucza SSH nadal trzeba zrekonstruować, dopasować do odpowiedniego klucza publicznego i sprawdzić, czy jest akceptowany przez politykę SSH tego konta. Unikaj umieszczania zawartości zrzutów pamięci lub payloadów przechwyconego ruchu w wynikach szerokiej enumeracji.

## Zidentyfikuj warstwy zapory

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` i `iptables` mogą być udostępniane za pośrednictwem wrapperów dystrybucji, takich jak UFW lub firewalld. Odczytaj aktywne reguły i utrwaloną konfigurację wrappera; reguła widoczna w jednej reprezentacji mogła zostać wygenerowana przez inne narzędzie. Przed przypisaniem blokady usługi do konkretnej reguły sprawdź interfejs, kierunek, źródło, miejsce docelowe, protokół, port i stan połączenia. Zobacz [przegląd reguł nftables](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes), aby zapoznać się z konkretnym przykładem.

## Testowanie ruchu wychodzącego i działania proxy

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Oddziel błędy DNS od błędów TCP, TLS lub proxy. Testuj konkretny cel i protokół istotne dla oceny; osiągalność przez ICMP nie oznacza, że dozwolony jest TCP lub UDP. Jeśli skonfigurowano proxy, porównaj zamierzone żądanie kierowane przez proxy z żądaniem do tego samego celu przy zastosowaniu odpowiednich reguł `no_proxy`. Lokalne przekierowanie portu może też udostępnić usługę loopback w innym miejscu, więc sprawdź aktywne listenery i tunele SSH, gdy widok firewalla nie zgadza się z zaobserwowaną ekspozycją.
{{#include ../../banners/hacktricks-training.md}}
