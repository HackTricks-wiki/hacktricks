# Analiza ruchu sieciowego, firewalla i ruchu wychodzącego

{{#include ../../banners/hacktricks-training.md}}

Po zlokalizowaniu [lokalnych listenerów i gniazd Unix](local-network-and-socket-triage.md) sprawdź, które interfejsy przenoszą ich ruch oraz które reguły firewalla lub proxy wpływają na dostępność. Usługa dostępna wyłącznie przez loopback może przesyłać poufne nagłówki HTTP, nawet jeśli nie można się z nią połączyć z innego hosta.

## Sprawdź uprawnienia do przechwytywania ruchu i wybierz interfejs

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` może mieć uprawnienia do przechwytywania pakietów, nawet jeśli bieżący użytkownik nie ma dostępu do sudo. Sprawdź rzeczywiste capabilities pliku wykonywalnego i uprawnienia grup. Ogranicz przechwytywanie do najmniejszej użytecznej liczby interfejsów, czasu trwania i filtra; przechwycone dane mogą zawierać dane uwierzytelniające lub osobowe.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` rekonstruuje strumienie TCP w postaci jawnego tekstu; `tshark` może filtrować przechwycony ruch i wyodrębniać z niego pola. W przypadku ruchu TLS odszyfrowanie wymaga kluczy endpointów lub obsługiwanego klienta skonfigurowanego przed połączeniem do używania `SSLKEYLOGFILE`. [Strona dotycząca analizy lokalnej sieci](local-network-and-socket-triage.md#tls-key-logging) przedstawia ten proces. Nie traktuj zaszyfrowanego przechwyconego ruchu jak czytelnego tekstu jawnego.

Przechowywane artefakty incydentu mogą zmienić tę ocenę. [Zrzut pamięci procesu w Linuksie jest obrazem jego pamięci](https://man7.org/linux/man-pages/man5/core.5.html) i może zawierać klucz sesji; jeśli czytelny zrzut i przechwycony ruch pochodzą z tego samego procesu i sesji, analityk może być w stanie odszyfrować ten ruch. Najpierw zinwentaryzuj ścieżki artefaktów i uprawnienia, a następnie osobno zweryfikuj tożsamość procesu, czas przechwycenia, protokół i format klucza. Odszyfrowany ruch lub odzyskane archiwum to trop wskazujący na ujawnienie danych, a nie dowód dostępu do konta innej osoby: wszelkie fragmenty materiału klucza SSH trzeba najpierw zrekonstruować, dopasować do odpowiadającego mu klucza publicznego i sprawdzić, czy akceptuje je polityka SSH tego konta. Unikaj wypisywania zawartości zrzutów pamięci lub przechwyconych pakietów w wynikach szeroko zakrojonego rozpoznania.

## Identify firewall layers

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` i `iptables` mogą być udostępniane za pośrednictwem nakładek dystrybucji, takich jak UFW lub firewalld. Odczytaj aktywne reguły i utrwaloną konfigurację nakładki; reguła widoczna w jednym widoku mogła zostać utworzona przez inne narzędzie. Zanim przypiszesz zablokowaną usługę konkretnej regule, sprawdź interfejs, kierunek, źródło, cel, protokół, port i stan połączenia. Zobacz [przegląd reguł nftables](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes), aby zapoznać się z konkretnym przykładem.

## Testowanie ruchu wychodzącego i działania proxy

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Oddziel awarię DNS od awarii TCP, TLS lub proxy. Testuj konkretny cel i protokół istotne dla oceny; osiągalność przez ICMP nie oznacza, że TCP lub UDP są dozwolone. Jeśli skonfigurowano proxy, porównaj zamierzone żądanie kierowane przez proxy z żądaniem do tego samego celu przy zastosowaniu odpowiednich reguł `no_proxy`. Lokalne przekierowanie portu może również udostępnić usługę loopback w innym miejscu, dlatego gdy widok zapory nie zgadza się z zaobserwowaną ekspozycją, sprawdź aktywne nasłuchujące porty i tunele SSH.
{{#include ../../banners/hacktricks-training.md}}
