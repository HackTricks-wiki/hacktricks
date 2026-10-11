# Przechwytywanie ruchu, zapora i analiza ruchu wychodzącego

{{#include ../../banners/hacktricks-training.md}}

Po zlokalizowaniu [lokalnych listenerów i gniazd Unix](local-network-and-socket-triage.md) sprawdź, przez które interfejsy przepływa ich ruch oraz jakie reguły zapory lub proxy wpływają na dostępność. Usługa dostępna wyłącznie przez loopback może przenosić poufne nagłówki HTTP, nawet jeśli nie można się z nią połączyć z innego hosta.

## Sprawdź uprawnienia do przechwytywania i wybierz interfejs

```bash
ip -br addr
ip route
getcap "$(command -v dumpcap)" 2>/dev/null
tcpdump -D 2>/dev/null
```

`dumpcap` może mieć uprawnienia do przechwytywania pakietów, nawet jeśli bieżący użytkownik nie ma dostępu do sudo. Sprawdź rzeczywiste capabilities pliku wykonywalnego i uprawnienia grupy. Przechwytuj dane z najmniejszej użytecznej liczby interfejsów, przez najkrótszy potrzebny czas i z odpowiednim filtrem; przechwycone dane mogą zawierać dane uwierzytelniające lub osobowe.

```bash
sudo tcpdump -i lo -s 0 -w /tmp/loopback.pcap 'tcp port 8080'
tshark -r /tmp/loopback.pcap -Y 'http.request' -T fields -e ip.src -e http.host -e http.request.uri
tcpflow -r /tmp/loopback.pcap 2>/dev/null
```

`tcpflow` rekonstruuje jawne strumienie TCP; `tshark` może filtrować przechwycone dane i wyodrębniać z nich pola. W przypadku ruchu TLS odszyfrowanie wymaga kluczy endpointu lub obsługiwanego klienta skonfigurowanego przed nawiązaniem połączenia z użyciem `SSLKEYLOGFILE`. [Strona dotycząca analizy lokalnej sieci](local-network-and-socket-triage.md#tls-key-logging) opisuje ten proces. Nie traktuj zaszyfrowanego przechwycenia jako czytelnego tekstu jawnego.

Zapisane artefakty incydentu mogą zmienić tę ocenę. [Zrzut pamięci procesu w systemie Linux to obraz pamięci procesu](https://man7.org/linux/man-pages/man5/core.5.html), który może zawierać klucz sesji; jeśli czytelny zrzut i przechwycenie pakietów pochodzą z tego samego procesu i sesji, analityk może być w stanie odszyfrować ten ruch. Najpierw zinwentaryzuj ścieżki i uprawnienia artefaktów, a następnie osobno zweryfikuj tożsamość procesu, czas przechwycenia, protokół i format klucza. Odszyfrowany ruch lub odzyskane archiwum to wskazówka dotycząca ujawnienia, a nie dowód dostępu do konta innej osoby: wszelkie fragmenty materiału klucza SSH nadal trzeba odtworzyć, dopasować do odpowiedniego klucza publicznego i sprawdzić, czy są akceptowane przez zasady SSH tego konta. Unikaj umieszczania zawartości zrzutów pamięci lub przechwyconych ładunków w wynikach szeroko zakrojonego rozpoznania.

## Zidentyfikuj warstwy zapory

```bash
sudo nft list ruleset 2>/dev/null
sudo iptables-save 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

`nftables` i `iptables` mogą być udostępniane za pośrednictwem wrapperów dystrybucji, takich jak UFW lub firewalld. Odczytaj aktywne reguły i utrwaloną konfigurację wrappera; reguła widoczna w jednej reprezentacji mogła zostać wygenerowana przez inne narzędzie. Zanim przypiszesz blokadę usługi konkretnej regule, sprawdź interfejs, kierunek, źródło, cel, protokół, port i stan połączenia. Zobacz [przegląd reguł nftables](local-network-and-socket-triage.md#nftables-review-and-authorized-rule-changes), gdzie znajdziesz konkretny przykład.

## Testowanie ruchu wychodzącego i zachowania proxy

```bash
ip route get 1.1.1.1
getent hosts example.com
curl -I --connect-timeout 3 https://example.com/
printenv http_proxy https_proxy all_proxy no_proxy 2>/dev/null
```

Oddziel awarię DNS od awarii TCP, TLS lub proxy. Przetestuj konkretny cel i protokół istotne dla oceny; osiągalność przez ICMP nie oznacza, że TCP lub UDP są dozwolone. Jeśli skonfigurowano proxy, porównaj żądanie wysyłane przez proxy z żądaniem do tego samego celu przy zastosowaniu odpowiednich reguł `no_proxy`. Lokalny port forward może też udostępnić usługę loopback w innym miejscu, dlatego sprawdź aktywne nasłuchujące porty i tunele SSH, gdy widok firewalla nie zgadza się z zaobserwowaną ekspozycją.
{{#include ../../banners/hacktricks-training.md}}
