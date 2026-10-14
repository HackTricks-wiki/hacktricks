# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

**Low-Power Wide Area Network** (LPWAN) to grupa bezprzewodowych technologii sieciowych o niskim poborze mocy i dużym zasięgu, zaprojektowanych z myślą o **komunikacji na duże odległości** przy niskiej przepływności bitowej.
W zależności od parametrów radiowych, anteny, regionu regulacyjnego, ukształtowania terenu i duty cycle, wdrożenia LPWAN mogą zapewniać zasięg wielu kilometrów i wieloletnią pracę na baterii kosztem przepustowości. Deklarowane przez producentów wartości zasięgu i czasu pracy na baterii należy traktować jako założenia projektowe, a nie gwarancje.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) to obecnie najpowszechniej wdrażana warstwa fizyczna LPWAN, a jej otwarta specyfikacja warstwy MAC to **LoRaWAN**.

---

## LPWAN, LoRa i LoRaWAN

* LoRa – warstwa fizyczna Chirp Spread Spectrum (CSS), opracowana przez Semtech (zastrzeżona, ale udokumentowana).
* LoRaWAN – otwarta warstwa MAC/sieciowa utrzymywana przez LoRa-Alliance. W użyciu powszechne są wersje 1.0.x i 1.1.
* Typowa architektura: *urządzenie końcowe → bramka (packet-forwarder) → serwer sieciowy → serwer aplikacji*.<sup>[[3]](#references)</sup>

> W LoRaWAN 1.1 **model bezpieczeństwa** wykorzystuje oddzielne klucze główne AES-128 dla aplikacji i sieci, z których podczas OTAA wyprowadzane są klucze sesyjne przypisane do konkretnych ról. W starszych wdrożeniach 1.0.x zwykle używa się jednego AppKey do wyprowadzenia kluczy sesyjnych sieci i aplikacji, natomiast w ABP klucze sesyjne są konfigurowane bezpośrednio. Możliwości uzyskane dzięki wyciekowi klucza zależą zatem od wersji LoRaWAN i tego, który klucz został ujawniony.<sup>[[3]](#references)</sup>

---

## Podsumowanie powierzchni ataku

| Warstwa | Słabość | Praktyczny wpływ |
|-------|----------|------------------|
| PHY | Reaktywne / selektywne jamming | Lokalne gubienie pakietów; skuteczność zależy od budżetu łącza, czasu, szerokości pasma i ograniczeń regulacyjnych |
| MAC | Replay żądań dołączenia i ramek danych w przypadku ponownego użycia stanu nonce/licznika | Desynchronizacja urządzenia, spoofing lub injection, jeśli serwer/urządzenie narusza zabezpieczenia przed replay |
| Network-Server | Niebezpieczny packet-forwarder, słabe filtry MQTT/UDP, nieaktualne firmware bramki | RCE na bramkach → pivot do sieci OT/IT |
| Aplikacja | Zakodowane na stałe lub przewidywalne AppKeys | Brute-force/decrypt ruchu, podszywanie się pod czujniki |

---

## Przykładowe podatności implementacji

* **CVE-2024-29862** – W podatnych wersjach ChirpStack Gateway Bridge wcześniejszych niż 4.0.11 i MQTT Forwarder wcześniejszych niż 4.2.1 można było połączyć się z kontrolowanym przez atakującego brokerem MQTT, ponieważ weryfikacja certyfikatu serwera TLS była wyłączona. Mogło to ujawnić dane uwierzytelniające i ruch bramki; należy zaktualizować oprogramowanie do poprawionych wersji.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 opisuje nieuwierzytelnione wyświetlanie zawartości katalogu `/lib/`, obejmującego plik kopii zapasowej do pobrania; CVE-2022-45228 to CSRF o niskim poziomie zagrożenia na stronie wylogowania. Te wpisy nie potwierdzają deklarowanego wpływu na LG308, nadpisywania konfiguracji, liczby urządzeń ani stanu poprawek z 2025 roku.<sup>[[6]](#references)[[7]](#references)</sup>
* Wcześniejsza wersja tej strony opisywała rzekomy problem z Semtech UDP packet-forwarder jako **spreparowany uplink większy niż 255 bajtów powodujący przepełnienie stosu i RCE na bramkach referencyjnych SX130x**, przypisując go prezentacji „LoRa Exploitation Reloaded” z Black Hat Europe 2023 i prywatnej poprawce z października 2023 roku. Te szczegółowe informacje pozostawiono tutaj jako trop badawczy, ale nie udało się potwierdzić istnienia pasującego publicznego komunikatu bezpieczeństwa, prezentacji ani poprawki. Nie należy traktować tego problemu jako znanej podatności bez ustalenia podatnego produktu/wersji i uzyskania weryfikowalnego źródła pierwotnego.

---

## Praktyczne techniki ataku

### 1. Sniff & Decrypt traffic

```bash
# Capture all channels around 868.3 MHz with an SDR (USRP B205)
python3 lorattack/sniffer.py \
    --freq 868.3e6 --bw 125e3 --rate 1e6 --sf 7 --session smartcity

# Bruteforce AppKey from captured OTAA join-request/accept pairs
python3 lorapwn/bruteforce_join.py --pcap smartcity.pcap --wordlist top1m.txt
```

Te polecenia zachowują oryginalny przepływ pracy jako **składnię poglądową**; układ repozytorium i flagi różnią się między projektami i wydaniami. Pasywne przechwytywanie nie ujawnia silnego AppKey. Zgadywanie offline jest przydatne tylko wtedy, gdy klucz główny jest na tyle słaby, że można go znaleźć, a przechwycona wymiana podczas dołączania do sieci dostarcza wartości pozwalającej zweryfikować kandydatów.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Testowanie ochrony przed powtórzeniem OTAA i stanu nonce

1. W autoryzowanej sieci testowej przechwyć prawidłowy **JoinRequest**.
2. Odtwórz to samo żądanie i potwierdź, że serwer sieciowy odrzuca ponownie użyty `DevNonce`.
3. Uruchom ponownie lub zresetuj urządzenie testowe i powtórz test, aby wykryć utratę stanu nonce. Zgodny serwer musi śledzić użyte nonce; samo odtworzenie JoinRequest nie ujawnia nowo wyprowadzonych kluczy sesji ani nie daje odtwarzającemu kontroli nad sesją.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Obniżanie parametrów Adaptive Data-Rate (ADR)

Atakujący, który może uwierzytelniać polecenia MAC warstwy sieciowej — na przykład po przejęciu odpowiedniego klucza sesji sieciowej lub serwera sieciowego — może próbować wymusić nieefektywne parametry szybkości transmisji danych i zwiększyć czas nadawania. Znajdujący się w pobliżu nieuwierzytelniony nadajnik nie może legalnie wysyłać poleceń ADR tylko dlatego, że zna adres urządzenia.<sup>[[3]](#references)</sup>

### 4. Reaktywne zagłuszanie

Reaktywny jammer może nadawać po wykryciu preambuły LoRa i selektywnie zakłócać ramki. Na poprzedniej stronie stwierdzono, że konfiguracja HackRF/GNU Radio spowodowała całkowitą awarię w odległości **2 km przy mocy nie większej niż 200 mW**, ale nie podano źródła potwierdzającego te pomiary; liczby te należy traktować jako cel do odtworzenia, a nie oczekiwany wynik. Wymagana moc nadawania, synchronizacja, szerokość pasma, zakłócane współczynniki rozpraszania i zasięg zależą od środowiska. Testy przeprowadzaj wyłącznie w autoryzowanym, ekranowanym środowisku RF i przestrzegaj lokalnych przepisów dotyczących widma radiowego.

---

## Narzędzia ofensywne (2025)

| Narzędzie | Cel | Uwagi |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Tworzenie i parsowanie ramek LoRaWAN, ataki na nie, analizatory korzystające z DB, narzędzie do brute-force | Obraz Docker; obsługuje wejście Semtech UDP<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Narzędzie Pythona Trend Micro do brute-force OTAA, generowania downlinków i odszyfrowywania payloadów | Publiczne narzędzie badawcze; sprawdź obsługiwany sprzęt i wersje protokołu<sup>[[2]](#references)</sup> |
| **LoRAttack** | Framework badawczy do przechwytywania LoRaWAN na wielu kanałach, analizy sesji, wyprowadzania kluczy i testowania odtwarzania | Opisany w pracy magisterskiej z 2024 r.; przed poleganiem na przykładowych flagach pobierz i zweryfikuj dokładną implementację<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | Bloki out-of-tree GNU Radio do odbioru sygnału bazowego LoRa lub badań nad transceiverami | Projekty różnią się zgodnością z GNU Radio i zestawem funkcji<sup>[[9]](#references)</sup> |

---

## Zalecenia obronne (lista kontrolna pentestera)

1. Preferuj **OTAA** i sprawdź, czy urządzenia i serwery trwale zapisują wymagany stan nonce; monitoruj odrzucone, powielone żądania dołączenia.
2. Jeśli to możliwe, preferuj **LoRaWAN 1.1**, aby funkcje sieciowe używały odrębnych kluczy sesji i zaktualizowanej obsługi nonce.<sup>[[3]](#references)</sup>
3. Przechowuj licznik ramek w pamięci nieulotnej (**ABP**) lub przejdź na OTAA.
4. Zastosuj odpowiedni **secure element** (na przykład ATECC608A w obsługiwanym projekcie), aby ograniczyć narażenie kluczy głównych w zwykłej pamięci firmware’u.
5. Nie udostępniaj niezaufanym sieciom skonfigurowanych listenerów UDP packet-forwardera (zwykle port 1700); uwierzytelniaj i szyfruj połączenie backhaul bramki lub ograniczaj je za pomocą VPN.
6. Używaj firmware’u bramek wspieranego przez producenta i sprawdzaj dokładny model oraz wersję pod kątem odpowiednich zaleceń bezpieczeństwa.
7. Wdróż **wykrywanie anomalii w ruchu** (np. analizator LAF) – oznaczaj resetowanie liczników, powielone żądania dołączenia i nagłe zmiany ADR.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Przegląd LoRaPWN od Trend Micro](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - specyfikacja LoRaWAN L2 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - regionalne parametry LoRaWAN 1.1 i synchronizacja dołączania do sieci](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [Katalog prac CTU - Analiza bezpieczeństwa protokołów LPWAN z wykorzystaniem technologii SDR](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [Transceiver GNU Radio EPFL `gr-lora_sdr`](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
