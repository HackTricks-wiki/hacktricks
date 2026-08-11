# Low-Power Wide Area Network

{{#include ../../banners/hacktricks-training.md}}

## Wprowadzenie

**Low-Power Wide Area Network** (LPWAN) to grupa bezprzewodowych technologii sieci rozległych o niskim poborze mocy, zaprojektowanych do **komunikacji dalekiego zasięgu** przy niskiej przepływności bitowej.
W zależności od parametrów radiowych, anteny, regionu regulacyjnego, ukształtowania terenu i cyklu pracy, wdrożenia LPWAN mogą wymieniać przepustowość na zasięg obejmujący wiele kilometrów oraz wieloletni czas pracy na baterii. Dane dotyczące zasięgu i czasu pracy baterii podawane przez dostawców należy traktować jako cele projektowe, a nie gwarancje.<sup>[[3]](#references)</sup>

Long Range (**LoRa**) jest obecnie najczęściej wdrażaną warstwą fizyczną LPWAN, a jej otwartą specyfikacją warstwy MAC jest **LoRaWAN**.

---

## LPWAN, LoRa i LoRaWAN

* LoRa – warstwa fizyczna Chirp Spread Spectrum (CSS), opracowana przez firmę Semtech (własnościowa, ale udokumentowana).
* LoRaWAN – otwarta warstwa MAC/Network utrzymywana przez LoRa-Alliance. W praktyce często spotykane są wersje 1.0.x i 1.1.
* Typowa architektura: *end-device → gateway (packet-forwarder) → network-server → application-server*.<sup>[[3]](#references)</sup>

> W LoRaWAN 1.1 **model bezpieczeństwa** wykorzystuje oddzielne klucze główne AES-128 aplikacji i sieci do wyprowadzania kluczy sesyjnych specyficznych dla ról podczas OTAA. Wcześniejsze wdrożenia 1.0.x zazwyczaj używają jednego AppKey do wyprowadzania kluczy sesyjnych sieci i aplikacji, podczas gdy ABP bezpośrednio konfiguruje klucze sesyjne. Możliwości uzyskane dzięki leaked key zależą zatem od wersji LoRaWAN oraz od tego, który klucz został ujawniony.<sup>[[3]](#references)</sup>

---

## Podsumowanie powierzchni ataku

| Warstwa | Słabość | Praktyczny wpływ |
|-------|----------|------------------|
| PHY | Reactive / selective jamming | Lokalne gubienie pakietów; skuteczność zależy od budżetu łącza, czasu, szerokości pasma i ograniczeń regulacyjnych |
| MAC | Replay join i ramek danych w przypadku ponownego użycia stanu nonce/licznika | Desynchronizacja urządzeń, spoofing lub injection, jeśli serwer/urządzenie narusza mechanizmy ochrony przed replay |
| Network-Server | Niezabezpieczony packet-forwarder, słabe filtry MQTT/UDP, nieaktualne firmware gatewaya | RCE na gatewayach → pivot do sieci OT/IT |
| Application | Hard-coded lub przewidywalne AppKeys | Brute-force/decrypt ruchu, impersonate sensorów |

---

## Reprezentatywne podatności implementacji

* **CVE-2024-29862** – wersje ChirpStack Gateway Bridge przed 4.0.11 oraz MQTT Forwarder przed 4.2.1 mogły łączyć się z brokerem MQTT kontrolowanym przez atakującego, ponieważ walidacja certyfikatu serwera TLS była wyłączona. Mogło to ujawnić dane uwierzytelniające i ruch gatewaya; należy zaktualizować oprogramowanie do wersji zawierających poprawkę.<sup>[[4]](#references)</sup>
* **Dragino LG01 firmware 4.3.4** – CVE-2022-45227 opisuje nieuwierzytelnione wyświetlenie zawartości katalogu `/lib/`, obejmujące możliwy do pobrania plik kopii zapasowej; CVE-2022-45228 to podatność CSRF o niskim poziomie zagrożenia na stronie wylogowania. Rekordy te nie potwierdzają rzekomego wpływu na LG308, nadpisywania konfiguracji, liczby urządzeń ani stanu poprawek w 2025 roku.<sup>[[6]](#references)[[7]](#references)</sup>
* We wcześniejszej wersji tej strony opisano rzekomy problem Semtech UDP packet-forwardera jako **crafted uplink o długości większej niż 255 bajtów powodujący stack smash i RCE na referencyjnych gatewayach SX130x**, przypisywany prezentacji „LoRa Exploitation Reloaded” na Black Hat Europe 2023 oraz prywatnej poprawce z października 2023 roku. Te szczegółowe informacje pozostawiono tutaj jako trop badawczy, jednak nie udało się potwierdzić istnienia odpowiadającego im publicznego advisory, prezentacji ani poprawki. Nie należy traktować tego problemu jako znanej podatności bez uzyskania informacji o produkcie/wersji, której dotyczy, oraz weryfikowalnego źródła pierwotnego.

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
Te polecenia zachowują oryginalny workflow jako **składnię poglądową**; układ repozytorium i flagi różnią się między projektami i wydaniami. Pasywny capture nie ujawnia silnego AppKey. Zgadywanie offline jest użyteczne tylko wtedy, gdy root key jest wystarczająco słaby, aby można go było znaleźć, a przechwycona wymiana join dostarcza wartości umożliwiającej walidację kandydatów.<sup>[[2]](#references)[[3]](#references)</sup>

### 2. Testowanie ochrony OTAA przed replay i stanu nonce

1. W autoryzowanej sieci testowej przechwyć prawidłowy **JoinRequest**.
2. Wykonaj replay tego samego żądania i potwierdź, że network server odrzuca ponownie użyty `DevNonce`.
3. Uruchom ponownie lub zresetuj urządzenie testowe i powtórz test, aby wykryć utratę stanu nonce. Zgodny ze specyfikacją server musi śledzić użyte nonce; sam replay JoinRequest nie ujawnia nowo wyprowadzonych session keys ani nie daje atakującemu kontroli nad sesją.<sup>[[3]](#references)</sup><sup>[[5]](#references)</sup>

### 3. Obniżanie Adaptive Data-Rate (ADR)

Atakujący, który może uwierzytelniać network-layer MAC commands — na przykład po przejęciu odpowiedniego network session key lub network server — może próbować wymusić nieefektywne parametry data-rate i zwiększyć airtime. Znajdujący się w pobliżu nieuwierzytelniony transmitter nie może legalnie wydawać poleceń ADR wyłącznie dzięki znajomości adresu urządzenia.<sup>[[3]](#references)</sup>

### 4. Reactive jamming

Reactive jammer może transmitować po wykryciu preambuły LoRa i wybiórczo zakłócać ramki. Wcześniejsza strona twierdziła, że konfiguracja HackRF/GNU Radio spowodowała całkowitą awarię na dystansie **2 km przy nie więcej niż 200 mW**, ale nie podano źródła potwierdzającego te pomiary; zachowaj te wartości wyłącznie jako cel reprodukcji, a nie oczekiwany rezultat. Wymagana moc nadawania, czas, bandwidth, dotknięte spreading factors i zasięg zależą od środowiska. Testuj wyłącznie w autoryzowanej konfiguracji z kontrolą RF i przestrzegaj lokalnych przepisów dotyczących widma.

---

## Offensive tooling (2025)

| Tool | Purpose | Notes |
|------|---------|-------|
| **LoRaWAN Auditing Framework (LAF)** | Tworzenie, parsowanie i atakowanie ramek LoRaWAN, analyzers korzystające z DB, brute-forcer | Obraz Docker; obsługuje wejście Semtech UDP<sup>[[1]](#references)</sup> |
| **LoRaPWN** | Narzędzie Python firmy Trend Micro do brute OTAA, generowania downlinks i odszyfrowywania payloadów | Publiczne narzędzie badawcze; zweryfikuj obsługiwany hardware i wersje protokołu<sup>[[2]](#references)</sup> |
| **LoRAttack** | Framework badawczy do wielokanałowego capture LoRaWAN, analizy sesji, wyprowadzania kluczy i testowania replay | Opisany w pracy magisterskiej z 2024 roku; zdobądź i zweryfikuj dokładną implementację przed poleganiem na przykładowych flagach<sup>[[8]](#references)</sup> |
| **gr-lora / gr-lora_sdr** | Bloki GNU Radio out-of-tree do odbioru baseband LoRa lub badań transceiverów | Projekty różnią się zgodnością z GNU Radio i zestawem funkcji<sup>[[9]](#references)</sup> |

---

## Zalecenia defensywne (checklista pentestera)

1. Preferuj **OTAA** i sprawdzaj, czy urządzenia oraz servery zachowują wymagany stan nonce; monitoruj odrzucone zduplikowane joiny.
2. Jeśli jest obsługiwany, preferuj **LoRaWAN 1.1**, aby funkcje sieciowe korzystały z odrębnych session keys i zaktualizowanej obsługi nonce.<sup>[[3]](#references)</sup>
3. Przechowuj frame-counter w pamięci nieulotnej (**ABP**) lub przeprowadź migrację do OTAA.
4. Wdróż odpowiedni **secure element** (na przykład ATECC608A w obsługiwanej konstrukcji), aby ograniczyć ujawnienie root keys w zwykłym storage firmware.
5. Nie wystawiaj skonfigurowanych listenerów UDP packet-forwardera (zwykle 1700) do niezaufanych sieci; uwierzytelniaj i szyfruj backhaul gatewaya albo ograniczaj go za pomocą VPN.
6. Utrzymuj gatewaye na firmware wspieranym przez vendora i sprawdzaj dokładny model oraz wersję względem odpowiednich advisories.
7. Wdróż **traffic anomaly detection** (np. analyzer LAF) — wykrywaj resety liczników, zduplikowane joiny i nagłe zmiany ADR.<sup>[[1]](#references)</sup>



## References

- [1] [LoRaWAN Auditing Framework (LAF)](https://github.com/IOActive/laf)
- [2] [Przegląd LoRaPWN firmy Trend Micro](https://www.hackster.io/news/trend-micro-finds-lorawan-security-lacking-develops-lorapwn-python-utility-bba60c27d57a)
- [3] [LoRa Alliance - specyfikacja LoRaWAN L2 1.1](https://resources.lora-alliance.org/technical-specifications/lorawan-specification-v1-1)
- [4] [NVD - CVE-2024-29862](https://nvd.nist.gov/vuln/detail/CVE-2024-29862)
- [5] [LoRa Alliance - parametry regionalne LoRaWAN 1.1 i synchronizacja join](https://resources.lora-alliance.org/technical-specifications/lorawan-backend-interfaces-v1-1)
- [6] [NVD - CVE-2022-45227](https://nvd.nist.gov/vuln/detail/CVE-2022-45227)
- [7] [NVD - CVE-2022-45228](https://nvd.nist.gov/vuln/detail/CVE-2022-45228)
- [8] [Katalog prac CTU - analiza bezpieczeństwa protokołów LPWAN z wykorzystaniem technologii SDR](https://fit.cvut.cz/en/faculty/people/5076-ing-jiri-dostal-ph-d/theses)
- [9] [Transceiver GNU Radio EPFL `gr-lora_sdr`](https://github.com/tapparelj/gr-lora_sdr)
{{#include ../../banners/hacktricks-training.md}}
