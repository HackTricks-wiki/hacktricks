# Podczerwień

{{#include ../../banners/hacktricks-training.md}}

## Jak działa podczerwień <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Światło podczerwone jest niewidoczne dla ludzi**. Długość fali IR wynosi od **0,7 do 1000 mikronów**. Piloty domowe używają sygnału IR do transmisji danych i działają w zakresie długości fali 0,75..1,4 mikrona. Mikrokontroler w pilocie sprawia, że dioda LED podczerwieni miga z określoną częstotliwością, zamieniając sygnał cyfrowy w sygnał IR.<sup>[[1]](#references)</sup>

Do odbierania sygnałów IR używa się **fotoodbiornika**. **Zamienia on światło IR na impulsy napięcia**, które są już **sygnałami cyfrowymi**. Zwykle wewnątrz odbiornika znajduje się **filtr światła ciemnego**, który przepuszcza **tylko pożądaną długość fali** i odcina szumy.

### Różnorodność protokołów IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Protokoły IR różnią się pod 3 względami:

- kodowanie bitów
- struktura danych
- częstotliwość nośna — często w zakresie 36..38 kHz

#### Sposoby kodowania bitów <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Bity są kodowane przez modulowanie czasu trwania przerwy między impulsami. Szerokość samego impulsu jest stała.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Bity są kodowane przez modulowanie szerokości impulsu. Szerokość przerwy po serii impulsów jest stała.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Jest również znane jako kodowanie Manchester. Wartość logiczna jest określana przez polaryzację przejścia między serią impulsów a przerwą. „Przerwa do serii impulsów” oznacza logikę „0”, a „seria impulsów do przerwy” oznacza logikę „1”.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Połączenie poprzednich metod i inne egzotyczne rozwiązania**

> [!TIP]
> Istnieją protokoły IR, które **mają stać się uniwersalne** dla kilku typów urządzeń. Najbardziej znane to RC5 i NEC. Niestety, bycie najbardziej znanym **nie oznacza bycia najczęściej używanym**. W moim otoczeniu spotkałem tylko dwa piloty NEC i żadnego RC5.
>
> Producenci chętnie używają własnych, unikalnych protokołów IR, nawet w obrębie tego samego zakresu urządzeń (na przykład TV-boxów). Dlatego piloty różnych firm, a czasami także różnych modeli tej samej firmy, nie są w stanie współpracować z innymi urządzeniami tego samego typu.

### Analiza sygnału IR

Najbardziej niezawodnym sposobem sprawdzenia, jak wygląda sygnał IR pilota, jest użycie oscyloskopu. Nie demoduluje on ani nie odwraca odebranego sygnału — wyświetla go po prostu „w niezmienionej postaci”. Jest to przydatne podczas testowania i debugowania. Pokażę oczekiwany sygnał na przykładzie protokołu IR NEC.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Zwykle na początku zakodowanego pakietu znajduje się preambuła. Pozwala to odbiornikowi określić poziom wzmocnienia i tło. Istnieją również protokoły bez preambuły, na przykład Sharp.

Następnie przesyłane są dane. Struktura, preambuła i metoda kodowania bitów zależą od konkretnego protokołu.

**Protokół IR NEC** zawiera krótką komendę oraz kod powtórzenia, który jest wysyłany, gdy przycisk pozostaje wciśnięty. Zarówno komenda, jak i kod powtórzenia mają tę samą preambułę na początku.

**Komenda** NEC, oprócz preambuły, składa się z bajtu adresu i bajtu numeru komendy, na podstawie których urządzenie rozumie, co należy wykonać. Bajty adresu i numeru komendy są powielone z odwróconymi wartościami w celu sprawdzenia integralności transmisji. Na końcu komendy znajduje się dodatkowy bit stopu.

**Kod powtórzenia** ma po preambule wartość „1”, która jest bitem stopu.

Dla **logiki „0” i „1”** NEC używa Pulse Distance Encoding: najpierw przesyłana jest seria impulsów, po której następuje pauza; jej długość określa wartość bitu.

### Klimatyzatory

W przeciwieństwie do innych pilotów, **klimatyzatory nie przesyłają tylko kodu wciśniętego przycisku**. Przesyłają również **wszystkie informacje** w momencie naciśnięcia przycisku, aby zapewnić **synchronizację klimatyzatora i pilota**.\
Zapobiega to sytuacji, w której urządzenie ustawione na 20°C zostaje za pomocą jednego pilota zwiększone do 21°C, a następnie użycie innego pilota, który wciąż ma ustawioną temperaturę 20°C, ponownie „zwiększa” ją do 21°C (zamiast do 22°C, ponieważ zakłada on, że temperatura wynosi 21°C).

---

## Ataki i badania ofensywne <a href="#attacks" id="attacks"></a>

Możesz atakować podczerwień za pomocą Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Przejęcie Smart-TV / Set-top Box (EvilScreen)

Najnowsze badania akademickie (EvilScreen, 2022) wykazały, że **wielokanałowe piloty łączące podczerwień z Bluetooth lub Wi-Fi mogą zostać wykorzystane do całkowitego przejęcia współczesnych smart-TV**. Atak łączy kody usług IR o wysokich uprawnieniach z uwierzytelnionymi pakietami Bluetooth, omijając izolację kanałów i umożliwiając uruchamianie dowolnych aplikacji, aktywowanie mikrofonu lub przywrócenie ustawień fabrycznych bez fizycznego dostępu. Osiem popularnych telewizorów różnych producentów — w tym model Samsung deklarujący zgodność z ISO/IEC 27001 — potwierdzono jako podatne. Ograniczenie ryzyka wymaga poprawek firmware'u producenta lub całkowitego wyłączenia nieużywanych odbiorników IR.<sup>[[2]](#references)</sup>

### Eksfiltracja danych z sieci odizolowanych za pomocą diod LED IR (rodzina aIR-Jumper)

Kamery bezpieczeństwa, routery, a nawet złośliwe pamięci USB często zawierają **diody LED IR noktowizji**. Badania pokazują, że malware może modulować te diody (<10–20 kbit/s przy użyciu prostego OOK), aby **eksfiltrować sekrety przez ściany i okna** do zewnętrznej kamery umieszczonej w odległości kilkudziesięciu metrów. Ponieważ światło znajduje się poza widmem widzialnym, operatorzy rzadko je zauważają. Środki zaradcze:

* Fizycznie osłonić lub usunąć diody LED IR w wrażliwych obszarach
* Monitorować cykl pracy diod LED kamery i integralność firmware'u
* Instalować filtry IR-cut na oknach i kamerach monitoringu

Atakujący może również użyć silnych projektorów IR do **wstrzykiwania** komend do sieci poprzez przesyłanie danych do niezabezpieczonych kamer.

### Brute-force na dużą odległość i rozszerzone protokoły z Flipper Zero 1.0

Firmware 1.0 (wrzesień 2024) dodał **dziesiątki dodatkowych protokołów IR i opcjonalne moduły zewnętrznych wzmacniaczy**. W połączeniu z trybem brute-force uniwersalnego pilota Flipper może wyłączać lub rekonfigurować większość publicznych telewizorów i klimatyzatorów z odległości do 30 m przy użyciu diody dużej mocy.

---

## Narzędzia i przykłady praktyczne <a href="#tooling" id="tooling"></a>

### Sprzęt

* **Flipper Zero** – przenośny transceiver z trybami uczenia, replay i dictionary-bruteforce (patrz wyżej).
* **Arduino / ESP32** + dioda LED IR / odbiornik TSOP38xx – tani DIY analyser/transmitter. Połącz z biblioteką `Arduino-IRremote` (v4.x obsługuje ponad 40 protokołów).
* **Analizatory logiczne** (Saleae/FX2) – przechwytują surowe czasy, gdy protokół jest nieznany.
* **Smartfony z IR-blasterem** (np. Xiaomi) – szybki test w terenie, ale z ograniczonym zasięgiem.

### Oprogramowanie

* **`Arduino-IRremote`** – aktywnie rozwijana biblioteka C++:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – dekodery GUI, które importują surowe przechwycenia, automatycznie identyfikują protokół oraz generują kod Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – odbieranie i wstrzykiwanie IR z wiersza poleceń:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Środki ochronne <a href="#defense" id="defense"></a>

* Wyłącz lub zasłoń odbiorniki IR w urządzeniach rozmieszczonych w przestrzeni publicznej, gdy nie są wymagane.
* Wymuszaj *pairing* lub kontrole kryptograficzne między smart-TV a pilotami; izoluj uprzywilejowane kody „serwisowe”.
* Instaluj filtry IR-cut lub detektory fali ciągłej wokół obszarów niejawnych, aby przerwać optyczne covert channels.
* Monitoruj integralność firmware'u kamer i urządzeń IoT udostępniających sterowane diody LED IR.

## References

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen: Smart TV hijacking via remote control mimicry](https://arxiv.org/abs/2210.03014)

{{#include ../../banners/hacktricks-training.md}}
