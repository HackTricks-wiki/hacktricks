# Podczerwień

{{#include ../../banners/hacktricks-training.md}}

## Jak działa podczerwień <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Światło podczerwone jest niewidoczne dla ludzi**. Długość fali IR wynosi od **0,7 do 1000 mikronów**. Piloty domowe używają sygnału IR do transmisji danych i działają w zakresie długości fali 0,75..1,4 mikrona. Mikrokontroler w pilocie sprawia, że dioda LED podczerwieni miga z określoną częstotliwością, przekształcając sygnał cyfrowy w sygnał IR.

Do odbierania sygnałów IR używa się **fotoodbiornika**. **Przekształca on światło IR w impulsy napięcia**, które są już **sygnałami cyfrowymi**. Zwykle wewnątrz odbiornika znajduje się **filtr światła ciemnego**, który przepuszcza **wyłącznie żądaną długość fali** i odfiltrowuje zakłócenia.<sup>[[1]](#references)</sup>

### Różnorodność protokołów IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Protokoły IR różnią się trzema czynnikami:<sup>[[1]](#references)</sup>

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

**4. Połączenie powyższych metod i inne egzotyczne rozwiązania**

> [!TIP]
> Istnieją protokoły IR, które **próbują stać się uniwersalne** dla kilku rodzajów urządzeń. Najbardziej znane z nich to RC5 i NEC. Niestety **najbardziej znane** nie oznacza **najczęściej używane**. W moim otoczeniu spotkałem tylko dwa piloty NEC i żadnego pilota RC5.
>
> Producenci lubią używać własnych, unikatowych protokołów IR, nawet w obrębie tego samego zakresu urządzeń (na przykład TV-boxów). Dlatego piloty różnych firm, a czasami także piloty różnych modeli tej samej firmy, nie są w stanie współpracować z innymi urządzeniami tego samego typu.

### Analiza sygnału IR

Najbardziej niezawodnym sposobem sprawdzenia, jak wygląda sygnał IR pilota, jest użycie oscyloskopu. Nie demoduluje on ani nie odwraca odebranego sygnału, lecz wyświetla go dokładnie „tak, jak jest”. Jest to przydatne podczas testowania i debugowania. Pokażę oczekiwany sygnał na przykładzie protokołu NEC IR.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Zwykle na początku zakodowanego pakietu znajduje się preambuła. Umożliwia ona odbiornikowi określenie poziomu wzmocnienia i tła. Istnieją również protokoły bez preambuły, na przykład Sharp.

Następnie transmitowane są dane. Struktura, preambuła i metoda kodowania bitów są określone przez konkretny protokół.

**Protokół NEC IR** zawiera krótką komendę oraz kod powtórzenia, który jest wysyłany, gdy przycisk pozostaje wciśnięty. Zarówno komenda, jak i kod powtórzenia mają taką samą preambułę na początku.

**Komenda** NEC, oprócz preambuły, składa się z bajtu adresu i bajtu numeru komendy, na podstawie których urządzenie rozumie, co należy wykonać. Bajty adresu i numeru komendy są duplikowane z odwróconymi wartościami w celu sprawdzenia integralności transmisji. Na końcu komendy znajduje się dodatkowy bit stopu.

**Kod powtórzenia** zawiera po preambule wartość „1”, która jest bitem stopu.

Dla **logiki „0” i „1”** NEC używa Pulse Distance Encoding: najpierw transmitowana jest seria impulsów, po której następuje przerwa, a jej długość określa wartość bitu.

### Klimatyzatory

W przeciwieństwie do innych pilotów **klimatyzatory nie transmitują wyłącznie kodu wciśniętego przycisku**. Transmitują również **wszystkie informacje** w momencie naciśnięcia przycisku, aby zapewnić **synchronizację klimatyzatora i pilota**.\
Zapobiega to sytuacji, w której urządzenie ustawione na 20ºC zostanie jednym pilotem podniesione do 21ºC, a następnie użycie innego pilota, który nadal ma ustawioną temperaturę 20ºC, spowoduje jej „zwiększenie” do 21ºC (zamiast do 22ºC, ponieważ pilot zakłada, że temperatura wynosi 21ºC).<sup>[[1]](#references)</sup>

---

## Attacks & Offensive Research <a href="#attacks" id="attacks"></a>

Możesz atakować podczerwień za pomocą Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Przejęcie Smart-TV / Set-top Box (EvilScreen)

Niedawne badania akademickie (EvilScreen, 2022) wykazały, że **wielokanałowe piloty łączące podczerwień z Bluetooth lub Wi-Fi mogą zostać wykorzystane do pełnego przejęcia nowoczesnych telewizorów smart-TV**. Atak łączy kody usług IR o wysokich uprawnieniach z uwierzytelnionymi pakietami Bluetooth, omijając izolację kanałów i umożliwiając uruchamianie dowolnych aplikacji, aktywację mikrofonu lub przywrócenie ustawień fabrycznych bez fizycznego dostępu. Potwierdzono podatność ośmiu popularnych telewizorów różnych producentów — w tym modelu Samsung deklarującego zgodność z ISO/IEC 27001. Ograniczenie ryzyka wymaga poprawek firmware'u od producenta lub całkowitego wyłączenia nieużywanych odbiorników IR.<sup>[[2]](#references)</sup>

### Eksfiltracja danych z sieci odizolowanej za pomocą diod LED IR (rodzina aIR-Jumper)

Kamery bezpieczeństwa często zawierają **diody IR do widzenia nocnego**. Prototyp aIR-Jumper wykazał, że malware sterujący tymi diodami może **eksfiltrować sekrety przez okna** do zewnętrznej kamery z prędkością do **20 bit/s na kamerę monitoringu** na odległość kilkudziesięciu metrów. W kierunku odwrotnym badacze zademonstrowali infiltrację z prędkością ponad **100 bit/s** na odległości od setek metrów do kilometrów.<sup>[[3]](#references)</sup> Ponieważ światło znajduje się poza widzialnym spektrum, operatorzy mogą go nie zauważyć. Środki zaradcze obejmują:

* Fizyczne osłonięcie lub usunięcie diod IR w obszarach wrażliwych
* Monitorowanie cyklu pracy diod kamery i integralności firmware'u
* Montaż filtrów IR-cut na oknach i kamerach monitoringu

Atakujący może również użyć silnych projektorów IR do **infiltracji** komend do sieci przez migotanie danych z powrotem do niezabezpieczonych kamer.

### Brute-force dalekiego zasięgu i rozszerzone protokoły za pomocą Flipper Zero 1.0

Firmware 1.0 (wrzesień 2024) rozszerzył bibliotekę universal-remotes i dodał dynamiczne ładowanie plików zasobów podczerwieni z karty microSD.<sup>[[4]](#references)</sup> Funkcje uczenia i universal-remote mogą odtwarzać lub próbować znane komendy na pobliskich telewizorach i klimatyzatorach. Zasięg w dużym stopniu zależy od emitera, optyki, oświetlenia otoczenia i odbiornika; zewnętrzny sprzęt IR może go zwiększyć, ale nie należy zakładać stałej odległości.

---

## Narzędzia i praktyczne przykłady <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – przenośny transceiver z trybami uczenia, odtwarzania i dictionary-bruteforce (patrz wyżej).
* **Arduino / ESP32** + dioda LED IR / odbiornik TSOP38xx – tani DIY analyser/transmitter. Połącz z biblioteką `Arduino-IRremote` (v4.x obsługuje ponad 40 protokołów).
* **Logic analysers** (Saleae/FX2) – przechwytują surowe czasy, gdy protokół jest nieznany.
* **Smartfony z IR-blasterem** (np. Xiaomi) – szybki test w terenie, ale z ograniczonym zasięgiem.

### Software

* **`Arduino-IRremote`** – aktywnie rozwijana biblioteka C++:<sup>[[5]](#references)</sup>
```cpp
#include <IRremote.hpp>
void setup(){ IrSender.begin(3); }
void loop(){
IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – dekodery GUI, które importują surowe przechwycone dane, automatycznie identyfikują protokół oraz generują kod Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – odbieranie i wstrzykiwanie IR z wiersza poleceń:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Środki obronne <a href="#defense" id="defense"></a>

* Wyłączaj lub zasłaniaj odbiorniki IR w urządzeniach wdrożonych w przestrzeni publicznej, gdy nie są wymagane.
* Wymuszaj *pairing* lub sprawdzanie kryptograficzne między telewizorami smart-TV a pilotami; izoluj uprzywilejowane kody „service”.
* Stosuj filtry IR-cut lub detektory fali ciągłej wokół obszarów niejawnych, aby przerywać optyczne covert channels.
* Monitoruj integralność firmware'u kamer i urządzeń IoT udostępniających sterowalne diody LED IR.

## References

- [1] [Wpis na blogu Flipper Zero dotyczący podczerwieni](https://blog.flipperzero.one/infrared/)
- [2] [Atak EvilScreen: przejęcie Smart TV za pomocą imitacji wielokanałowego sterowania pilotem (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: potajemna eksfiltracja i infiltracja przez air-gap za pomocą kamer bezpieczeństwa i podczerwieni (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Blog Flipper Zero — wydanie firmware'u 1.0](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote — dokumentacja użycia i protokołów](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
