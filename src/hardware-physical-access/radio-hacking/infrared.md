# Podczerwień

{{#include ../../banners/hacktricks-training.md}}

## Jak działa podczerwień <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Światło podczerwone jest niewidoczne dla ludzi**. Długość fali podczerwieni wynosi od **0,7 do 1000 mikronów**. Piloty domowe używają sygnału podczerwieni do przesyłania danych i działają w zakresie długości fal 0,75..1,4 mikrona. Mikrokontroler w pilocie sprawia, że dioda LED podczerwieni miga z określoną częstotliwością, zamieniając sygnał cyfrowy na sygnał podczerwieni.

Do odbierania sygnałów podczerwieni używa się **fotoodbiornika**. **Zamienia on światło podczerwone na impulsy napięcia**, które są już **sygnałami cyfrowymi**. Zwykle wewnątrz odbiornika znajduje się **filtr światła**, który przepuszcza **tylko pożądaną długość fali** i odfiltrowuje zakłócenia.<sup>[[1]](#references)</sup>

### Różnorodność protokołów IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Protokoły IR różnią się pod 3 względami:<sup>[[1]](#references)</sup>

- kodowaniem bitów
- strukturą danych
- częstotliwością nośną — często z zakresu 36..38 kHz

#### Sposoby kodowania bitów <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Kodowanie odległością między impulsami**

Bity koduje się przez modulowanie czasu trwania przerwy między impulsami. Szerokość samego impulsu jest stała.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Kodowanie szerokością impulsu**

Bity koduje się przez modulowanie szerokości impulsu. Szerokość przerwy po serii impulsów jest stała.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Kodowanie fazowe**

Znane jest również jako kodowanie Manchester. Wartość logiczną określa polaryzacja przejścia między serią impulsów a przerwą. „Przerwa do serii impulsów” oznacza wartość logiczną „0”, a „seria impulsów do przerwy” — wartość logiczną „1”.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Połączenie powyższych metod i innych nietypowych rozwiązań**

> [!TIP]
> Istnieją protokoły IR, które **próbują stać się uniwersalne** dla kilku rodzajów urządzeń. Najbardziej znane to RC5 i NEC. Niestety, **najbardziej znane nie oznacza najczęściej spotykane**. W moim otoczeniu spotkałem tylko dwa piloty NEC i żadnego RC5.
>
> Producenci uwielbiają używać własnych, unikalnych protokołów IR, nawet w obrębie tej samej kategorii urządzeń (na przykład TV-boxów). Dlatego piloty różnych firm, a czasem nawet różnych modeli tej samej firmy, nie mogą współpracować z innymi urządzeniami tego samego typu.

### Analiza sygnału IR

Najbardziej niezawodnym sposobem sprawdzenia, jak wygląda sygnał IR z pilota, jest użycie oscyloskopu. Nie demoduluje on ani nie odwraca odbieranego sygnału, tylko wyświetla go „tak, jak jest”. Przydaje się to podczas testowania i debugowania. Pokażę oczekiwany sygnał na przykładzie protokołu IR NEC.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Na początku zakodowanego pakietu zwykle znajduje się preambuła. Dzięki niej odbiornik może określić poziom wzmocnienia i sygnał tła. Istnieją również protokoły bez preambuły, na przykład Sharp.

Następnie przesyłane są dane. Strukturę, preambułę i metodę kodowania bitów określa konkretny protokół.

**Protokół IR NEC** zawiera krótką komendę i kod powtórzenia, który jest wysyłany, gdy przycisk pozostaje wciśnięty. Zarówno komenda, jak i kod powtórzenia mają na początku tę samą preambułę.

**Komenda** NEC, oprócz preambuły, składa się z bajtu adresu i bajtu numeru komendy, na podstawie którego urządzenie rozpoznaje, co ma wykonać. Bajty adresu i numeru komendy są powielane z odwróconymi wartościami, aby sprawdzić integralność transmisji. Na końcu komendy znajduje się dodatkowy bit stopu.

**Kod powtórzenia** zawiera „1” po preambule, która jest bitem stopu.

Do kodowania **wartości logicznych „0” i „1”** NEC używa kodowania odległością między impulsami: najpierw przesyłana jest seria impulsów, po której następuje przerwa, a jej długość określa wartość bitu.

### Klimatyzatory

W przeciwieństwie do innych pilotów **pilot do klimatyzatora nie przesyła wyłącznie kodu wciśniętego przycisku**. Po wciśnięciu przycisku przesyła również **wszystkie informacje**, aby zapewnić **synchronizację klimatyzatora z pilotem**.\
Dzięki temu urządzenie ustawione na 20ºC nie zostanie podniesione do 21ºC za pomocą jednego pilota, a następnie — po użyciu innego pilota, który nadal ma ustawioną temperaturę 20ºC — ponownie „podniesione” do 21ºC (zamiast do 22ºC, bo pilot zakłada, że temperatura wynosi 21ºC).<sup>[[1]](#references)</sup>

---

## Ataki i badania ofensywne <a href="#attacks" id="attacks"></a>

Możesz atakować podczerwień za pomocą Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Przejęcie Smart-TV / dekodera (EvilScreen)

Niedawne badania akademickie (EvilScreen, 2022) wykazały, że **pilotami wielokanałowymi, łączącymi podczerwień z Bluetooth lub Wi-Fi, można manipulować, aby całkowicie przejąć nowoczesne smart-TV**. Atak łączy kody usług IR o wysokich uprawnieniach z uwierzytelnionymi pakietami Bluetooth, omijając izolację kanałów i umożliwiając uruchamianie dowolnych aplikacji, aktywację mikrofonu lub przywrócenie ustawień fabrycznych bez fizycznego dostępu. Potwierdzono podatność ośmiu popularnych telewizorów różnych producentów — w tym modelu Samsung deklarującego zgodność z ISO/IEC 27001. Aby ograniczyć ryzyko, potrzebne są poprawki firmware'u od producenta lub całkowite wyłączenie nieużywanych odbiorników IR.<sup>[[2]](#references)</sup>

### Eksfiltracja danych z sieci odizolowanej za pomocą diod LED IR (rodzina aIR-Jumper)

Kamery bezpieczeństwa często zawierają **diody LED IR do noktowizji**. Prototyp aIR-Jumper pokazał, że malware kontrolujące te diody może **eksfiltrować sekrety przez okna** do zewnętrznej kamery z szybkością do **20 bit/s na kamerę monitoringu** i na odległość kilkudziesięciu metrów. W przeciwnym kierunku badacze zademonstrowali infiltrację z szybkością ponad **100 bit/s** na odległości od setek metrów do kilometrów.<sup>[[3]](#references)</sup> Ponieważ światło znajduje się poza widzialnym zakresem widma, operatorzy mogą go nie zauważyć. Środki zaradcze obejmują:

* Fizyczne osłonięcie lub usunięcie diod LED IR w miejscach wrażliwych
* Monitorowanie cyklu pracy diod LED kamery i integralności firmware'u
* Zastosowanie filtrów odcinających podczerwień w oknach i kamerach monitoringu

Atakujący może również użyć silnych projektorów IR, aby **infiltrować** komendy do sieci, przesyłając dane do niezabezpieczonych kamer. 

### Brute-force na dużą odległość i rozszerzone protokoły z Flipper Zero 1.0

Firmware 1.0 (wrzesień 2024) rozszerzył bibliotekę uniwersalnych pilotów i dodał dynamiczne ładowanie plików zasobów podczerwieni z microSD.<sup>[[4]](#references)</sup> Funkcje uczenia i uniwersalnego pilota pozwalają odtwarzać lub testować znane komendy na pobliskich telewizorach i klimatyzatorach. Zasięg zależy w dużej mierze od nadajnika, optyki, światła otoczenia i odbiornika; zewnętrzny sprzęt IR może go zwiększyć, ale nie należy zakładać stałej odległości.

---

## Narzędzia i przykłady praktyczne <a href="#tooling" id="tooling"></a>

### Sprzęt

* **Flipper Zero** – przenośny nadajnik-odbiornik z trybami uczenia, odtwarzania i brute-force słownikowego (patrz wyżej).
* **Arduino / ESP32** + dioda LED IR / odbiornik TSOP38xx – tani analizator/nadajnik DIY. Można połączyć go z biblioteką `Arduino-IRremote` (wersja 4.x obsługuje ponad 40 protokołów).
* **Analizatory stanów logicznych** (Saleae/FX2) – przechwytują surowe czasy, gdy protokół jest nieznany.
* **Smartfony z nadajnikiem IR** (np. Xiaomi) – szybki test w terenie, ale o ograniczonym zasięgu.

### Oprogramowanie

* **`Arduino-IRremote`** – aktywnie rozwijana biblioteka C++:<sup>[[5]](#references)</sup>
  ```cpp
  #include <IRremote.hpp>
  void setup(){ IrSender.begin(3); }
  void loop(){
    IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
    delay(5000);
  }
  ```
* **IRscrutinizer / AnalysIR** – dekodery GUI, które importują surowe przechwycenia, automatycznie identyfikują protokół i generują kod Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – odbieranie i nadawanie IR z wiersza poleceń:
  ```bash
  sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
  irsend SEND_ONCE samsung KEY_POWER
  ```

---

## Środki ochronne <a href="#defense" id="defense"></a>

* Wyłączaj lub zasłaniaj odbiorniki IR w urządzeniach umieszczonych w przestrzeni publicznej, gdy nie są potrzebne.
* Wymuszaj *pairing* lub kontrole kryptograficzne między smart-TV a pilotami; odizoluj uprzywilejowane kody „serwisowe”.
* Rozmieszczaj filtry odcinające IR lub detektory fali ciągłej wokół obszarów niejawnych, aby przerwać optyczne kanały ukryte.
* Monitoruj integralność firmware kamer i urządzeń IoT, które udostępniają sterowane diody IR.

## References

- [1] [Flipper Zero: wpis na blogu o podczerwieni](https://blog.flipperzero.one/infrared/)
- [2] [Atak EvilScreen: przejęcie smart-TV przez naśladowanie wielokanałowego sterowania pilotem (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: ukryta eksfiltracja/infiltracja przez air gap za pośrednictwem kamer bezpieczeństwa i podczerwieni (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Blog Flipper Zero — wydano firmware 1.0](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote — dokumentacja użycia i protokołów](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
