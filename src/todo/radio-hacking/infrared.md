# Infrared

{{#include ../../banners/hacktricks-training.md}}

## Jak działa podczerwień <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Światło podczerwone jest niewidoczne dla ludzi**. Długość fali IR wynosi od **0,7 do 1000 mikronów**. Piloty domowe używają sygnału IR do transmisji danych i działają w zakresie długości fal od 0,75 do 1,4 mikronów. Mikrokontroler w pilocie sprawia, że dioda LED podczerwieni miga z określoną częstotliwością, przekształcając sygnał cyfrowy w sygnał IR.

Aby odbierać sygnały IR, używa się **fotoreceptora**. On **przekształca światło IR w impulsy napięciowe**, które są już **sygnałami cyfrowymi**. Zwykle w **odbiorniku znajduje się filtr ciemnego światła**, który przepuszcza **tylko pożądaną długość fali** i eliminuje szumy.

### Różnorodność protokołów IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Protokoły IR różnią się w 3 czynnikach:

- kodowanie bitów
- struktura danych
- częstotliwość nośna — często w zakresie 36..38 kHz

#### Sposoby kodowania bitów <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Kodowanie odległości impulsów**

Bity są kodowane przez modulację czasu trwania przestrzeni między impulsami. Szerokość samego impulsu jest stała.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Kodowanie szerokości impulsów**

Bity są kodowane przez modulację szerokości impulsu. Szerokość przestrzeni po wybuchu impulsu jest stała.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Kodowanie fazowe**

Znane również jako kodowanie Manchester. Wartość logiczna jest definiowana przez polaryzację przejścia między wybuchem impulsu a przestrzenią. "Przestrzeń do wybuchu impulsu" oznacza logikę "0", "wybuch impulsu do przestrzeni" oznacza logikę "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Kombinacja poprzednich i inne egzotyki**

> [!TIP]
> Istnieją protokoły IR, które **próbują stać się uniwersalne** dla kilku typów urządzeń. Najbardziej znane to RC5 i NEC. Niestety, najbardziej znane **nie oznacza najbardziej powszechne**. W moim otoczeniu spotkałem tylko dwa piloty NEC i żadnego RC5.
>
> Producenci uwielbiają używać swoich unikalnych protokołów IR, nawet w obrębie tej samej grupy urządzeń (na przykład, dekodery TV). Dlatego piloty z różnych firm, a czasami z różnych modeli tej samej firmy, nie są w stanie współpracować z innymi urządzeniami tego samego typu.

### Badanie sygnału IR

Najbardziej niezawodnym sposobem na zobaczenie, jak wygląda sygnał IR z pilota, jest użycie oscyloskopu. Nie demoduluje ani nie odwraca odebranego sygnału, jest po prostu wyświetlany "tak jak jest". To jest przydatne do testowania i debugowania. Pokażę oczekiwany sygnał na przykładzie protokołu IR NEC.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Zwykle na początku zakodowanego pakietu znajduje się preambuła. Umożliwia to odbiornikowi określenie poziomu wzmocnienia i tła. Istnieją również protokoły bez preambuły, na przykład Sharp.

Następnie przesyłane są dane. Struktura, preambuła i metoda kodowania bitów są określane przez konkretny protokół.

**Protokół IR NEC** zawiera krótki kod komendy i kod powtórzenia, który jest wysyłany podczas przytrzymywania przycisku. Zarówno kod komendy, jak i kod powtórzenia mają tę samą preambułę na początku.

**Kod komendy NEC**, oprócz preambuły, składa się z bajtu adresu i bajtu numeru komendy, dzięki którym urządzenie rozumie, co należy wykonać. Bajty adresu i numeru komendy są powielane z odwrotnymi wartościami, aby sprawdzić integralność transmisji. Na końcu komendy znajduje się dodatkowy bit stopu.

**Kod powtórzenia** ma "1" po preambule, co jest bitem stopu.

Dla **logiki "0" i "1"** NEC używa kodowania odległości impulsów: najpierw przesyłany jest wybuch impulsu, po którym następuje pauza, której długość ustala wartość bitu.

### Klimatyzatory

W przeciwieństwie do innych pilotów, **klimatyzatory nie przesyłają tylko kodu naciśniętego przycisku**. Przesyłają również **wszystkie informacje**, gdy przycisk jest naciśnięty, aby zapewnić, że **urządzenie klimatyzacyjne i pilot są zsynchronizowane**.\
To zapobiegnie sytuacji, w której urządzenie ustawione na 20ºC zostanie zwiększone do 21ºC za pomocą jednego pilota, a następnie, gdy użyty zostanie inny pilot, który nadal ma temperaturę 20ºC, temperatura zostanie "zwiększona" do 21ºC (a nie do 22ºC, myśląc, że jest w 21ºC).

---

## Ataki i badania ofensywne <a href="#attacks" id="attacks"></a>

Możesz zaatakować podczerwień za pomocą Flipper Zero:

{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Przejęcie Smart-TV / Dekodera (EvilScreen)

Najnowsze prace akademickie (EvilScreen, 2022) wykazały, że **piloty wielokanałowe, które łączą podczerwień z Bluetooth lub Wi-Fi, mogą być nadużywane do pełnego przejęcia nowoczesnych smart-TV**. Atak łączy kody usług IR o wysokich uprawnieniach z uwierzytelnionymi pakietami Bluetooth, omijając izolację kanałów i umożliwiając uruchamianie dowolnych aplikacji, aktywację mikrofonu lub reset fabryczny bez dostępu fizycznego. Osiem popularnych telewizorów od różnych dostawców — w tym model Samsunga, który twierdzi, że spełnia normy ISO/IEC 27001 — zostało potwierdzonych jako podatne. Łagodzenie wymaga poprawek oprogramowania od producenta lub całkowitego wyłączenia nieużywanych odbiorników IR.

### Ekstrakcja danych z powietrza za pomocą diod IR (rodzina aIR-Jumper)

Kamery bezpieczeństwa, routery czy nawet złośliwe pendrive'y często zawierają **diodowe IR do nocnego widzenia**. Badania pokazują, że złośliwe oprogramowanie może modulować te diody (<10–20 kbit/s z prostym OOK), aby **ekstrahować sekrety przez ściany i okna** do zewnętrznej kamery umieszczonej kilkadziesiąt metrów dalej. Ponieważ światło znajduje się poza widzialnym spektrum, operatorzy rzadko to zauważają. Środki zaradcze:

* Fizycznie osłonić lub usunąć diody IR w wrażliwych obszarach
* Monitorować cykl pracy diod LED kamery i integralność oprogramowania
* Zainstalować filtry IR-cut na oknach i kamerach monitorujących

Atakujący może również użyć silnych projektorów IR do **infiltrowania** poleceń do sieci, błyskając dane z powrotem do niebezpiecznych kamer.

### Długozasięgowe ataki brute-force i rozszerzone protokoły z Flipper Zero 1.0

Oprogramowanie 1.0 (wrzesień 2024) dodało **dziesiątki dodatkowych protokołów IR i opcjonalnych modułów wzmacniających**. W połączeniu z trybem brute-force uniwersalnego pilota, Flipper może wyłączyć lub skonfigurować większość publicznych telewizorów/klimatyzatorów z odległości do 30 m, używając diody o dużej mocy.

---

## Narzędzia i praktyczne przykłady <a href="#tooling" id="tooling"></a>

### Sprzęt

* **Flipper Zero** – przenośny transceiver z trybami nauki, powtórzenia i brute-force słownikowego (patrz powyżej).
* **Arduino / ESP32** + dioda IR / odbiornik TSOP38xx – tani analizator/nadajnik DIY. Połącz z biblioteką `Arduino-IRremote` (v4.x obsługuje >40 protokołów).
* **Analizatory logiczne** (Saleae/FX2) – rejestrują surowe czasy, gdy protokół jest nieznany.
* **Smartfony z IR-blasterem** (np. Xiaomi) – szybki test w terenie, ale ograniczony zasięg.

### Oprogramowanie

* **`Arduino-IRremote`** – aktywnie utrzymywana biblioteka C++:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – dekodery GUI, które importują surowe zrzuty i automatycznie identyfikują protokół + generują kod Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – odbieraj i wstrzykuj IR z linii poleceń:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Środki obronne <a href="#defense" id="defense"></a>

* Wyłącz lub zakryj odbiorniki IR w urządzeniach używanych w przestrzeniach publicznych, gdy nie są wymagane.
* Wymuszaj *parowanie* lub kontrole kryptograficzne między smart-TV a pilotami; izoluj uprzywilejowane kody "usługowe".
* Zainstaluj filtry IR-cut lub detektory fal ciągłych wokół obszarów klasyfikowanych, aby przerwać optyczne kanały ukryte.
* Monitoruj integralność oprogramowania kamer/urządzeń IoT, które eksponują kontrolowane diody IR.

## Odniesienia

- [Post na blogu Flipper Zero Infrared](https://blog.flipperzero.one/infrared/)
- EvilScreen: Przejęcie Smart TV poprzez naśladowanie pilota (arXiv 2210.03014)

{{#include ../../banners/hacktricks-training.md}}
