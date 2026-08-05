# Budowa przenośnego mobilnego cloner'a HID MaxiProx 125 kHz

{{#include ../../banners/hacktricks-training.md}}

## Cel
Przekształcenie zasilanego z sieci czytnika dalekiego zasięgu HID MaxiProx 5375 125 kHz w przenośny, zasilany baterią cloner kart, który podczas ocen physical-security po cichu przechwytuje karty proximity.

Opisana tutaj konwersja bazuje na serii badań TrustedSec „Let’s Clone a Cloner – Part 3: Putting It All Together” i łączy aspekty mechaniczne, elektryczne oraz RF, aby finalne urządzenie można było wrzucić do plecaka i natychmiast użyć na miejscu.<sup>[[1]](#references)</sup>

> [!warning]
> Manipulowanie urządzeniami zasilanymi z sieci oraz power-bankami Lithium-ion może być niebezpieczne. Zweryfikuj każde połączenie **przed** zasileniem obwodu i pozostaw anteny, przewody koncentryczne oraz płaszczyzny masy dokładnie w takim układzie, jak w konstrukcji fabrycznej, aby uniknąć rozstrojenia czytnika.

## Zestawienie materiałów (BOM)

* Czytnik HID MaxiProx 5375 (lub dowolny dalekiego zasięgu czytnik HID Prox® 12 V)
* ESP RFID Tool v2.2 (sniffer/logger Wiegand oparty na ESP32)
* Moduł triggera USB-PD (Power-Delivery) zdolny negocjować 12 V @ ≥3 A
* Power-bank USB-C 100 W (udostępniający profil 12 V PD)
* Przewód połączeniowy 26 AWG z izolacją silikonową – czerwony/biały
* Przełącznik dźwigniowy SPST do montażu panelowego (wyłącznik beepera)
* Osłona przełącznika / nasadka zabezpieczająca przed przypadkowym uruchomieniem NKK AT4072
* Lutownica, taśma rozlutownicza i odsysacz do cyny
* Narzędzia ręczne do ABS: piła kabłąkowa, nóż uniwersalny, pilniki płaski i półokrągły
* Wiertła 1/16″ (1,5 mm) i 1/8″ (3 mm)
* Dwustronna taśma 3 M VHB i opaski zaciskowe

## 1. Podsystem zasilania

1. Rozlutuj i usuń fabryczną płytkę przetwornicy buck używaną do generowania 5 V dla płytki logicznej.
2. Zamontuj trigger USB-PD obok ESP RFID Tool i wyprowadź gniazdo USB-C triggera na zewnątrz obudowy.
3. Trigger PD negocjuje 12 V z power-bankiem i zasila nimi bezpośrednio MaxiProx (czytnik natywnie wymaga 10–14 V). Dodatkowa szyna 5 V jest pobierana z płytki ESP w celu zasilania akcesoriów.
4. Akumulator 100 W jest umieszczony równo przy wewnętrznym dystansie, dzięki czemu **żadne** przewody zasilające nie przebiegają nad anteną ferrytową, co pozwala zachować parametry RF.

## 2. Wyłącznik beepera – cicha praca

1. Zlokalizuj dwa pola głośnika na płytce logicznej MaxiProx.
2. Oczyść rozlutownicą *oba* pola, a następnie przylutuj ponownie tylko pole **ujemne**.
3. Przylutuj przewody 26 AWG (biały = ujemny, czerwony = dodatni) do pól beepera i przeprowadź je przez nowo wycięte gniazdo do przełącznika SPST montowanego w panelu.
4. Gdy przełącznik jest otwarty, obwód beepera zostaje przerwany, a czytnik działa całkowicie bezgłośnie – idealnie do covert przechwytywania kart.
5. Załóż sprężynową nasadkę zabezpieczającą NKK AT4072 na przełącznik. Ostrożnie powiększ otwór piłą kabłąkową / pilnikiem, aż nasadka zatrzaśnie się na korpusie przełącznika. Osłona zapobiega przypadkowemu uruchomieniu wewnątrz plecaka.

## 3. Obudowa i prace mechaniczne

• Użyj obcinaka czołowego, a następnie noża i pilnika, aby *usunąć* wewnętrzne wybrzuszenie ABS, dzięki czemu duży akumulator USB-C będzie płasko przylegał do dystansu.
• Wytnij w ściance obudowy dwa równoległe kanały na przewód USB-C; unieruchomi to akumulator i wyeliminuje ruchy oraz wibracje.
• Wykonaj prostokątny otwór na przycisk **zasilania** akumulatora:
1. Przyklej papierowy szablon w odpowiednim miejscu.
2. Wywierć otwory prowadzące 1/16″ we wszystkich czterech rogach.
3. Powiększ je wiertłem 1/8″.
4. Połącz otwory piłą kabłąkową; wykończ krawędzie pilnikiem.
✱  Unikano użycia obrotowego narzędzia Dremel – szybko obracające się wiertło topi gruby ABS i pozostawia nieestetyczną krawędź.

## 4. Montaż końcowy

1. Ponownie zamontuj płytkę logiczną MaxiProx i przylutuj przewód SMA do pola masy na PCB czytnika.
2. Zamocuj ESP RFID Tool i trigger USB-PD za pomocą taśmy VHB 3 M.
3. Uporządkuj wszystkie przewody opaskami zaciskowymi, trzymając przewody zasilające **z dala** od pętli anteny.
4. Dokręć śruby obudowy do momentu lekkiego ściśnięcia akumulatora; wewnętrzne tarcie zapobiega przesuwaniu się pakietu, gdy urządzenie odrzuca się po każdym odczycie karty.

## 5. Testy zasięgu i ekranowania

* Z użyciem testowej karty **Pupa** 125 kHz przenośny cloner uzyskał stabilne odczyty z odległości **≈ 8 cm** w wolnej przestrzeni – identycznie jak podczas pracy z zasilaniem sieciowym.<sup>[[1]](#references)</sup>
* Umieszczenie czytnika w metalowej kasetce z cienkimi ściankami (w celu zasymulowania biurka w lobby banku) zmniejszyło zasięg do ≤ 2 cm, potwierdzając, że znaczne metalowe obudowy działają jak skuteczne ekrany RF.<sup>[[1]](#references)</sup>

## Procedura użycia

1. Naładuj akumulator USB-C, podłącz go i przełącz główny przełącznik zasilania.
2. (Opcjonalnie) Otwórz osłonę beepera i włącz sygnalizację dźwiękową podczas testów na stanowisku; zablokuj ją przed użyciem covert w terenie.
3. Przejdź obok posiadacza docelowej karty – MaxiProx wzbudzi kartę, a ESP RFID Tool przechwyci strumień Wiegand.
4. Zrzuć przechwycone dane uwierzytelniające przez Wi-Fi lub USB-UART i odtwórz/sklonuj je zgodnie z potrzebami.

## Rozwiązywanie problemów

| Objaw | Prawdopodobna przyczyna | Rozwiązanie |
|---------|--------------|------|
| Czytnik uruchamia się ponownie po przyłożeniu karty | Trigger PD wynegocjował 9 V zamiast 12 V | Sprawdź zworki triggera / użyj przewodu USB-C o wyższej mocy |
| Brak zasięgu odczytu | Akumulator lub przewody znajdują się *na* antenie | Zmień przebieg przewodów i zachowaj 2 cm odstępu wokół pętli ferrytowej |
| Beeper nadal emituje dźwięk | Przełącznik podłączono na przewodzie dodatnim zamiast ujemnym | Przenieś wyłącznik, aby przerywał **ujemną** ścieżkę głośnika |

## References

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
