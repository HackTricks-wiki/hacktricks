# Budowa przenośnego mobilnego klonera HID MaxiProx 125 kHz

{{#include ../../banners/hacktricks-training.md}}

## Cel
Przekształcenie zasilanego z sieci czytnika dalekiego zasięgu HID MaxiProx 5375 125 kHz w przenośny, zasilany bateryjnie kloner kart, który po cichu przechwytuje karty zbliżeniowe podczas testów bezpieczeństwa fizycznego.

Opisana tu konwersja opiera się na serii badań TrustedSec „Sklonujmy klonera – część 3: składamy wszystko w całość” i łączy zagadnienia mechaniczne, elektryczne oraz radiowe, aby gotowe urządzenie można było wrzucić do plecaka i od razu użyć w terenie.<sup>[[1]](#references)</sup>

> [!warning]
> Praca z urządzeniami zasilanymi z sieci i powerbankami litowo-jonowymi może być niebezpieczna. Przed **włączeniem** układu sprawdź wszystkie połączenia, a anteny, przewód koncentryczny i płaszczyzny masy pozostaw dokładnie w fabrycznym układzie, aby uniknąć rozstrojenia czytnika.

## Zestawienie materiałów (BOM)

* Czytnik HID MaxiProx 5375 (lub dowolny dalekiego zasięgu czytnik HID Prox® 12 V)
* ESP RFID Tool v2.2 (sniffer/logger Wiegand oparty na ESP32)
* Moduł wyzwalacza USB-PD (Power-Delivery) obsługujący negocjację 12 V przy ≥3 A
* Powerbank 100 W USB-C (profil wyjściowy 12 V PD)
* Przewód montażowy 26 AWG w izolacji silikonowej – czerwony/biały
* Panelowy przełącznik SPST (do wyłącznika brzęczyka)
* Osłona przełącznika NKK AT4072 / nasadka chroniąca przed przypadkowym uruchomieniem
* Lutownica, plecionka do rozlutowywania i odsysacz cyny
* Narzędzia ręczne do ABS: piła włośnica, nóż uniwersalny, pilniki płaski i półokrągły
* Wiertła 1/16″ (1,5 mm) i 1/8″ (3 mm)
* Dwustronna taśma 3 M VHB i opaski zaciskowe

## 1. Podsystem zasilania

1. Rozlutuj i usuń fabryczną płytkę przetwornicy obniżającej napięcie, używaną do uzyskania 5 V dla płytki logicznej.
2. Zamontuj wyzwalacz USB-PD obok ESP RFID Tool i poprowadź jego gniazdo USB-C na zewnątrz obudowy.
3. Wyzwalacz PD negocjuje z powerbankiem napięcie 12 V i podaje je bezpośrednio do MaxiProx (czytnik standardowo wymaga 10–14 V). Dodatkowa linia 5 V jest pobierana z płytki ESP do zasilania akcesoriów.
4. Powerbank 100 W umieszcza się równo przy wewnętrznym wsporniku, tak aby **żadne** przewody zasilające nie przebiegały nad anteną ferrytową, co pozwala zachować parametry RF.

## 2. Wyłącznik brzęczyka – cicha praca

1. Znajdź dwa pola lutownicze głośnika na płytce logicznej MaxiProx.
2. Oczyść plecionką *oba* pola, a następnie przylutuj ponownie tylko pole **ujemne**.
3. Przylutuj przewody 26 AWG (biały = ujemny, czerwony = dodatni) do pól brzęczyka i poprowadź je przez nowo wycięty otwór do panelowego przełącznika SPST.
4. Gdy przełącznik jest otwarty, obwód brzęczyka zostaje przerwany, a czytnik działa całkowicie bezgłośnie – idealnie do potajemnego przechwytywania danych kart.
5. Załóż na przełącznik sprężynową osłonę zabezpieczającą NKK AT4072. Ostrożnie powiększ otwór piłą włośnicą lub pilnikiem, aż osłona zatrzaśnie się na korpusie przełącznika. Osłona zapobiega przypadkowemu włączeniu urządzenia w plecaku.

## 3. Obudowa i prace mechaniczne

• Użyj cążek, a następnie noża i pilnika, aby *usunąć* wewnętrzne zgrubienie z ABS, tak by duży akumulator USB-C płasko przylegał do wspornika.
• Wytnij w ściance obudowy dwa równoległe kanały na przewód USB-C; unieruchomią one akumulator i zapobiegną jego przesuwaniu się oraz drganiom.
• Wykonaj prostokątny otwór na przycisk **zasilania** akumulatora:
  1. Przyklej w tym miejscu papierowy szablon taśmą.
  2. Wywierć otwory prowadzące wiertłem 1/16″ we wszystkich czterech narożnikach.
  3. Powiększ otwory wiertłem 1/8″.
  4. Połącz otwory piłą włośnicą, a krawędzie wygładź pilnikiem.  
  ✱  Zrezygnowano z obrotowego narzędzia Dremel – szybko obracające się wiertło topi gruby ABS i pozostawia nieestetyczną krawędź.

## 4. Montaż końcowy

1. Zamontuj ponownie płytkę logiczną MaxiProx i przylutuj przewód SMA do pola masy na płytce PCB czytnika.
2. Zamocuj ESP RFID Tool i wyzwalacz USB-PD taśmą 3 M VHB.
3. Uporządkuj przewody opaskami zaciskowymi, prowadząc przewody zasilające **daleko** od pętli anteny.
4. Dokręć śruby obudowy tak, aby akumulator był lekko ściśnięty; tarcie wewnątrz zapobiega przesunięciu się akumulatora, gdy urządzenie odskakuje po każdym odczycie karty.

## 5. Testy zasięgu i ekranowania

* Z kartą testową 125 kHz **Pupa** przenośny kloner uzyskiwał powtarzalne odczyty z odległości **≈ 8 cm** w otwartej przestrzeni – tak samo jak podczas pracy z zasilaniem sieciowym.<sup>[[1]](#references)</sup>
* Umieszczenie czytnika w cienkościennym metalowym kasetniku (symulującym biurko w holu banku) zmniejszyło zasięg do ≤ 2 cm, co potwierdza, że masywne metalowe obudowy skutecznie ekranują RF.<sup>[[1]](#references)</sup>

## Procedura użycia

1. Naładuj akumulator USB-C, podłącz go i przestaw główny przełącznik zasilania.
2. (Opcjonalnie) Otwórz osłonę brzęczyka i włącz sygnały dźwiękowe podczas testów na stanowisku; przed użyciem w terenie zamknij osłonę.
3. Przejdź obok osoby mającej kartę – MaxiProx wzbudzi kartę, a ESP RFID Tool przechwyci strumień Wiegand.
4. Zrzuć przechwycone dane uwierzytelniające przez Wi-Fi lub USB-UART i w razie potrzeby odtwórz/sklonuj je.

## Rozwiązywanie problemów

| Objaw | Prawdopodobna przyczyna | Rozwiązanie |
|---------|--------------|------|
| Czytnik uruchamia się ponownie po przyłożeniu karty | Wyzwalacz PD negocjuje 9 V zamiast 12 V | Sprawdź zworki wyzwalacza / użyj przewodu USB-C o większej mocy |
| Brak zasięgu odczytu | Akumulator lub przewody leżą *na* antenie | Poprowadź przewody inaczej i zachowaj 2 cm odstępu wokół pętli ferrytowej |
| Brzęczyk nadal pika | Przełącznik jest podłączony do przewodu dodatniego zamiast ujemnego | Przenieś wyłącznik, aby przerywał **ujemną** ścieżkę głośnika |

## References

- [1] [Sklonujmy klonera – część 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)
{{#include ../../banners/hacktricks-training.md}}