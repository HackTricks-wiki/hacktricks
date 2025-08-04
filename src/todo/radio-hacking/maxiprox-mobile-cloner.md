# Budowanie przenośnego klonera HID MaxiProx 125 kHz

{{#include ../../banners/hacktricks-training.md}}

## Cel
Przekształcenie zasilanego z sieci czytnika HID MaxiProx 5375 o dużym zasięgu 125 kHz w przenośny, zasilany bateryjnie kloner identyfikatorów, który cicho zbiera karty zbliżeniowe podczas ocen bezpieczeństwa fizycznego.

Konwersja opisana tutaj opiera się na serii badań TrustedSec „Let’s Clone a Cloner – Part 3: Putting It All Together” i łączy aspekty mechaniczne, elektryczne i RF, aby końcowe urządzenie mogło być wrzucone do plecaka i natychmiast użyte na miejscu.

> [!warning]
> Manipulowanie sprzętem zasilanym z sieci i bankami zasilania litowo-jonowego może być niebezpieczne. Zweryfikuj każde połączenie **przed** zasileniem obwodu i trzymaj anteny, kable koncentryczne i płaszczyzny uziemiające dokładnie tak, jak były w fabrycznym projekcie, aby uniknąć detuningu czytnika.

## Lista materiałów (BOM)

* Czytnik HID MaxiProx 5375 (lub dowolny 12 V czytnik HID Prox® o dużym zasięgu)
* Narzędzie ESP RFID v2.2 (sniffer/logger Wiegand oparty na ESP32)
* Moduł wyzwalacza USB-PD (Power-Delivery) zdolny do negocjacji 12 V @ ≥3 A
* Bank zasilania USB-C 100 W (wyjścia 12 V PD)
* Przewód 26 AWG z izolacją silikonową – czerwony/biały
* Przełącznik SPST montowany na panelu (do wyłącznika sygnalizatora)
* Osłona przełącznika NKK AT4072 / osłona przeciwwypadkowa
* Lutownica, plecionka lutownicza i odsysacz
* Narzędzia ręczne o klasie ABS: piła do metalu, nóż uniwersalny, pilniki płaskie i półokrągłe
* Wiertła 1/16″ (1,5 mm) i 1/8″ (3 mm)
* Taśma dwustronna 3 M VHB i opaski zaciskowe

## 1. Podsystem zasilania

1. Usuń lut i wyjmij fabryczną płytkę konwertera buck, używaną do generowania 5 V dla PCB logiki.
2. Zamontuj wyzwalacz USB-PD obok narzędzia ESP RFID i poprowadź gniazdo USB-C wyzwalacza na zewnątrz obudowy.
3. Wyzwalacz PD negocjuje 12 V z banku zasilania i podaje je bezpośrednio do MaxiProx (czytnik oczekuje natywnie 10–14 V). Druga szyna 5 V jest pobierana z płytki ESP, aby zasilać wszelkie akcesoria.
4. Akumulator 100 W jest umieszczony na równi z wewnętrznym dystansem, aby **żadne** kable zasilające nie były zawieszone na antenie ferrytowej, co zachowuje wydajność RF.

## 2. Wyłącznik sygnalizatora – cicha praca

1. Zlokalizuj dwa pady głośnika na płytce logiki MaxiProx.
2. Oczyść *oba* pady, a następnie przelutuj tylko **ujemny** pad.
3. Przylutuj przewody 26 AWG (biały = ujemny, czerwony = dodatni) do padów sygnalizatora i poprowadź je przez nowo wycięty otwór do przełącznika SPST montowanego na panelu.
4. Gdy przełącznik jest otwarty, obwód sygnalizatora jest przerwany, a czytnik działa w całkowitej ciszy – idealne do dyskretnego zbierania identyfikatorów.
5. Umieść sprężynową osłonę bezpieczeństwa NKK AT4072 na przełączniku. Ostrożnie powiększ otwór za pomocą piły do metalu / pilnika, aż zatrzaśnie się na korpusie przełącznika. Osłona zapobiega przypadkowemu włączeniu wewnątrz plecaka.

## 3. Obudowa i prace mechaniczne

• Użyj nożyc do cięcia na równo, a następnie noża i pilnika, aby *usunąć* wewnętrzny „wypust” ABS, aby duży akumulator USB-C leżał płasko na dystansie.
• Wytnij dwa równoległe kanały w ścianie obudowy dla kabla USB-C; to blokuje akumulator na miejscu i eliminuje ruch/wibracje.
• Stwórz prostokątny otwór dla przycisku **zasilania** akumulatora:
1. Przyklej papierowy szablon nad lokalizacją.
2. Wywierć otwory pilotowe 1/16″ w każdym z czterech rogów.
3. Powiększ otwory wiertłem 1/8″.
4. Połącz otwory za pomocą piły do metalu; wykończ krawędzie pilnikiem.
✱ Unikano użycia wiertarki Dremel – szybkie wiertło topnieje grubego ABS i pozostawia brzydką krawędź.

## 4. Ostateczny montaż

1. Zainstaluj ponownie płytkę logiki MaxiProx i przelutuj przewód SMA do padów uziemiających PCB czytnika.
2. Zamontuj narzędzie ESP RFID i wyzwalacz USB-PD za pomocą taśmy 3 M VHB.
3. Uporządkuj wszystkie przewody za pomocą opasek zaciskowych, trzymając przewody zasilające **daleko** od pętli antenowej.
4. Dokręć śruby obudowy, aż akumulator będzie lekko sprężony; wewnętrzny opór zapobiega przesuwaniu się pakietu, gdy urządzenie odbija się po każdym odczycie karty.

## 5. Testy zasięgu i ekranowania

* Używając karty testowej 125 kHz **Pupa**, przenośny kloner osiągnął stałe odczyty na poziomie **≈ 8 cm** w wolnej przestrzeni – identycznie jak w przypadku zasilania z sieci.
* Umieszczenie czytnika wewnątrz cienkościennego metalowego pudełka na pieniądze (aby symulować biurko w banku) zmniejszyło zasięg do ≤ 2 cm, potwierdzając, że znaczne metalowe obudowy działają jako skuteczne ekrany RF.

## Przepływ pracy

1. Naładuj akumulator USB-C, podłącz go i włącz główny przełącznik zasilania.
2. (Opcjonalnie) Otwórz osłonę sygnalizatora i włącz sygnał dźwiękowy podczas testowania na stole; zamknij go przed dyskretnym użyciem w terenie.
3. Przejdź obok docelowego posiadacza identyfikatora – MaxiProx zasilą kartę, a narzędzie ESP RFID przechwyci strumień Wiegand.
4. Przekaż przechwycone dane przez Wi-Fi lub USB-UART i odtwórz/klonuj w razie potrzeby.

## Rozwiązywanie problemów

| Objaw | Prawdopodobna przyczyna | Naprawa |
|-------|-------------------------|---------|
| Czytnik restartuje się po zbliżeniu karty | Wyzwalacz PD negocjował 9 V zamiast 12 V | Zweryfikuj zworki wyzwalacza / spróbuj wyższej mocy kabla USB-C |
| Brak zasięgu odczytu | Akumulator lub przewody leżą *na górze* anteny | Przeprowadź kable na nowo i zachowaj 2 cm odstępu wokół pętli ferrytowej |
| Sygnalizator nadal piszczy | Przełącznik podłączony do dodatniego przewodu zamiast ujemnego | Przenieś wyłącznik, aby przerwać **ujemny** tor głośnika |

## Odniesienia

- [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
