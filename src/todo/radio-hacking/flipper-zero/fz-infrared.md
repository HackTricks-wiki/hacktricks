# FZ - Infrared

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Aby uzyskać więcej informacji na temat działania podczerwieni, sprawdź:

{{#ref}}
../infrared.md
{{#endref}}

## Odbiornik sygnału IR w Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper używa cyfrowego odbiornika sygnału IR TSOP, który **pozwala na przechwytywanie sygnałów z pilotów IR**. Istnieją niektóre **smartfony**, takie jak Xiaomi, które również mają port IR, ale pamiętaj, że **większość z nich może tylko przesyłać** sygnały i jest **niezdolna do ich odbierania**.

Odbiornik podczerwieni Flippera **jest dość czuły**. Możesz nawet **złapać sygnał**, pozostając **gdzieś pomiędzy** pilotem a telewizorem. Nie ma potrzeby, aby celować pilotem bezpośrednio w port IR Flippera. To jest przydatne, gdy ktoś zmienia kanały, stojąc blisko telewizora, a zarówno ty, jak i Flipper jesteście w pewnej odległości.

Ponieważ **dekodowanie sygnału podczerwieni** odbywa się po stronie **oprogramowania**, Flipper Zero potencjalnie obsługuje **odbiór i transmisję dowolnych kodów pilotów IR**. W przypadku **nieznanych** protokołów, które nie mogły zostać rozpoznane - **nagrywa i odtwarza** surowy sygnał dokładnie tak, jak został odebrany.

## Akcje

### Uniwersalne Piloty

Flipper Zero może być używany jako **uniwersalny pilot do sterowania dowolnym telewizorem, klimatyzatorem lub centrum multimedialnym**. W tym trybie Flipper **bruteforcuje** wszystkie **znane kody** wszystkich obsługiwanych producentów **zgodnie ze słownikiem z karty SD**. Nie musisz wybierać konkretnego pilota, aby wyłączyć telewizor w restauracji.

Wystarczy nacisnąć przycisk zasilania w trybie Uniwersalnego Pilota, a Flipper **sekwencyjnie wyśle komendy "Power Off"** wszystkich telewizorów, które zna: Sony, Samsung, Panasonic... i tak dalej. Gdy telewizor odbierze swój sygnał, zareaguje i wyłączy się.

Taki brute-force zajmuje czas. Im większy słownik, tym dłużej to potrwa. Niemożliwe jest ustalenie, który sygnał dokładnie telewizor rozpoznał, ponieważ nie ma informacji zwrotnej z telewizora.

### Nauka Nowego Pilota

Możliwe jest **przechwycenie sygnału podczerwieni** za pomocą Flippera Zero. Jeśli **znajdzie sygnał w bazie danych**, Flipper automatycznie **będzie wiedział, jakie to urządzenie** i pozwoli ci z nim interagować.\
Jeśli nie, Flipper może **zapisać** **sygnał** i pozwoli ci **go odtworzyć**.

## Referencje

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
