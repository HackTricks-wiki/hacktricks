# FZ - Infrared

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Więcej informacji o działaniu Infrared znajdziesz tutaj:


{{#ref}}
../infrared.md
{{#endref}}

## Odbiornik sygnału IR w Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper korzysta z cyfrowego odbiornika sygnału IR TSOP, który **umożliwia przechwytywanie sygnałów z pilotów IR**. Istnieją **smartfony**, takie jak Xiaomi, które również mają port IR, ale należy pamiętać, że **większość z nich może tylko transmitować** sygnały i **nie potrafi ich odbierać**.<sup>[[1]](#references)</sup>

Odbiornik podczerwieni Flippera jest **bardzo czuły**. Możesz nawet **przechwycić sygnał**, pozostając **gdzieś pomiędzy** pilotem a telewizorem. Nie ma potrzeby kierowania pilota bezpośrednio na port IR Flippera. Jest to przydatne, gdy ktoś zmienia kanały, stojąc obok telewizora, a Ty i Flipper znajdujecie się w pewnej odległości.

Ponieważ **dekodowanie** sygnału podczerwieni odbywa się po stronie **software**, Flipper Zero potencjalnie obsługuje **odbieranie i transmitowanie dowolnych kodów pilotów IR**. W przypadku **nieznanych** protokołów, których nie udało się rozpoznać, **zapisuje i odtwarza** surowy sygnał dokładnie w takiej postaci, w jakiej został odebrany.<sup>[[1]](#references)</sup>

## Działania

### Uniwersalne piloty

Flipper Zero może służyć jako **uniwersalny pilot do sterowania dowolnym telewizorem, klimatyzatorem lub centrum multimedialnym**. W tym trybie Flipper wykonuje **bruteforces** wszystkich **znanych kodów** wszystkich obsługiwanych producentów **zgodnie ze słownikiem zapisanym na karcie SD**. Nie musisz wybierać konkretnego pilota, aby wyłączyć telewizor w restauracji.<sup>[[1]](#references)</sup>

Wystarczy nacisnąć przycisk zasilania w trybie Universal Remote, a Flipper będzie **sekwencyjnie wysyłać** polecenia „Power Off” do wszystkich znanych mu telewizorów: Sony, Samsung, Panasonic... i tak dalej. Gdy telewizor odbierze swój sygnał, zareaguje i wyłączy się.

Takie brute-force zajmuje czas. Im większy słownik, tym dłużej potrwa zakończenie procesu. Nie da się dowiedzieć, który dokładnie sygnał został rozpoznany przez telewizor, ponieważ telewizor nie przekazuje żadnej informacji zwrotnej.

### Nauka nowego pilota

Za pomocą Flipper Zero można **przechwycić sygnał podczerwieni**. Jeśli **znajdzie sygnał w bazie danych**, Flipper automatycznie **rozpozna, jakie to urządzenie**, i pozwoli Ci z nim wchodzić w interakcję.\
Jeśli go nie znajdzie, Flipper może **zapisać** **sygnał** i umożliwić jego **odtworzenie**.<sup>[[1]](#references)</sup>

## Źródła

- [1] [Taking over TVs with Flipper Zero Infrared Port](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
