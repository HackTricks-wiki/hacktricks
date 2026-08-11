# FZ - Podczerwień

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Więcej informacji o działaniu podczerwieni znajdziesz tutaj:


{{#ref}}
../infrared.md
{{#endref}}

## Odbiornik sygnału IR w Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero korzysta z demodulującego odbiornika IR do przechwytywania sygnałów ze standardowych pilotów na podczerwień. Niektóre telefony, w tym wybrane modele Xiaomi, mają nadajnik IR, ale większość z nich nie potrafi odbierać ani dekodować sygnałów zdalnego sterowania.<sup>[[1]](#references)</sup>

**Odbiornik podczerwieni Flippera jest bardzo czuły**. Możesz nawet **przechwycić sygnał**, pozostając **gdzieś pomiędzy** pilotem a telewizorem. Nie ma potrzeby kierowania pilota bezpośrednio na port IR Flippera. Przydaje się to, gdy ktoś przełącza kanały, stojąc blisko telewizora, a zarówno Ty, jak i Flipper znajdujecie się w pewnej odległości.

Dekodowanie protokołu odbywa się programowo. Rozpoznane protokoły mogą być przechowywane jako zdekodowane komendy; nieobsługiwane protokoły można przechwytywać i odtwarzać jako surowe dane czasowe, z uwzględnieniem ograniczeń sprzętowych dotyczących częstotliwości nośnej i taktowania.<sup>[[1]](#references)</sup>

## Działania

### Uniwersalne piloty

Tryb uniwersalnego pilota Flipper Zero przechodzi przez znane komendy z bazy danych podczerwieni dla obsługiwanych telewizorów, urządzeń audio, projektorów i klimatyzatorów. Nie ma gwarancji, że będzie sterować każdym urządzeniem, dlatego należy go używać wyłącznie ze sprzętem będącym Twoją własnością lub takim, do którego testowania masz upoważnienie.<sup>[[1]](#references)</sup>

W trybie Universal Remote wystarczy nacisnąć przycisk zasilania, a Flipper będzie **sekwencyjnie wysyłać komendy „Power Off”** dla wszystkich znanych mu telewizorów: Sony, Samsung, Panasonic... i tak dalej. Gdy telewizor odbierze właściwy sygnał, zareaguje i wyłączy się.

Taki brute-force zajmuje czas. Im większy słownik, tym dłużej potrwa jego przeszukanie. Nie da się dowiedzieć, który dokładnie sygnał został rozpoznany przez telewizor, ponieważ telewizor nie przekazuje żadnej informacji zwrotnej.

### Nauka nowego pilota

Flipper Zero może **przechwycić sygnał podczerwieni**. Jeśli rozpozna protokół i komendę, zapisuje zdekodowaną reprezentację; w przeciwnym razie może zapisać surowe dane czasowe do późniejszego odtworzenia.<sup>[[1]](#references)</sup>

## References

- [1] [Przejmowanie kontroli nad telewizorami za pomocą portu podczerwieni Flipper Zero](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
