# FZ - Podczerwień

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Więcej informacji o działaniu podczerwieni znajdziesz tutaj:


{{#ref}}
../infrared.md
{{#endref}}

## Odbiornik sygnału IR w Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero używa demodulującego odbiornika IR do przechwytywania sygnałów ze standardowych pilotów IR. Niektóre telefony, w tym wybrane modele Xiaomi, mają nadajnik IR, ale większość nie potrafi odbierać i dekodować sygnałów z pilotów.<sup>[[1]](#references)</sup>

Odbiornik podczerwieni Flippera jest **dość czuły**. Możesz nawet **przechwycić sygnał**, znajdując się **gdzieś pomiędzy** pilotem a telewizorem. Nie trzeba kierować pilota bezpośrednio na port IR Flippera. Przydaje się to, gdy ktoś zmienia kanały, stojąc blisko telewizora, a ty i Flipper znajdujecie się w pewnej odległości.

Dekodowanie protokołu odbywa się programowo. Rozpoznane protokoły można zapisać jako zdekodowane komendy; nieobsługiwane protokoły można przechwycić i odtworzyć jako surowe dane czasowe, z uwzględnieniem ograniczeń sprzętu dotyczących częstotliwości nośnej i czasu.<sup>[[1]](#references)</sup>

## Działania

### Uniwersalne piloty

Tryb uniwersalnego pilota Flipper Zero kolejno wysyła znane komendy z bazy danych podczerwieni dla obsługiwanych telewizorów, sprzętu audio, projektorów i klimatyzatorów. Nie ma gwarancji, że będzie sterować każdym urządzeniem. Używaj go wyłącznie na sprzęcie, który posiadasz lub którego testowanie jest dozwolone.<sup>[[1]](#references)</sup>

Wystarczy nacisnąć przycisk zasilania w trybie Universal Remote, a Flipper będzie **kolejno wysyłać komendy „Wyłącz”** do wszystkich znanych mu telewizorów: Sony, Samsung, Panasonic... i tak dalej. Gdy telewizor odbierze sygnał, zareaguje i się wyłączy.

Taki brute-force zajmuje czas. Im większy słownik, tym dłużej potrwa jego przeszukanie. Nie da się ustalić, który dokładnie sygnał rozpoznał telewizor, ponieważ telewizor nie wysyła żadnej informacji zwrotnej.

### Nauka obsługi nowego pilota

Flipper Zero może **przechwycić sygnał podczerwieni**. Jeśli rozpozna protokół i komendę, zapisze zdekodowaną reprezentację; w przeciwnym razie może zapisać surowe dane czasowe do późniejszego odtworzenia.<sup>[[1]](#references)</sup>

## References

- [1] [Przejmowanie kontroli nad telewizorami za pomocą portu podczerwieni Flipper Zero](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
