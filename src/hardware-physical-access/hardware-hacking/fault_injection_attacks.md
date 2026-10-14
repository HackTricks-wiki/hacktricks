# Ataki z wstrzykiwaniem błędów

{{#include ../../banners/hacktricks-training.md}}

Wstrzykiwanie błędów — w pracach nad bezpieczeństwem sprzętu często nazywane **glitchingiem** — polega na celowym zakłócaniu działania urządzenia, aby wykonywało nieprawidłowe obliczenia. Przydatny błąd może spowodować pominięcie instrukcji, uszkodzenie danych, ominięcie kontroli bezpieczeństwa lub wygenerowanie nieprawidłowego wyniku kryptograficznego, z którego można wywnioskować tajne informacje.<sup>[[1]](#references)</sup>

Typowe techniki polegają na manipulowaniu napięciem zasilania lub sygnałem zegarowym, wprowadzaniu zakłóceń elektromagnetycznych albo stosowaniu stymulacji optycznej lub laserowej.<sup>[[1]](#references)</sup> Różnią się precyzją i inwazyjnością, ale skuteczne testy zazwyczaj wymagają powtarzalnego wyzwalania oraz systematycznego sprawdzania różnych wartości czasu, szerokości impulsu i natężenia. Zacznij od stabilnego stanu bazowego, osobno zapisuj restarty i nieprawidłowe wyniki, a następnie zmieniaj jeden parametr naraz.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Nieinwazyjna metoda wstrzykiwania błędów bez wyzwalania, oparta na celowych zakłóceniach elektromagnetycznych](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [Dokumentacja ChipWhisperer - Przegląd i porównanie sprzętu do przechwytywania](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
