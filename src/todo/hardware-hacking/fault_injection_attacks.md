# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection celowo zakłóca działanie urządzenia podczas jego pracy, aby wykonało ono nieprawidłowe obliczenie. Użyteczna usterka może pominąć instrukcję, uszkodzić dane, ominąć kontrolę bezpieczeństwa lub wygenerować wadliwy wynik kryptograficzny, z którego można wyprowadzić poufne informacje.<sup>[[1]](#references)</sup>

Typowe techniki polegają na manipulowaniu napięciem zasilania lub zegarem, wstrzykiwaniu zakłóceń elektromagnetycznych albo stosowaniu stymulacji optycznej lub laserowej.<sup>[[1]](#references)</sup> Różnią się precyzją i inwazyjnością, ale skuteczne testowanie zazwyczaj wymaga powtarzalnego wyzwalania oraz systematycznego przeszukiwania zakresów czasu, szerokości impulsu i intensywności. Rozpocznij od stabilnego stanu bazowego, rejestruj osobno restarty i zniekształcone wyniki oraz zmieniaj jeden parametr naraz.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Nieinwazyjna metoda Fault Injection bez wyzwalania, oparta na celowych zakłóceniach elektromagnetycznych](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [Dokumentacja ChipWhisperer - Przegląd i porównanie sprzętu do przechwytywania](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
