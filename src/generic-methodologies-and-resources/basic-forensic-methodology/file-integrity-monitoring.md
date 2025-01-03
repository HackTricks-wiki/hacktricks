{{#include ../../banners/hacktricks-training.md}}

# Podstawa

Podstawa polega na zrobieniu zrzutu niektórych części systemu, aby **porównać go z przyszłym stanem w celu uwydatnienia zmian**.

Na przykład, możesz obliczyć i przechować hash każdego pliku w systemie plików, aby móc dowiedzieć się, które pliki zostały zmodyfikowane.\
Można to również zrobić z kontami użytkowników, uruchomionymi procesami, działającymi usługami i innymi rzeczami, które nie powinny się zbytnio zmieniać lub wcale.

## Monitorowanie integralności plików

Monitorowanie integralności plików (FIM) to kluczowa technika zabezpieczeń, która chroni środowiska IT i dane poprzez śledzenie zmian w plikach. Obejmuje dwa kluczowe kroki:

1. **Porównanie podstawy:** Ustal podstawę, używając atrybutów plików lub kryptograficznych sum kontrolnych (takich jak MD5 lub SHA-2) do przyszłych porównań w celu wykrycia modyfikacji.
2. **Powiadomienie o zmianach w czasie rzeczywistym:** Otrzymuj natychmiastowe powiadomienia, gdy pliki są otwierane lub zmieniane, zazwyczaj za pośrednictwem rozszerzeń jądra systemu operacyjnego.

## Narzędzia

- [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
- [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## Odniesienia

- [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)

{{#include ../../banners/hacktricks-training.md}}
