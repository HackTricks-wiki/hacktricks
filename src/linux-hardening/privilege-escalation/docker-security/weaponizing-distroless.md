# Weaponizing Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Co to jest Distroless

Kontener distroless to rodzaj kontenera, który **zawiera tylko niezbędne zależności do uruchomienia konkretnej aplikacji**, bez dodatkowego oprogramowania lub narzędzi, które nie są wymagane. Te kontenery są zaprojektowane, aby być jak **najlżejsze** i **bezpieczne** jak to możliwe, a ich celem jest **minimalizacja powierzchni ataku** poprzez usunięcie wszelkich zbędnych komponentów.

Kontenery distroless są często używane w **środowiskach produkcyjnych, gdzie bezpieczeństwo i niezawodność są kluczowe**.

Niektóre **przykłady** **kontenerów distroless** to:

- Dostarczone przez **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- Dostarczone przez **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Celem uzbrojenia kontenera distroless jest możliwość **wykonywania dowolnych binarek i ładunków, nawet z ograniczeniami** narzuconymi przez **distroless** (brak powszechnych binarek w systemie) oraz ochronami powszechnie spotykanymi w kontenerach, takimi jak **tylko do odczytu** lub **brak wykonania** w `/dev/shm`.

### Przez pamięć

Nadchodzi w pewnym momencie 2023...

### Poprzez istniejące binarki

#### openssl

\***\*[**W tym poście,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) wyjaśniono, że binarka **`openssl`** jest często znajdowana w tych kontenerach, potencjalnie dlatego, że jest **potrzebna** przez oprogramowanie, które ma działać wewnątrz kontenera.

{{#include ../../../banners/hacktricks-training.md}}
