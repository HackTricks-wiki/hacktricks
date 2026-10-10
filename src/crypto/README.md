# Kryptografia

{{#include ../banners/hacktricks-training.md}}

Ta sekcja skupia się na praktycznej kryptografii przy testach bezpieczeństwa i CTF-ach: rozpoznawaniu typowych wzorców, doborze odpowiednich narzędzi i stosowaniu znanych ataków.

Techniki ukrywania danych w plikach opisano w sekcji **Stego**.

## Jak korzystać z tej sekcji

Zacznij od zidentyfikowania prymitywu i jego parametrów. Następnie ustal, nad czym kontrolę ma atakujący lub co może obserwować, na przykład oracle, leaked value albo ponowne użycie nonce, zanim wybierzesz atak.

### Przebieg pracy w CTF

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Kryptografia symetryczna

{{#ref}}
symmetric/README.md
{{#endref}}

### Hashy, MAC-ów i KDF-ów

{{#ref}}
hashes/README.md
{{#endref}}

### Kryptografia klucza publicznego

{{#ref}}
public-key/README.md
{{#endref}}

### TLS i certyfikaty

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Kryptografia w malware

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Różne

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Szybka konfiguracja

Utwórz odizolowane środowisko Python i zainstaluj często używane pakiety. Dokumentacja PyCryptodome zaleca instalację `pycryptodome` za pomocą `pip`; SageMath udostępnia osobne instrukcje instalacji dla każdej obsługiwanej platformy.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```

SageMath jest często przydatny do obliczeń algebraicznych, kratowych, związanych z RSA i krzywymi eliptycznymi.<sup>[[2]](#references)</sup>

## References

- [1] [Dokumentacja PyCryptodome — instalacja](https://www.pycryptodome.org/src/installation)
- [2] [Dokumentacja SageMath — przewodnik instalacji](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
