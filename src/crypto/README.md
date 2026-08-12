# Kryptografia

{{#include ../banners/hacktricks-training.md}}

Ta sekcja koncentruje się na praktycznej kryptografii na potrzeby testów bezpieczeństwa i CTF: rozpoznawaniu typowych wzorców, wyborze odpowiednich narzędzi i stosowaniu znanych ataków.

Techniki ukrywania danych w plikach opisano w sekcji **Stego**.

## Jak korzystać z tej sekcji

Zacznij od zidentyfikowania prymitywu i jego parametrów. Następnie ustal, co kontroluje lub obserwuje atakujący, na przykład oracle, leaked value lub ponowne użycie nonce, zanim wybierzesz atak.

### Workflow CTF

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Kryptografia symetryczna

{{#ref}}
symmetric/README.md
{{#endref}}

### Hashe, MAC-i i KDF-y

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

Utwórz izolowane środowisko Python i zainstaluj powszechnie używane pakiety. Dokumentacja PyCryptodome zaleca instalację `pycryptodome` za pomocą `pip`; SageMath udostępnia osobne instrukcje instalacji dla każdej obsługiwanej platformy.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```
SageMath jest często przydatny do obliczeń algebraicznych, kratowych, RSA i obliczeń na krzywych eliptycznych.<sup>[[2]](#references)</sup>

## References

- [1] [Dokumentacja PyCryptodome - Instalacja](https://www.pycryptodome.org/src/installation)
- [2] [Dokumentacja SageMath - Przewodnik instalacji](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
