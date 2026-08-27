# Injection σε εφαρμογές Erlang και Elixir στο macOS

{{#include ../../../banners/hacktricks-training.md}}

## `ERL_AFLAGS`, `ERL_FLAGS` και `ERL_ZFLAGS`

Ο launcher `erl` προσθέτει το `ERL_AFLAGS` στην αρχή της command line και τα `ERL_FLAGS` / `ERL_ZFLAGS` στο τέλος. Επειδή το `-eval` αξιολογεί μια έκφραση Erlang κατά την αρχικοποίηση της VM, αυτές οι μεταβλητές μπορούν να παρέχουν fileless code execution πριν από το προβλεπόμενο workload.<sup>[[1]](#references)</sup>
```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```
Τα Elixir, Mix, Phoenix και πολλές Elixir releases εκκινούν τελικά το Erlang VM και ενδέχεται να κληρονομούν αυτές τις flags. Επιβεβαιώστε το ακριβές release wrapper: μπορεί να ανακατασκευάζει ή να καθαρίζει τα VM arguments, ενώ ορισμένα εργαλεία υποστηρίζουν ρητά τα `ERL_AFLAGS`, `ERL_ZFLAGS` ή `ELIXIR_ERL_OPTIONS`.<sup>[[2]](#references)</sup>

Σε αντίθεση με τις περισσότερες τεχνικές που βασίζονται σε αρχεία, το payload του `-eval` δεν χρειάζεται αρχείο ελεγχόμενο από τον attacker. Ένα trusted wrapper θα πρέπει να διαγράφει και τις τρεις μεταβλητές flags της Erlang (καθώς και το `ELIXIR_ERL_OPTIONS` για το Elixir) πριν από την εκκίνηση του runtime· μην επιχειρείτε να κάνετε allowlist μεμονωμένων VM flags, εκτός εάν ο parser και η σειρά επεξεργασίας είναι πλήρως κατανοητά.

## References

- [1] [`erl` command and environment variables](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [2] [Elixir releases και επιλογές περιβάλλοντος του VM](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
