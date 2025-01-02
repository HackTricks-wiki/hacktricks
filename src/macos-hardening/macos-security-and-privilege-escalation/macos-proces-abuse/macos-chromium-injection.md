# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Οι περιηγητές που βασίζονται στο Chromium, όπως το Google Chrome, το Microsoft Edge, το Brave και άλλοι. Αυτοί οι περιηγητές είναι χτισμένοι πάνω στο έργο ανοιχτού κώδικα Chromium, που σημαίνει ότι μοιράζονται μια κοινή βάση και, επομένως, έχουν παρόμοιες λειτουργίες και επιλογές προγραμματιστή.

#### `--load-extension` Flag

Η σημαία `--load-extension` χρησιμοποιείται κατά την εκκίνηση ενός περιηγητή που βασίζεται στο Chromium από τη γραμμή εντολών ή ένα σενάριο. Αυτή η σημαία επιτρέπει να **φορτωθεί αυτόματα μία ή περισσότερες επεκτάσεις** στον περιηγητή κατά την εκκίνηση.

#### `--use-fake-ui-for-media-stream` Flag

Η σημαία `--use-fake-ui-for-media-stream` είναι μια άλλη επιλογή γραμμής εντολών που μπορεί να χρησιμοποιηθεί για να ξεκινήσει περιηγητές που βασίζονται στο Chromium. Αυτή η σημαία έχει σχεδιαστεί για να **παρακάμπτει τις κανονικές προτροπές χρήστη που ζητούν άδεια για πρόσβαση σε ροές μέσων από την κάμερα και το μικρόφωνο**. Όταν χρησιμοποιείται αυτή η σημαία, ο περιηγητής χορηγεί αυτόματα άδεια σε οποιαδήποτε ιστοσελίδα ή εφαρμογή ζητά πρόσβαση στην κάμερα ή το μικρόφωνο.

### Tools

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop)
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO)

### Example
```bash
# Intercept traffic
voodoo intercept -b chrome
```
Βρείτε περισσότερα παραδείγματα στους συνδέσμους εργαλείων

## Αναφορές

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)

{{#include ../../../banners/hacktricks-training.md}}
