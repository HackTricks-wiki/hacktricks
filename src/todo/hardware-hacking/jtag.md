# JTAG

{{#include ../../banners/hacktricks-training.md}}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)είναι ένα εργαλείο που μπορεί να χρησιμοποιηθεί με ένα Raspberry PI ή ένα Arduino για να προσπαθήσει να βρει τα JTAG pins από ένα άγνωστο τσιπ.\
Στο **Arduino**, συνδέστε τα **pins από 2 έως 11 σε 10pins που ενδεχομένως ανήκουν σε ένα JTAG**. Φορτώστε το πρόγραμμα στο Arduino και θα προσπαθήσει να βρει με brute force όλα τα pins για να δει αν κάποιο από αυτά ανήκει σε JTAG και ποιο είναι το καθένα.\
Στο **Raspberry PI** μπορείτε να χρησιμοποιήσετε μόνο **pins από 1 έως 6** (6pins, οπότε θα προχωρήσετε πιο αργά δοκιμάζοντας κάθε πιθανό JTAG pin).

### Arduino

Στο Arduino, μετά τη σύνδεση των καλωδίων (pin 2 έως 11 στα JTAG pins και Arduino GND στη βάση GND), **φορτώστε το πρόγραμμα JTAGenum στο Arduino** και στο Serial Monitor στείλτε ένα **`h`** (εντολή για βοήθεια) και θα πρέπει να δείτε τη βοήθεια:

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

Ρυθμίστε **"No line ending" και 115200baud**.\
Στείλτε την εντολή s για να ξεκινήσετε τη σάρωση:

![](<../../images/image (774).png>)

Αν επικοινωνείτε με ένα JTAG, θα βρείτε μία ή περισσότερες **γραμμές που ξεκινούν με FOUND!** υποδεικνύοντας τα pins του JTAG.

{{#include ../../banners/hacktricks-training.md}}
