# Επιθέσεις Fault Injection

{{#include ../../banners/hacktricks-training.md}}

Το Fault injection - που συχνά αποκαλείται **glitching** στον χώρο του hardware security - διαταράσσει σκόπιμα μια συσκευή ενώ λειτουργεί, ώστε να εκτελέσει έναν εσφαλμένο υπολογισμό. Ένα χρήσιμο fault μπορεί να παρακάμψει μια εντολή, να καταστρέψει δεδομένα, να παρακάμψει έναν έλεγχο ασφαλείας ή να παράγει εσφαλμένο κρυπτογραφικό αποτέλεσμα, από το οποίο μπορούν να εξαχθούν μυστικές πληροφορίες.<sup>[[1]](#references)</sup>

Οι συνήθεις τεχνικές χειραγωγούν την τάση τροφοδοσίας ή το clock, εισάγουν ηλεκτρομαγνητικές παρεμβολές ή χρησιμοποιούν οπτική ή laser διέγερση.<sup>[[1]](#references)</sup> Η ακρίβεια και η παρεμβατικότητά τους διαφέρουν, όμως οι επιτυχημένες δοκιμές απαιτούν γενικά ένα επαναλήψιμο trigger και συστηματικές σαρώσεις ως προς τον χρονισμό, το πλάτος παλμού και την ένταση. Ξεκινήστε με ένα σταθερό baseline, καταγράψτε ξεχωριστά τα resets και τις μη έγκυρες εξόδους και αλλάζετε μία παράμετρο κάθε φορά.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Μη παρεμβατική μέθοδος Fault Injection χωρίς trigger, βασισμένη σε σκόπιμη ηλεκτρομαγνητική παρεμβολή](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [Τεκμηρίωση ChipWhisperer - Επισκόπηση και σύγκριση hardware καταγραφής](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
