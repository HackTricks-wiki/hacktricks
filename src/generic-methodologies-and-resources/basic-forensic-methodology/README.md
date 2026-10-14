# Βασική Εγκληματολογική Μεθοδολογία

{{#include ../../banners/hacktricks-training.md}}

## Δημιουργία και Προσάρτηση Εικόνας


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Ανάλυση Malware

Αυτό **δεν είναι απαραίτητα το πρώτο βήμα που πρέπει να εκτελέσετε μόλις αποκτήσετε την εικόνα**. Ωστόσο, μπορείτε να χρησιμοποιήσετε αυτές τις τεχνικές ανάλυσης malware ανεξάρτητα, αν έχετε ένα αρχείο, μια εικόνα συστήματος αρχείων, μια εικόνα μνήμης, ένα pcap... επομένως είναι καλό να **έχετε αυτές τις ενέργειες υπόψη**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Επιθεώρηση Εικόνας

αν σας δοθεί μια **forensic εικόνα** μιας συσκευής, μπορείτε να ξεκινήσετε **αναλύοντας τις κατατμήσεις και το σύστημα αρχείων** που χρησιμοποιείται, καθώς και **ανακτώντας** δυνητικά **ενδιαφέροντα αρχεία** (ακόμα και διαγραμμένα). Μάθετε πώς:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Ανάλογα με τα λειτουργικά συστήματα και ακόμα και την πλατφόρμα που χρησιμοποιούνται, πρέπει να αναζητηθούν διαφορετικά ενδιαφέροντα artifacts:


{{#ref}}
windows-forensics/
{{#endref}}


{{#ref}}
linux-forensics.md
{{#endref}}


{{#ref}}
docker-forensics.md
{{#endref}}


{{#ref}}
ios-backup-forensics.md
{{#endref}}

Για κλειδωμένη συσκευή Android, διαδρομές απόκτησης και απεικόνιση μνήμης, δείτε το [Android forensics](android-forensics.md).

## Λεπτομερής επιθεώρηση συγκεκριμένων τύπων αρχείων και λογισμικού

Αν έχετε ένα πολύ **ύποπτο** **αρχείο**, τότε **ανάλογα με τον τύπο του αρχείου και το λογισμικό** που το δημιούργησε, μπορεί να φανούν χρήσιμα διάφορα **tricks**.\
Διαβάστε την ακόλουθη σελίδα για να μάθετε μερικά ενδιαφέροντα tricks:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Θέλω να κάνω ειδική αναφορά στη σελίδα:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Επιθεώρηση Memory Dump


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Επιθεώρηση Pcap


{{#ref}}
pcap-inspection/
{{#endref}}

## **Τεχνικές Anti-Forensics**

Έχετε υπόψη την πιθανή χρήση τεχνικών anti-forensics:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Κυνήγι Απειλών


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

## References

{{#include ../../banners/hacktricks-training.md}}
