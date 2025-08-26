# Βασική Μεθοδολογία Forensic

{{#include ../../banners/hacktricks-training.md}}

## Δημιουργία και Προσάρτηση ενός Image


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

Αυτό **δεν είναι απαραίτητα το πρώτο βήμα που πρέπει να εκτελέσετε μόλις έχετε το image**. Αλλά μπορείτε να χρησιμοποιήσετε αυτές τις malware analysis τεχνικές ανεξάρτητα αν έχετε ένα αρχείο, ένα file-system image, memory image, pcap... οπότε είναι καλό να **έχετε αυτές τις ενέργειες στο μυαλό**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Έλεγχος ενός Image

αν σας δοθεί μια **forensic image** μιας συσκευής μπορείτε να ξεκινήσετε **να αναλύετε τα partitions, το file-system** που χρησιμοποιείται και **να ανακτάτε** ενδεχομένως **ενδιαφέροντα αρχεία** (ακόμη και διαγραμμένα). Μάθετε πώς στο:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}# Βασική Μεθοδολογία Forensic



## Δημιουργία και Προσάρτηση ενός Image


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

Αυτό **δεν είναι απαραίτητα το πρώτο βήμα που πρέπει να εκτελέσετε μόλις έχετε το image**. Αλλά μπορείτε να χρησιμοποιήσετε αυτές τις malware analysis τεχνικές ανεξάρτητα αν έχετε ένα αρχείο, ένα file-system image, memory image, pcap... οπότε είναι καλό να **έχετε αυτές τις ενέργειες στο μυαλό**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Έλεγχος ενός Image

αν σας δοθεί μια **forensic image** μιας συσκευής μπορείτε να ξεκινήσετε **να αναλύετε τα partitions, το file-system** που χρησιμοποιείται και **να ανακτάτε** ενδεχομένως **ενδιαφέροντα αρχεία** (ακόμη και διαγραμμένα). Μάθετε πώς στο:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Ανάλογα με τα χρησιμοποιούμενα OSs και ακόμη την πλατφόρμα, πρέπει να αναζητηθούν διαφορετικά ενδιαφέροντα artifacts:


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

## Βαθύς έλεγχος συγκεκριμένων τύπων αρχείων και Software

Αν έχετε ένα πολύ **ύποπτο** **αρχείο**, τότε **ανάλογα με τον τύπο αρχείου και το software** που το δημιούργησε, διάφορα **κόλπα** μπορεί να είναι χρήσιμα.\
Διαβάστε την παρακάτω σελίδα για να μάθετε μερικά ενδιαφέροντα κόλπα:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Θέλω να κάνω ειδική μνεία στη σελίδα:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Memory Dump Inspection


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap Inspection


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Techniques**

Λάβετε υπόψη τη πιθανή χρήση anti-forensic techniques:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}



## Βαθύς έλεγχος συγκεκριμένων τύπων αρχείων και Software

Αν έχετε ένα πολύ **ύποπτο** **αρχείο**, τότε **ανάλογα με τον τύπο αρχείου και το software** που το δημιούργησε, διάφορα **κόλπα** μπορεί να είναι χρήσιμα.\
Διαβάστε την παρακάτω σελίδα για να μάθετε μερικά ενδιαφέροντα κόλπα:


{{#ref}}
specific-software-file-type-tricks/
{{#endref}}

Θέλω να κάνω ειδική μνεία στη σελίδα:


{{#ref}}
specific-software-file-type-tricks/browser-artifacts.md
{{#endref}}

## Memory Dump Inspection


{{#ref}}
memory-dump-analysis/
{{#endref}}

## Pcap Inspection


{{#ref}}
pcap-inspection/
{{#endref}}

## **Anti-Forensic Techniques**

Λάβετε υπόψη τη πιθανή χρήση anti-forensic techniques:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
