# Βασική Μεθοδολογία Forensics

{{#include ../../banners/hacktricks-training.md}}

## Δημιουργία και Mounting ενός Image


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md
{{#endref}}

## Malware Analysis

Αυτό **δεν είναι απαραίτητα το πρώτο βήμα που πρέπει να εκτελέσετε μόλις αποκτήσετε το image**. Ωστόσο, μπορείτε να χρησιμοποιήσετε ανεξάρτητα αυτές τις τεχνικές malware analysis αν έχετε ένα αρχείο, ένα file-system image, memory image, pcap... επομένως είναι καλό να **έχετε υπόψη αυτές τις ενέργειες**:


{{#ref}}
malware-analysis.md
{{#endref}}

## Επιθεώρηση ενός Image

αν σας δοθεί ένα **forensic image** μιας συσκευής, μπορείτε να ξεκινήσετε την **ανάλυση των partitions και του file-system** που χρησιμοποιείται, καθώς και την **ανάκτηση** δυνητικά **ενδιαφερόντων αρχείων** (ακόμα και διαγραμμένων). Μάθετε πώς:


{{#ref}}
partitions-file-systems-carving/
{{#endref}}

Ανάλογα με τα χρησιμοποιούμενα OSs και, ακόμη, την πλατφόρμα, θα πρέπει να αναζητηθούν διαφορετικά ενδιαφέροντα artifacts:


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

## Ενδελεχής επιθεώρηση συγκεκριμένων τύπων αρχείων και Software

Αν έχετε ένα πολύ **ύποπτο** **αρχείο**, τότε **ανάλογα με τον τύπο του αρχείου και το software** που το δημιούργησε, διάφορα **tricks** μπορεί να φανούν χρήσιμα.\
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

## **Anti-Forensic Techniques**

Έχετε υπόψη την πιθανή χρήση anti-forensic techniques:


{{#ref}}
anti-forensic-techniques.md
{{#endref}}

## Threat Hunting


{{#ref}}
file-integrity-monitoring.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
