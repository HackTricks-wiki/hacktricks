# Ανάλυση memory dump

{{#include ../../../banners/hacktricks-training.md}}

## Έναρξη

Ξεκινήστε να **αναζητάτε** **malware** μέσα στο pcap. Χρησιμοποιήστε τα **εργαλεία** που αναφέρονται στο [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Το Volatility είναι το κύριο open-source framework για την ανάλυση memory dump**. Αυτό το Python tool αναλύει dumps από εξωτερικές πηγές ή VMware VMs, εντοπίζοντας δεδομένα όπως processes και passwords με βάση το OS profile του dump. Είναι επεκτάσιμο μέσω plugins, γεγονός που το καθιστά ιδιαίτερα ευέλικτο για forensic investigations.

[**Βρείτε εδώ ένα cheatsheet**](volatility-cheatsheet.md)

## Mini dump crash report

Όταν το dump είναι μικρό (μόλις μερικά KB, ίσως μερικά MB), τότε πιθανότατα πρόκειται για mini dump crash report και όχι για memory dump.

![Volatility - Mini dump crash report: Όταν το dump είναι μικρό (μόλις μερικά KB, ίσως μερικά MB), τότε πιθανότατα πρόκειται για mini dump crash report και όχι για memory dump](<../../../images/image (532).png>)

Αν έχετε εγκατεστημένο το Visual Studio, μπορείτε να ανοίξετε αυτό το αρχείο και να αντλήσετε βασικές πληροφορίες, όπως το όνομα του process, την αρχιτεκτονική, πληροφορίες για το exception και τα modules που εκτελούνται:

![Volatility - Mini dump crash report: Αν έχετε εγκατεστημένο το Visual Studio, μπορείτε να ανοίξετε αυτό το αρχείο και να αντλήσετε βασικές πληροφορίες, όπως το όνομα του process, την αρχιτεκτονική, πληροφορίες για το exception και...](<../../../images/image (263).png>)

Μπορείτε επίσης να φορτώσετε το exception και να δείτε τις decompiled instructions

![Volatility - Mini dump crash report: Μπορείτε επίσης να φορτώσετε το exception και να δείτε τις decompiled instructions](<../../../images/image (142).png>)

![Volatility - Mini dump crash report: Μπορείτε επίσης να φορτώσετε το exception και να δείτε τις decompiled instructions](<../../../images/image (610).png>)

Σε κάθε περίπτωση, το Visual Studio δεν είναι το καλύτερο εργαλείο για ανάλυση σε βάθος του dump.

Θα πρέπει να το **ανοίξετε** χρησιμοποιώντας το **IDA** ή το **Radare**, για να το επιθεωρήσετε σε **βάθος**.

{{#include ../../../banners/hacktricks-training.md}}
