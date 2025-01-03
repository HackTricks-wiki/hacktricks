{{#include ../../../banners/hacktricks-training.md}}

Αν έχετε ένα pcap μιας σύνδεσης USB με πολλές διακοπές, πιθανότατα είναι μια σύνδεση USB πληκτρολογίου.

Ένας φίλτρο wireshark όπως αυτός θα μπορούσε να είναι χρήσιμος: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

Είναι σημαντικό να γνωρίζετε ότι τα δεδομένα που ξεκινούν με "02" πατιούνται χρησιμοποιώντας shift.

Μπορείτε να διαβάσετε περισσότερες πληροφορίες και να βρείτε μερικά σενάρια σχετικά με το πώς να αναλύσετε αυτό σε:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
