# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Αν έχετε ένα pcap που περιέχει την επικοινωνία μέσω USB ενός πληκτρολογίου όπως το παρακάτω:

![](<../../../images/image (962).png>)

Μπορείτε να χρησιμοποιήσετε το εργαλείο [**ctf-usb-keyboard-parser**](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser) για να αποκτήσετε ό,τι γράφτηκε στην επικοινωνία:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Μπορείτε να διαβάσετε περισσότερες πληροφορίες και να βρείτε μερικά σενάρια σχετικά με το πώς να αναλύσετε αυτό στο:

- [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
- [https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)

{{#include ../../../banners/hacktricks-training.md}}
