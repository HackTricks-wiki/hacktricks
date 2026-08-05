# Κατασκευή φορητού HID MaxiProx 125 kHz Mobile Cloner

{{#include ../../banners/hacktricks-training.md}}

## Στόχος
Μετατροπή ενός τροφοδοτούμενου από το δίκτυο HID MaxiProx 5375 long-range 125 kHz reader σε field-deployable, battery-powered badge cloner που συλλέγει αθόρυβα proximity cards κατά τη διάρκεια physical-security assessments.

Η μετατροπή που παρουσιάζεται εδώ βασίζεται στη σειρά ερευνών “Let’s Clone a Cloner – Part 3: Putting It All Together” της TrustedSec και συνδυάζει mechanical, electrical και RF considerations, ώστε η τελική συσκευή να μπορεί να τοποθετηθεί σε backpack και να χρησιμοποιηθεί άμεσα στο πεδίο.<sup>[[1]](#references)</sup>

> [!warning]
> Ο χειρισμός mains-powered εξοπλισμού και Lithium-ion power-banks μπορεί να είναι επικίνδυνος.  Επαληθεύστε κάθε σύνδεση **πριν** ενεργοποιήσετε το κύκλωμα και διατηρήστε τις κεραίες, τα coax και τα ground planes ακριβώς όπως ήταν στον εργοστασιακό σχεδιασμό, ώστε να αποφύγετε το detuning του reader.

## Λίστα υλικών (BOM)

* HID MaxiProx 5375 reader (ή οποιοσδήποτε 12 V HID Prox® long-range reader)
* ESP RFID Tool v2.2 (Wiegand sniffer/logger βασισμένο σε ESP32)
* USB-PD (Power-Delivery) trigger module με δυνατότητα διαπραγμάτευσης 12 V @ ≥3 A
* 100 W USB-C power-bank (παρέχει 12 V PD profile)
* 26 AWG silicone-insulated hook-up wire – red/white
* Panel-mount SPST toggle switch (για beeper kill-switch)
* NKK AT4072 switch-guard / accident-proof cap
* Soldering iron, solder wick & desolder pump
* ABS-rated hand tools: coping-saw, utility-knife, flat & half-round files
* Drill bits 1/16″ (1.5 mm) και 1/8″ (3 mm)
* 3 M VHB double-sided tape & Zip-ties

## 1. Power Sub-System

1. Αφαιρέστε με desoldering και απομακρύνετε το factory buck-converter daughter-board που χρησιμοποιείται για την παραγωγή 5 V για το logic PCB.
2. Τοποθετήστε ένα USB-PD trigger δίπλα στο ESP RFID Tool και περάστε το USB-C receptacle του trigger προς το εξωτερικό του enclosure.
3. Το PD trigger διαπραγματεύεται 12 V από το power-bank και τα τροφοδοτεί απευθείας στο MaxiProx (ο reader αναμένει εγγενώς 10–14 V). Ένα δευτερεύον 5 V rail λαμβάνεται από το ESP board για την τροφοδοσία τυχόν accessories.
4. Το 100 W battery pack τοποθετείται επίπεδα πάνω στο εσωτερικό standoff, ώστε να **μην** υπάρχουν power cables που περνούν πάνω από τη ferrite antenna, διατηρώντας την RF performance.

## 2. Beeper Kill-Switch – Αθόρυβη λειτουργία

1. Εντοπίστε τα δύο speaker pads στο MaxiProx logic board.
2. Απομακρύνετε το solder και από τα *δύο* pads, έπειτα επανακολλήστε μόνο το **αρνητικό** pad.
3. Κολλήστε wires 26 AWG (λευκό = αρνητικό, κόκκινο = θετικό) στα beeper pads και περάστε τα μέσα από μια νέα σχισμή προς ένα panel-mount SPST switch.
4. Όταν ο switch είναι ανοιχτός, το beeper circuit διακόπτεται και ο reader λειτουργεί εντελώς αθόρυβα – ιδανικό για covert badge harvesting.
5. Τοποθετήστε ένα NKK AT4072 spring-loaded safety cap πάνω από το toggle. Μεγαλώστε προσεκτικά το bore με coping-saw / file μέχρι να ασφαλίσει πάνω στο σώμα του switch. Το guard αποτρέπει την τυχαία ενεργοποίηση μέσα σε backpack.

## 3. Enclosure & Mechanical Work

• Χρησιμοποιήστε flush cutters και στη συνέχεια knife & file για να *αφαιρέσετε* το εσωτερικό ABS “bump-out”, ώστε η μεγάλη USB-C battery να κάθεται επίπεδα πάνω στο standoff.
• Χαράξτε δύο παράλληλα channels στο τοίχωμα του enclosure για το USB-C cable· αυτό ασφαλίζει τη battery στη θέση της και εξαλείφει την κίνηση/δόνηση.
• Δημιουργήστε ένα rectangular aperture για το **power** button της battery:
1. Κολλήστε ένα paper stencil πάνω από το σημείο.
2. Ανοίξτε 1/16″ pilot holes και στις τέσσερις γωνίες.
3. Μεγαλώστε τα με bit 1/8″.
4. Ενώστε τις οπές με coping saw· ολοκληρώστε τις ακμές με file.
✱  Ένα rotary Dremel *αποφεύχθηκε* – το high-speed bit λιώνει το παχύ ABS και αφήνει μια αντιαισθητική ακμή.

## 4. Final Assembly

1. Επανατοποθετήστε το MaxiProx logic board και επανακολλήστε το SMA pigtail στο reader’s PCB ground pad.
2. Στερεώστε το ESP RFID Tool και το USB-PD trigger χρησιμοποιώντας 3 M VHB.
3. Τακτοποιήστε όλη την καλωδίωση με zip-ties, κρατώντας τα power leads **μακριά** από το antenna loop.
4. Σφίξτε τις βίδες του enclosure μέχρι η battery να συμπιεστεί ελαφρά· η εσωτερική τριβή εμποδίζει το pack να μετακινηθεί όταν η συσκευή ανακρούει μετά από κάθε card read.

## 5. Range & Shielding Tests

* Με χρήση μιας 125 kHz **Pupa** test card, το portable cloner πέτυχε σταθερά reads σε απόσταση **≈ 8 cm** σε free-air – ίδια με τη λειτουργία με τροφοδοσία από το δίκτυο.<sup>[[1]](#references)</sup>
* Η τοποθέτηση του reader μέσα σε ένα thin-walled metal cash box (για προσομοίωση desk σε bank lobby) μείωσε το range σε ≤ 2 cm, επιβεβαιώνοντας ότι τα substantial metal enclosures λειτουργούν ως αποτελεσματικά RF shields.<sup>[[1]](#references)</sup>

## Workflow χρήσης

1. Φορτίστε τη USB-C battery, συνδέστε την και ενεργοποιήστε τον main power switch.
2. (Προαιρετικά) Ανοίξτε το beeper guard και ενεργοποιήστε το audible feedback κατά το bench-testing· ασφαλίστε το πριν από covert field use.
3. Περάστε δίπλα από τον holder του target badge – το MaxiProx θα ενεργοποιήσει την card και το ESP RFID Tool θα καταγράψει το Wiegand stream.
4. Κάντε dump τα captured credentials μέσω Wi-Fi ή USB-UART και κάντε replay/clone όπως απαιτείται.

## Troubleshooting

| Σύμπτωμα | Πιθανή αιτία | Επιδιόρθωση |
|---------|--------------|------|
| Ο reader κάνει reboot όταν παρουσιάζεται card | Το PD trigger διαπραγματεύτηκε 9 V αντί για 12 V | Επαληθεύστε τα trigger jumpers / δοκιμάστε USB-C cable υψηλότερης ισχύος |
| Δεν υπάρχει read range | Η battery ή η καλωδίωση βρίσκεται *πάνω* από την antenna | Περάστε ξανά τα cables και διατηρήστε clearance 2 cm γύρω από το ferrite loop |
| Το beeper συνεχίζει να κάνει chirp | Ο switch είναι συνδεδεμένος στο positive lead αντί για το negative | Μετακινήστε το kill-switch ώστε να διακόπτει το **αρνητικό** speaker trace |

## References

- [1] [Let’s Clone a Cloner – Part 3 (TrustedSec)](https://trustedsec.com/blog/lets-clone-a-cloner-part-3-putting-it-all-together)

{{#include ../../banners/hacktricks-training.md}}
