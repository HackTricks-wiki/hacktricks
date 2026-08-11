# Το πρωτόκολλο Modbus

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή στο Modbus

Το Modbus είναι ένα ανοικτό πρωτόκολλο επιπέδου εφαρμογής, το οποίο υλοποιείται ευρέως από PLCs, αισθητήρες, actuators και άλλες βιομηχανικές συσκευές. Το μοντέλο request/response εκθέτει coils και registers μέσω function codes. Επομένως, το security testing επικεντρώνεται σε μη εξουσιοδοτημένες αναγνώσεις/εγγραφές, παρατήρηση traffic, replay και μη ασφαλή συμπεριφορά συσκευών — όχι απλώς στον εντοπισμό της TCP port 502.<sup>[[1]](#references)</sup>

Πολλές εγκαταστάσεις διατηρούν legacy serial εξοπλισμό, επειδή οι αναβαθμίσεις απαιτούν downtime, επαναπιστοποίηση ή αντικατάσταση field devices. Το παραδοσιακό Modbus δεν παρέχει ούτε confidentiality ούτε peer authentication. Το Modbus Security είναι ένα ξεχωριστό TLS-based profile που χρησιμοποιεί X.509 certificates και την TCP port 802. Επειδή η specification είναι δημόσια και μπορεί να υλοποιηθεί ανεξάρτητα, η συμπεριφορά των vendors και η υποστήριξη optional functions διαφέρουν και θα πρέπει να γίνεται fingerprinting αντί να θεωρούνται δεδομένες.<sup>[[1]](#references)[[2]](#references)</sup>

## Η αρχιτεκτονική Client-Server

Στη σύγχρονη ορολογία, ένας **client** ξεκινά μια transaction και ένας **server** επιστρέφει response. Η παλαιότερη τεκμηρίωση χρησιμοποιεί τους όρους **master/slave**. Μην συγχέετε αυτή τη σχέση σε επίπεδο εφαρμογής με τα SPI ή I2C: πρόκειται για διαφορετικά bus protocols.<sup>[[1]](#references)</sup>

## Serial και Ethernet transports

Τα ίδια Modbus application data μπορούν να μεταφερθούν μέσω serial variants (RTU ή ASCII framing) και μέσω Modbus TCP. Το Modbus TCP προσθέτει ένα MBAP header και συνήθως χρησιμοποιεί την TCP port 502. Το serial RTU χρησιμοποιεί compact binary framing και CRC, ενώ το serial ASCII αναπαριστά τα bytes ως hexadecimal characters και χρησιμοποιεί LRC.<sup>[[1]](#references)[[3]](#references)</sup>

## Αναπαράσταση δεδομένων

Το data model αποτελείται από single-bit coils/discrete inputs και 16-bit input/holding registers. Οι τιμές πολλαπλών registers, η σειρά των bytes, η κλιμάκωση και η σημασιολογική τους σημασία εξαρτώνται από τη συσκευή και πρέπει να επιβεβαιώνονται με βάση το register map του vendor.<sup>[[1]](#references)</sup>

## Function codes

Τα function codes επιλέγουν operations όπως η ανάγνωση coils (`0x01`), η ανάγνωση holding registers (`0x03`), η εγγραφή ενός coil/register (`0x05`/`0x06`) και η εγγραφή πολλαπλών coils/registers (`0x0F`/`0x10`). Ένα captured write request μπορεί να είναι replayable όταν η εγκατάσταση δεν διαθέτει compensating authentication ή ελέγχους process-state. Με εξουσιοδοτημένη φυσική πρόσβαση σε μεγάλες serial διαδρομές, ένας assessor μπορεί επίσης να καταγράψει ή να inject frames απευθείας στην καλωδίωση, αφού αναγνωρίσει το electrical interface, το termination και την ασφαλή μέθοδο σύνδεσης. Κάθε ενέργεια μπορεί να επηρεάσει τη φυσική διαδικασία, επομένως χρησιμοποιήστε lab ή explicit operational authorization.<sup>[[1]](#references)[[3]](#references)</sup>

## Addressing

Οι serial devices χρησιμοποιούν unit address. Το Modbus TCP χρησιμοποιεί IP addressing καθώς και ένα Unit Identifier στο MBAP header, κάτι ιδιαίτερα σημαντικό όταν ένα TCP-to-serial gateway δρομολογεί requests σε downstream units. Οι register references που εμφανίζονται στην τεκμηρίωση προϊόντων μπορεί να είναι one-based (`40001`), ενώ οι protocol addresses είναι zero-based, γεγονός που αποτελεί συχνή πηγή off-by-one errors.<sup>[[1]](#references)[[3]](#references)</sup>

Το serial framing περιλαμβάνει ελέγχους transmission errors (CRC για RTU και LRC για ASCII), ενώ το TCP παρέχει το κανονικό transport checksum. Αυτά εντοπίζουν τυχαία corruption· δεν αποτελούν cryptographic integrity ή origin authentication.<sup>[[3]](#references)</sup>

Κατά τη διάρκεια ενός authorized assessment, ελέγξτε το exposure, τα επιτρεπόμενα function codes, τα writable address ranges, το exception handling, τα rate limits και το κατά πόσο το network segmentation ή ένα Modbus-aware firewall περιορίζει τους clients. Οι σχετικές απειλές περιλαμβάνουν passive disclosure, unauthorized command injection, replay, data forgery και denial of service. Συντονίστε όλα τα active tests με τους process owners, επειδή φαινομενικά μικρές αλλαγές σε registers μπορούν να μεταβάλουν μια φυσική διαδικασία.

## References

- [1] [Οργανισμός Modbus — Προδιαγραφή πρωτοκόλλου εφαρμογής Modbus V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf)
- [2] [Οργανισμός Modbus — Πρωτόκολλο Modbus Security και οδηγοί υλοποίησης](https://www.modbus.org/modbus-specifications)
- [3] [Οργανισμός Modbus — Προδιαγραφή και οδηγός υλοποίησης Modbus μέσω Serial Line V1.02](https://www.modbus.org/file/secure/modbusoverserial.pdf)
{{#include ../../banners/hacktricks-training.md}}
