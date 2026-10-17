# Instruction tracing ARM CoreSight μέσω SWO

{{#include ../../banners/hacktricks-training.md}}

Μια προσβάσιμη [θύρα αποσφαλμάτωσης SWD/JTAG](jtag.md) μπορεί να χρησιμοποιηθεί για την ενεργοποίηση ζωντανής ανίχνευσης εκτέλεσης Cortex-M χωρίς instrumentation του firmware. Αυτό απαιτεί MCU με ETM και TPIU, εκτεθειμένη διαδρομή SWO, αντίγραφο του ακριβούς firmware για την αποκωδικοποίηση και logic analyzer αρκετά γρήγορο για τον επιλεγμένο ρυθμό bit SWO. Σε αντίθεση με τις [μετρήσεις side-channel ισχύος ή EM](side_channel_analysis.md), το ETM είναι ένα debug trace· η καταγραφή και των δύο μπορεί να ευθυγραμμίσει το παρατηρούμενο leak με τον κώδικα που εκτελείται. Η ίδια ευθυγράμμιση μπορεί να βοηθήσει στον χρονισμό του [fault injection](fault_injection_attacks.md).<sup>[[1]](#references)</sup>

Το ETM εκπέμπει συμπιεσμένα συμβάντα ροής ελέγχου αντί για bytes εντολών. Ένας decoder ανακατασκευάζει την εκτέλεση με βάση το αντίστοιχο firmware image. Το ITM μεταφέρει software instrumentation, ενώ το TPIU πλαισιώνει τις πηγές trace και οδηγεί την έξοδο serial-wire. Πριν εφαρμόσετε οποιεσδήποτε τιμές καταχωρητών, ελέγξτε τα στοιχεία CoreSight και το pin multiplexing του στόχου στο εγχειρίδιο αναφοράς του: το παρακάτω παράδειγμα αφορά το STM32F401 και δεν είναι καθολική διαμόρφωση Cortex-M.<sup>[[1]](#references)</sup>

## Εντοπισμός της εξόδου trace

Στο STM32F401, το ασύγχρονο SWO χρησιμοποιεί το PB3. Στον ελεγκτή που εξετάστηκε, το PB3 ήταν συνδεδεμένο με την αντίσταση R15, προσφέροντας προσβάσιμο σημείο probe. Όταν το package ή το net είναι κρυφό, διαμορφώστε προσωρινά το υποψήφιο pin με δυνατότητα SWO ως GPIO και αλλάξτε την κατάστασή του μέσω memory writes SWD. Ελέγξτε τα σημεία της πλακέτας για την αντίστοιχη κυματομορφή και, έπειτα, επαναφέρετε τη διαμόρφωση του pin trace. Συνδέστε τον analyzer με κοινή γείωση και συμβατή λογική τάση.<sup>[[1]](#references)</sup>

## Ενεργοποίηση TPIU και ETM με OpenOCD

Οι παρακάτω εντολές πρέπει να τοποθετηθούν σε διαμόρφωση OpenOCD αφού επιλεγούν ο κατάλληλος adapter και το `target/stm32f4x.cfg`. Το `setbits` διατηρεί τα άσχετα bits στους καταχωρητές ελέγχου, ενώ το `mww` αντικαθιστά ολόκληρη τη λέξη. Αρχικά, το TPIU δρομολογεί το ασύγχρονο trace· έπειτα, το ETM ξεκλειδώνεται, διαμορφώνεται σε λειτουργία προγραμματισμού, λαμβάνει το trace source ID `1` και ξεκινά. Αυτές οι τιμές προέρχονται από τη λειτουργική διαμόρφωση STM32F401 του συγγραφέα, επομένως προσαρμόστε τες στον χάρτη καταχωρητών και το clock tree του στόχου.<sup>[[1]](#references)[[2]](#references)</sup>

<details>
<summary>Διαμόρφωση καταχωρητών trace STM32F401 για OpenOCD</summary>

```tcl
proc setbits {addr mask} {
    mem2array value 32 $addr 1
    set value(0) [expr {$value(0) | $mask}]
    array2mem value 32 $addr 1
}
init
reset halt
setbits 0xe0042004 0x20       ;# DBGMCU_CR: trace I/O, async SWO
setbits 0xe000edfc 0x1000000  ;# DEMCR: TRCENA
mww 0xe0040004 1              ;# TPIU_CPSR: port size
mww 0xe0040010 3              ;# TPIU_ACPR: 16 MHz / (3 + 1) = 4 Mbaud
mww 0xe00400f0 2              ;# TPIU_SPPR: async UART framing
mww 0xe0040304 0x102          ;# TPIU_FFCR: formatter
mww 0xe0041fb0 0xC5ACCE55     ;# ETM_LAR: unlock
mww 0xe0041000 0x00201d0e     ;# ETM_CR: programming mode
mww 0xe0041200 1              ;# ETM_TRACEIDR: source ID 1
mww 0xe0041008 0x0000406F     ;# ETM_TER: trigger event
mww 0xe0041020 0x0000006F     ;# ETM_TEE: trace-enable event
mww 0xe0041024 0x00000001     ;# ETM_TSSR: start trace
mww 0xe0041000 0x0000191E     ;# ETM_CR: leave programming mode
```

</details>

Ο ρυθμός SWO είναι `HCLK / (TPIU_ACPR + 1)`. Με HCLK 16 MHz και `ACPR=3`, η λήψη γίνεται στα 4 Mbaud. Στο PulseView, τοποθετήστε τον ETM decoder πάνω από έναν UART decoder στο κανάλι του SWO analyzer, ορίστε για τον UART τον πραγματικό ρυθμό της γραμμής και χρησιμοποιήστε το ETM source ID που διαμορφώθηκε παραπάνω. Στο παράδειγμα χρησιμοποιήθηκαν δειγματοληψία 24 MHz (έξι δείγματα ανά bit), trigger στην κατερχόμενη ακμή και λήψη με 25% pre-trigger. Μετά τη διαμόρφωση, σταματήστε/κάντε reset στον στόχο, οπλίστε τη λήψη και μετά εκτελέστε `resume`· επαληθεύστε τον συγχρονισμό ETM και μια εύλογη διαδρομή PC σε σχέση με το firmware, αντί να βασιστείτε μόνο σε έξοδο που απλώς μοιάζει αποκωδικοποιημένη.<sup>[[1]](#references)</sup>

## Ανάκαμψη από αλλαγές clock και pin-mux

Δύο ανεξάρτητες ενέργειες του firmware μπορούν να σταματήσουν μια έγκυρη ιχνηλάτηση. Μια αλλαγή PLL αυξάνει το HCLK και, κατά συνέπεια, τον ρυθμό baud του SWO, ενώ το `ACPR` παραμένει σταθερό· έτσι, το επίπεδο UART ανακτά λανθασμένα bytes και η αναπαραγωγή ETM γίνεται ασυνάρτητη. Ελέγξτε τη ρύθμιση RCC/PLL στην [ανάλυση firmware](../firmware-analysis/) και, στο παράδειγμα STM32F401, φορτώστε το Cortex-M image στη διεύθυνση `0x08000000` και εισαγάγετε το SVD του στο Ghidra, ώστε οι εγγραφές στους καταχωρητές clock να εμφανίζονται με ονόματα. Ορίστε ένα hardware breakpoint σε μια εντολή Thumb δύο byte *μετά* την αρχικοποίηση του clock. Στο παράδειγμα, η εντολή `bp 0x080001fa 2 hw` και στη συνέχεια `resume` σταματά την εκτέλεση μετά τη ρύθμιση του PLL· ενώ ο στόχος είναι σταματημένος, η εντολή `mww 0xe0040010 31` ορίζει τον νέο διαιρέτη. Υπολογίστε και ορίστε τον νέο ρυθμό UART, οπλίστε τη λήψη και μετά εκτελέστε ξανά `resume`. Έτσι καταγράφεται η διαδρομή μετά τη μετάβαση· η μετάβαση που χάθηκε δεν ανακτάται.<sup>[[1]](#references)</sup>

Ξεχωριστά, το firmware μπορεί να αντιστοιχίσει ξανά το pad SWO σε άλλο peripheral. Στο παράδειγμα, η ρύθμιση alternate-function του GPIO άλλαξε το PB3 σε I2C2 SDA, οπότε καμία ρύθμιση decoder δεν μπορούσε να επαναφέρει την ιχνηλάτηση σε αυτό το καλώδιο. Εντοπίστε στο firmware την αντίστοιχη αρχικοποίηση GPIO και, στη συνέχεια, είτε αντικαταστήστε τα σημεία κλήσης της με Thumb NOPs ίδιου μεγέθους (`0xBF00` ανά halfword) είτε σταματήστε τον πυρήνα και επαναφέρετε μέσω SWD τη διαμόρφωση pin που είναι συμβατή με την ιχνηλάτηση. Και οι δύο προσεγγίσεις μπορούν να απενεργοποιήσουν το peripheral που εκτοπίζεται· μια επαναφορά κατά την εκτέλεση μπορεί επίσης να αντικατασταθεί ξανά από το firmware. Όταν επαναφέρετε το pin κατά την εκτέλεση, ορίστε τον διαιρέτη SWO σύμφωνα με το τρέχον HCLK.<sup>[[1]](#references)</sup>

## References

- [1] [Ακολουθώντας τις εντολές: Ζωντανή ιχνηλάτηση ARM με ETM, ITM και TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples: Διαμόρφωση STM32F4 OpenOCD ETM/TPIU](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)
{{#include ../../banners/hacktricks-training.md}}
