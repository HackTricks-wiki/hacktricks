# Radio

{{#include ../../banners/hacktricks-training.md}}

## SigDigger

Το [**SigDigger** ](https://github.com/BatchDrake/SigDigger) είναι ένας δωρεάν digital signal analyzer για GNU/Linux και macOS, σχεδιασμένος για την εξαγωγή πληροφοριών από άγνωστα radio signals. Υποστηρίζει διάφορες SDR συσκευές μέσω του SoapySDR και επιτρέπει ρυθμιζόμενη demodulation σημάτων FSK, PSK και ASK, αποκωδικοποίηση αναλογικού video, ανάλυση bursty signals και ακρόαση αναλογικών voice channels (όλα σε real time).<sup>[[1]](#references)</sup>

### Basic Config

Μετά την εγκατάσταση υπάρχουν μερικά πράγματα που μπορείτε να εξετάσετε να ρυθμίσετε.\
Στις ρυθμίσεις (το δεύτερο tab button) μπορείτε να επιλέξετε τη **SDR device** ή να **select a file** για ανάγνωση, καθώς και τη συχνότητα στην οποία θα γίνει syntonise και το Sample rate (συνιστάται έως 2.56Msps, αν το PC σας το υποστηρίζει).

![SigDigger settings showing SDR device, input file, frequency and sample rate options](<../../images/image (245).png>)

Στο GUI behaviour συνιστάται να ενεργοποιήσετε μερικές επιλογές, αν το PC σας τις υποστηρίζει:

![SigDigger - Basic Config: In the GUI behaviour it's recommended to enable a few things if your PC support it](<../../images/image (472).png>)

> [!TIP]
> Αν διαπιστώσετε ότι το PC σας δεν κάνει capture σωστά, δοκιμάστε να απενεργοποιήσετε το OpenGL και να μειώσετε το sample rate.

### Uses

- Για να **capture κάποια χρονική περίοδο ενός signal και να το αναλύσετε**, κρατήστε πατημένο το κουμπί "Push to capture" για όσο χρειάζεται.

![Basic Config - Uses: Just to capture some time of a signal and analyze it just maintain the button "Push to capture" as long as you need](<../../images/image (960).png>)

- Ο **Tuner** του SigDigger βοηθά στην **καλύτερη λήψη signals** (αλλά μπορεί επίσης να τα υποβαθμίσει). Ιδανικά ξεκινήστε από το 0 και συνεχίστε να **το αυξάνετε μέχρι** ο **θόρυβος** που εισάγεται να είναι **μεγαλύτερος από τη βελτίωση του signal** που χρειάζεστε.

![SigDigger tuner control adjusted to improve the captured radio signal](<../../images/image (1099).png>)

### Synchronize with radio channel

Με το [**SigDigger** ](https://github.com/BatchDrake/SigDigger) κάντε synchronize με το channel που θέλετε να ακούσετε, ρυθμίστε την επιλογή "Baseband audio preview", ρυθμίστε το bandwith ώστε να λαμβάνετε όλες τις πληροφορίες που αποστέλλονται και, στη συνέχεια, ρυθμίστε το Tuner στο επίπεδο πριν αρχίσει πραγματικά να αυξάνεται ο θόρυβος:<sup>[[1]](#references)</sup>

![SigDigger synchronized radio channel with baseband audio preview and bandwidth configured](<../../images/image (585).png>)

## Interesting tricks

- Όταν μια συσκευή στέλνει bursts πληροφοριών, συνήθως το **πρώτο μέρος είναι preamble**, οπότε **δεν χρειάζεται να ανησυχείτε** αν **δεν βρείτε πληροφορίες** εκεί **ή αν υπάρχουν ορισμένα errors**.
- Στα frames πληροφοριών συνήθως θα πρέπει να **βρείτε διαφορετικά frames καλά ευθυγραμμισμένα μεταξύ τους**:

![Synchronize with radio channel - Interesting tricks: In frames of information you usually should find different frames well aligned between them](<../../images/image (1076).png>)

![Synchronize with radio channel - Interesting tricks: In frames of information you usually should find different frames well aligned between them](<../../images/image (597).png>)

- **Μετά την ανάκτηση των bits μπορεί να χρειαστεί να τα επεξεργαστείτε με κάποιον τρόπο**. Για παράδειγμα, στη Manchester codification ένα up+down θα είναι 1 ή 0 και ένα down+up θα είναι το άλλο. Επομένως, ζεύγη από 1 και 0 (ups και downs) θα αντιστοιχούν σε ένα πραγματικό 1 ή 0.
- Ακόμη και αν ένα signal χρησιμοποιεί Manchester codification (είναι αδύνατο να βρείτε περισσότερα από δύο 0 ή 1 στη σειρά), μπορεί να **βρείτε πολλά συνεχόμενα 1 ή 0 στο preamble**!

### Uncovering modulation type with IQ

Υπάρχουν 3 τρόποι αποθήκευσης πληροφοριών σε signals: με modulation του **amplitude**, του **frequency** ή του **phase**.\
Αν εξετάζετε ένα signal, υπάρχουν διάφοροι τρόποι για να προσπαθήσετε να καταλάβετε τι χρησιμοποιείται για την αποθήκευση πληροφοριών (βρείτε περισσότερους τρόπους παρακάτω), αλλά ένας καλός τρόπος είναι να ελέγξετε το IQ graph.

![SigDigger IQ graph used to identify whether a signal uses amplitude, frequency or phase modulation](<../../images/image (788).png>)

- **Detecting AM**: Αν στο IQ graph εμφανίζονται, για παράδειγμα, **2 κύκλοι** (πιθανώς ένας στο 0 και ένας σε διαφορετικό amplitude), αυτό μπορεί να σημαίνει ότι πρόκειται για AM signal. Αυτό συμβαίνει επειδή στο IQ graph η απόσταση μεταξύ του 0 και του κύκλου είναι το amplitude του signal, επομένως είναι εύκολο να απεικονιστούν διαφορετικά amplitudes.
- **Detecting PM**: Όπως στην προηγούμενη εικόνα, αν βρείτε μικρούς κύκλους που δεν σχετίζονται μεταξύ τους, πιθανότατα χρησιμοποιείται phase modulation. Αυτό συμβαίνει επειδή στο IQ graph η γωνία μεταξύ του σημείου και του 0,0 είναι το phase του signal, πράγμα που σημαίνει ότι χρησιμοποιούνται 4 διαφορετικά phases.
- Σημειώστε ότι αν οι πληροφορίες είναι κρυμμένες στο γεγονός ότι ένα phase αλλάζει και όχι στο ίδιο το phase, δεν θα δείτε διαφορετικά phases καθαρά διαχωρισμένα.
- **Detecting FM**: Το IQ δεν διαθέτει πεδίο για την αναγνώριση frequencies (η απόσταση από το κέντρο είναι το amplitude και η γωνία είναι το phase).\
Επομένως, για την αναγνώριση FM, θα πρέπει να **βλέπετε ουσιαστικά μόνο έναν κύκλο** σε αυτό το graph.\
Επιπλέον, ένα διαφορετικό frequency "αναπαρίσταται" στο IQ graph ως **επιτάχυνση της ταχύτητας κατά μήκος του κύκλου** (έτσι, στο SysDigger, όταν επιλέγετε το signal, το IQ graph γεμίζει· αν βρείτε επιτάχυνση ή αλλαγή κατεύθυνσης στον δημιουργημένο κύκλο, αυτό μπορεί να σημαίνει ότι πρόκειται για FM):

## AM Example

{{#file}}
sigdigger_20220308_165547Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering AM

#### Checking the envelope

Ελέγχοντας AM info με το [**SigDigger** ](https://github.com/BatchDrake/SigDigger) και κοιτάζοντας απλώς το **envelope**, μπορείτε να δείτε διαφορετικά, σαφή επίπεδα amplitude. Το χρησιμοποιούμενο signal στέλνει pulses με πληροφορίες σε AM· έτσι φαίνεται ένα pulse:<sup>[[1]](#references)</sup>

![SigDigger AM signal envelope with clear pulse amplitude levels](<../../images/image (590).png>)

Και έτσι φαίνεται ένα μέρος του symbol μαζί με το waveform:

![Uncovering AM - Checking the envelope: And this is how part of the symbol looks like with the waveform](<../../images/image (734).png>)

#### Checking the Histogram

Μπορείτε να **επιλέξετε ολόκληρο το signal** όπου βρίσκονται οι πληροφορίες, να επιλέξετε τη λειτουργία **Amplitude** και το **Selection** και να κάνετε click στο **Histogram.** Μπορείτε να παρατηρήσετε ότι εμφανίζονται μόνο 2 σαφή levels.

![SigDigger amplitude histogram showing two clear levels for the selected AM signal](<../../images/image (264).png>)

Για παράδειγμα, αν επιλέξετε Frequency αντί για Amplitude σε αυτό το AM signal, θα βρείτε μόνο 1 frequency (δεν γίνεται πληροφορίες που έχουν γίνει modulation σε frequency να χρησιμοποιούν μόνο 1 freq).

![SigDigger frequency histogram for the AM signal showing one frequency](<../../images/image (732).png>)

Αν βρείτε πολλά frequencies, πιθανότατα δεν πρόκειται για FM· πιθανώς το frequency του signal τροποποιήθηκε απλώς λόγω του channel.

#### With IQ

Σε αυτό το παράδειγμα μπορείτε να δείτε έναν **μεγάλο κύκλο**, αλλά και **πολλά σημεία στο κέντρο**.

![Checking the Histogram - With IQ: In this example you can see how there is a big circle but also a lot of points in the centre](<../../images/image (222).png>)

### Get Symbol Rate

#### With one symbol

Επιλέξτε το μικρότερο symbol που μπορείτε να βρείτε (ώστε να είστε βέβαιοι ότι είναι μόνο 1) και ελέγξτε το "Selection freq". Σε αυτή την περίπτωση θα ήταν 1.013kHz (άρα 1kHz).

![Get Symbol Rate - With one symbol: Select the smallest symbol you can find (so you are sure it's just 1) and check the "Selection freq". I this case it would be 1.013kHz (so 1kHz)](<../../images/image (78).png>)

#### With a group of symbols

Μπορείτε επίσης να δηλώσετε τον αριθμό των symbols που πρόκειται να επιλέξετε και το SigDigger θα υπολογίσει το frequency ενός symbol (πιθανότατα, όσο περισσότερα symbols επιλέγονται τόσο καλύτερα). Σε αυτό το σενάριο επέλεξα 10 symbols και το "Selection freq" είναι 1.004 Khz:

![SigDigger symbol-rate calculation using a selected group of ten symbols](<../../images/image (1008).png>)

### Get Bits

Αφού διαπιστώσετε ότι πρόκειται για **AM modulated** signal και βρείτε το **symbol rate** (γνωρίζοντας ότι σε αυτή την περίπτωση κάτι προς τα πάνω σημαίνει 1 και κάτι προς τα κάτω σημαίνει 0), είναι πολύ εύκολο να **λάβετε τα bits** που είναι encoded στο signal. Επιλέξτε, λοιπόν, το signal με τις πληροφορίες, ρυθμίστε το sampling και το decision και πατήστε sample (βεβαιωθείτε ότι έχει επιλεγεί το **Amplitude**, ότι έχει ρυθμιστεί το ανακαλυφθέν **Symbol rate** και ότι έχει επιλεγεί το **Gadner clock recovery**):

![SigDigger Get Bits panel configured for AM sampling, symbol rate and Gardner clock recovery](<../../images/image (965).png>)

- Το **Sync to selection intervals** σημαίνει ότι, αν προηγουμένως επιλέξατε intervals για να βρείτε το symbol rate, θα χρησιμοποιηθεί αυτό το symbol rate.
- Το **Manual** σημαίνει ότι θα χρησιμοποιηθεί το υποδεικνυόμενο symbol rate.
- Στο **Fixed interval selection** δηλώνετε τον αριθμό των intervals που πρέπει να επιλεγούν και υπολογίζεται από αυτά το symbol rate.
- Το **Gadner clock recovery** είναι συνήθως η καλύτερη επιλογή, αλλά και πάλι πρέπει να δηλώσετε ένα κατά προσέγγιση symbol rate.

Πατώντας sample εμφανίζεται αυτό:

![With a group of symbols - Get Bits: Pressing sample this appears](<../../images/image (644).png>)

Τώρα, για να καταλάβει το SigDigger **πού βρίσκεται το range** του level που μεταφέρει τις πληροφορίες, πρέπει να κάνετε click στο **lower level** και να κρατήσετε πατημένο το click μέχρι το μεγαλύτερο level:

![SigDigger level-range selection from the lower amplitude level to the upper level](<../../images/image (439).png>)

Αν, για παράδειγμα, υπήρχαν **4 διαφορετικά levels amplitude**, θα έπρεπε να ρυθμίσετε τα **Bits per symbol σε 2** και να επιλέξετε από το μικρότερο έως το μεγαλύτερο.

Τέλος, **αυξάνοντας** το **Zoom** και **αλλάζοντας το Row size**, μπορείτε να δείτε τα bits (και να τα επιλέξετε όλα και να κάνετε copy για να λάβετε όλα τα bits):

![With a group of symbols - Get Bits: Finally increasing the Zoom and changing the Row size you can see the bits (and you can select all and copy to get all the bits)](<../../images/image (276).png>)

Αν το signal έχει περισσότερα από 1 bit ανά symbol (για παράδειγμα 2), το SigDigger **δεν μπορεί να γνωρίζει ποιο symbol είναι** 00, 01, 10 ή 11, επομένως χρησιμοποιεί διαφορετικές **grey scales** για να αναπαραστήσει το καθένα (και αν κάνετε copy τα bits, θα χρησιμοποιήσει **numbers από 0 έως 3**, τα οποία θα χρειαστεί να επεξεργαστείτε).

Επίσης, χρησιμοποιήστε **codifications** όπως η **Manchester**: ένα **up+down** μπορεί να είναι **1 ή 0** και ένα **down+up** μπορεί να είναι 1 ή 0. Σε αυτές τις περιπτώσεις πρέπει να **επεξεργαστείτε τα ups (1) και downs (0)** που λάβατε, ώστε να αντικαταστήσετε τα ζεύγη 01 ή 10 με 0 ή 1.

## FM Example

{{#file}}
sigdigger_20220308_170858Z_2560000_433500000_float32_iq.raw
{{#endfile}}

### Uncovering FM

#### Checking the frequencies and waveform

Παράδειγμα signal που στέλνει πληροφορίες modulated σε FM:

![Uncovering FM - Checking the frequencies and waveform: Signal example sending information modulated in FM](<../../images/image (725).png>)

Στην προηγούμενη εικόνα μπορείτε να παρατηρήσετε αρκετά καθαρά ότι χρησιμοποιούνται **2 frequencies**, αλλά αν **παρατηρήσετε** το **waveform**, μπορεί να **μην μπορέσετε να αναγνωρίσετε σωστά τα 2 διαφορετικά frequencies**:

![SigDigger FM waveform where the two frequencies are difficult to distinguish directly](<../../images/image (717).png>)

Αυτό συμβαίνει επειδή έκανα capture το signal και στα δύο frequencies, επομένως το ένα είναι περίπου το αρνητικό του άλλου:

![SigDigger FM capture showing the two frequencies as approximate negatives of each other](<../../images/image (942).png>)

Αν το synchronized frequency είναι **πιο κοντά στο ένα frequency από ό,τι στο άλλο**, μπορείτε εύκολα να δείτε τα 2 διαφορετικά frequencies:

![Uncovering FM - Checking the frequencies and waveform: If the synchronized frequency is closer to one frequency than to the other you can easily see the 2 different frequencies](<../../images/image (422).png>)

![Uncovering FM - Checking the frequencies and waveform: If the synchronized frequency is closer to one frequency than to the other you can easily see the 2 different frequencies](<../../images/image (488).png>)

#### Checking the histogram

Ελέγχοντας το frequency histogram του signal με τις πληροφορίες, μπορείτε εύκολα να δείτε 2 διαφορετικά signals:

![Checking the frequencies and waveform - Checking the histogram: Checking the frequency histogram of the signal with information you can easily see 2 different signals](<../../images/image (871).png>)

Σε αυτή την περίπτωση, αν ελέγξετε το **Amplitude histogram**, θα βρείτε **μόνο ένα amplitude**, επομένως **δεν μπορεί να είναι AM** (αν βρείτε πολλά amplitudes, μπορεί να οφείλεται στο ότι το signal έχασε ισχύ κατά μήκος του channel):

![SigDigger amplitude histogram for FM signal showing a single amplitude level](<../../images/image (817).png>)

Και αυτό θα ήταν το phase histogram (το οποίο κάνει απολύτως σαφές ότι το signal δεν είναι modulated σε phase):

![Checking the frequencies and waveform - Checking the histogram: And this is would be phase histogram (which makes very clear the signal is not modulated in phase)](<../../images/image (996).png>)

#### With IQ

Το IQ δεν διαθέτει πεδίο για την αναγνώριση frequencies (η απόσταση από το κέντρο είναι το amplitude και η γωνία είναι το phase).\
Επομένως, για την αναγνώριση FM, θα πρέπει να **βλέπετε ουσιαστικά μόνο έναν κύκλο** σε αυτό το graph.\
Επιπλέον, ένα διαφορετικό frequency "αναπαρίσταται" στο IQ graph ως **επιτάχυνση της ταχύτητας κατά μήκος του κύκλου** (έτσι, στο SysDigger, όταν επιλέγετε το signal, το IQ graph γεμίζει· αν βρείτε επιτάχυνση ή αλλαγή κατεύθυνσης στον δημιουργημένο κύκλο, αυτό μπορεί να σημαίνει ότι πρόκειται για FM):

![SigDigger IQ graph where FM appears as acceleration changes around the circle](<../../images/image (81).png>)

### Get Symbol Rate

Μπορείτε να χρησιμοποιήσετε την **ίδια τεχνική με αυτήν που χρησιμοποιήθηκε στο AM example** για να βρείτε το symbol rate, αφού εντοπίσετε τα frequencies που μεταφέρουν symbols.

### Get Bits

Μπορείτε να χρησιμοποιήσετε την **ίδια τεχνική με αυτήν που χρησιμοποιήθηκε στο AM example** για να βρείτε τα bits, αφού **διαπιστώσετε ότι το signal είναι modulated σε frequency** και εντοπίσετε το **symbol rate**.

## References

- [1] [SigDigger - Free digital signal analyzer for GNU/Linux and macOS](https://github.com/BatchDrake/SigDigger)

{{#include ../../banners/hacktricks-training.md}}
