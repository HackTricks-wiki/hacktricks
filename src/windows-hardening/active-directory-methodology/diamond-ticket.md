# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Όπως ένα χρυσό εισιτήριο**, ένα διαμαντένιο εισιτήριο είναι ένα TGT που μπορεί να χρησιμοποιηθεί για **πρόσβαση σε οποιαδήποτε υπηρεσία ως οποιοσδήποτε χρήστης**. Ένα χρυσό εισιτήριο κατασκευάζεται εντελώς εκτός σύνδεσης, κρυπτογραφημένο με το hash krbtgt αυτού του τομέα, και στη συνέχεια εισάγεται σε μια συνεδρία σύνδεσης για χρήση. Δεδομένου ότι οι ελεγκτές τομέα δεν παρακολουθούν τα TGT που έχουν εκδοθεί νόμιμα, θα αποδεχτούν ευχαρίστως TGT που είναι κρυπτογραφημένα με το δικό τους hash krbtgt.

Υπάρχουν δύο κοινές τεχνικές για την ανίχνευση της χρήσης χρυσών εισιτηρίων:

- Αναζητήστε TGS-REQ που δεν έχουν αντίστοιχο AS-REQ.
- Αναζητήστε TGT που έχουν ανόητες τιμές, όπως η προεπιλεγμένη διάρκεια ζωής 10 ετών του Mimikatz.

Ένα **διαμαντένιο εισιτήριο** δημιουργείται με **την τροποποίηση των πεδίων ενός νόμιμου TGT που εκδόθηκε από έναν DC**. Αυτό επιτυγχάνεται με **την αίτηση** ενός **TGT**, **την αποκρυπτογράφηση** του με το hash krbtgt του τομέα, **την τροποποίηση** των επιθυμητών πεδίων του εισιτηρίου και στη συνέχεια **την επανακρυπτογράφηση** του. Αυτό **ξεπερνά τα δύο προαναφερθέντα μειονεκτήματα** ενός χρυσού εισιτηρίου επειδή:

- Τα TGS-REQ θα έχουν έναν προηγούμενο AS-REQ.
- Το TGT εκδόθηκε από έναν DC, πράγμα που σημαίνει ότι θα έχει όλες τις σωστές λεπτομέρειες από την πολιτική Kerberos του τομέα. Αν και αυτά μπορούν να κατασκευαστούν με ακρίβεια σε ένα χρυσό εισιτήριο, είναι πιο περίπλοκο και επιρρεπές σε λάθη.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
{{#include ../../banners/hacktricks-training.md}}
