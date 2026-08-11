# Κλοπή Ευαίσθητων Πληροφοριών από μια Web Σελίδα

{{#include ../banners/hacktricks-training.md}}

Αν μια **web σελίδα εμφανίζει ευαίσθητες πληροφορίες με βάση την τρέχουσα session**—όπως cookies, δεδομένα λογαριασμού ή στοιχεία πιστωτικής κάρτας—ένας attacker μπορεί να προσπαθήσει να τις κάνει exfiltrate. Οι κύριες τεχνικές περιλαμβάνουν:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): Μια λανθασμένη ρύθμιση του CORS μπορεί να επιτρέψει σε ένα malicious origin να διαβάζει ευαίσθητες responses μέσω cross-origin requests.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Ένα XSS vulnerability στο target origin μπορεί να επιτρέψει σε injected JavaScript να διαβάζει και να κάνει exfiltrate τις πληροφορίες.
- [**Dangling markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Όταν το script injection δεν είναι διαθέσιμο, injected HTML elements μπορεί και πάλι να καταγράψουν ευαίσθητο περιεχόμενο.
- [**Clickjacking**](../pentesting-web/clickjacking.md): Αν απουσιάζουν οι protections against framing, ένας attacker μπορεί να εξαπατήσει έναν χρήστη ώστε να αλληλεπιδράσει με την ευαίσθητη σελίδα. Το συνδεδεμένο case study παρουσιάζει αυτή την τεχνική.<sup>[[1]](#references)</sup>

## References

- [1] [Το Apache example servlet οδηγεί σε Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)
{{#include ../banners/hacktricks-training.md}}
