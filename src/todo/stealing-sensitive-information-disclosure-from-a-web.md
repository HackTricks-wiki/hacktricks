# Κλοπή ευαίσθητων πληροφοριών από μια Web εφαρμογή

{{#include ../banners/hacktricks-training.md}}

Αν κάποια στιγμή βρείτε μια **Web σελίδα που εμφανίζει ευαίσθητες πληροφορίες με βάση το session σας**: Ίσως αντικατοπτρίζει cookies ή εμφανίζει στοιχεία CC ή οποιαδήποτε άλλη ευαίσθητη πληροφορία, μπορείτε να προσπαθήσετε να την κλέψετε.\
Εδώ παρουσιάζονται οι βασικοί τρόποι με τους οποίους μπορείτε να προσπαθήσετε να το πετύχετε:

- [**CORS bypass**](../pentesting-web/cors-bypass.md): Αν μπορείτε να παρακάμψετε τα CORS headers, θα μπορείτε να κλέψετε τις πληροφορίες εκτελώντας Ajax request για μια κακόβουλη σελίδα.
- [**XSS**](../pentesting-web/xss-cross-site-scripting/index.html): Αν βρείτε μια ευπάθεια XSS στη σελίδα, ίσως μπορέσετε να την εκμεταλλευτείτε για να κλέψετε τις πληροφορίες.
- [**Danging Markup**](../pentesting-web/dangling-markup-html-scriptless-injection/index.html): Αν δεν μπορείτε να εισαγάγετε XSS tags, ίσως εξακολουθείτε να μπορείτε να κλέψετε τις πληροφορίες χρησιμοποιώντας άλλα κανονικά HTML tags.
- [**Clickjaking**](../pentesting-web/clickjacking.md): Αν δεν υπάρχει προστασία απέναντι σε αυτή την επίθεση, ίσως μπορέσετε να εξαπατήσετε τον χρήστη ώστε να σας στείλει τα ευαίσθητα δεδομένα (ένα παράδειγμα [εδώ](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)).<sup>[[1]](#references)</sup>

## Αναφορές

- [1] [Apache example servlet leads to Information Disclosure](https://medium.com/bugbountywriteup/apache-example-servlet-leads-to-61a2720cac20)

{{#include ../banners/hacktricks-training.md}}
