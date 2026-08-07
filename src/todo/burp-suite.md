# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Basic Payloads

- **Simple List:** Απλώς μια λίστα που περιέχει μία καταχώρηση σε κάθε γραμμή
- **Runtime File:** Μια λίστα που διαβάζεται κατά το runtime (δεν φορτώνεται στη μνήμη). Για υποστήριξη μεγάλων λιστών.
- **Case Modification:** Εφαρμογή ορισμένων αλλαγών σε μια λίστα από strings (No change, to lower, to UPPER, to Proper name - First capitalized and the rest to lower-, to Proper Name -First capitalized an the rest remains the same-.
- **Numbers:** Δημιουργία αριθμών από το X έως το Y χρησιμοποιώντας βήμα Z ή τυχαία.
- **Brute Forcer:** Character set, ελάχιστο και μέγιστο μήκος.

[https://github.com/0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator) : Payload για την εκτέλεση commands και τη λήψη του output μέσω DNS requests προς το burpcollab.

{{#ref}}
https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e
{{#endref}}

[https://github.com/h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)

{{#include ../banners/hacktricks-training.md}}
