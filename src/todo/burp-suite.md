# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Τύποι payload του Intruder

- **Simple list:** Χρησιμοποιεί μια διαμορφωμένη λίστα συμβολοσειρών ως payloads.
- **Runtime file:** Διαβάζει ένα payload ανά γραμμή κατά τον χρόνο εκτέλεσης. Αυτό είναι χρήσιμο για μεγάλες λίστες, επειδή το Burp δεν φορτώνει ολόκληρο το αρχείο στη μνήμη.
- **Case modification:** Αλλάζει τη χρήση κεφαλαίων και πεζών μιας συμβολοσειράς εισόδου, για παράδειγμα σε πεζά, κεφαλαία, μορφή πρότασης ή μορφή τίτλου.
- **Numbers:** Δημιουργεί διαδοχικούς ή τυχαίους αριθμούς εντός ενός διαμορφωμένου εύρους.
- **Brute forcer:** Δημιουργεί κάθε μετάθεση για ένα επιλεγμένο σύνολο χαρακτήρων και ελάχιστο/μέγιστο μήκος.<sup>[[1]](#references)</sup>

## Extensions και συνοδευτικά εργαλεία

- Το **Collabfiltrator** δημιουργεί payloads που εκτελούν εντολές και κάνουν exfiltration της εξόδου τους μέσω DNS queries προς το Burp Collaborator.<sup>[[2]](#references)</sup>
- Το **Burp Suite Exporter** εξάγει ευρήματα του Burp για χρήση σε άλλες ροές εργασίας reporting.<sup>[[3]](#references)</sup>
- Το **HTTP Script Generator** μετατρέπει HTTP requests σε scripts σε διάφορες γλώσσες.<sup>[[4]](#references)</sup>

## References

- [1] [Τεκμηρίωση PortSwigger - Τύποι payload του Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
