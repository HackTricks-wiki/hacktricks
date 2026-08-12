# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Τύποι payload του Intruder

Το Burp Intruder περιλαμβάνει τους ακόλουθους ενσωματωμένους generators και transformations payload:<sup>[[1]](#references)</sup>

- **Simple list:** Χρησιμοποιεί μια ρυθμισμένη λίστα strings ως payloads.
- **Runtime file:** Διαβάζει ένα payload ανά γραμμή κατά το runtime. Αυτό είναι χρήσιμο για μεγάλες λίστες, επειδή το Burp δεν φορτώνει ολόκληρο το αρχείο στη μνήμη.
- **Case modification:** Δημιουργεί την αρχική τιμή, τις μορφές με πεζά και κεφαλαία, `Propername` (το πρώτο γράμμα κεφαλαίο και τα υπόλοιπα πεζά) ή `ProperName` (το πρώτο γράμμα κεφαλαίο και οι υπόλοιποι χαρακτήρες αμετάβλητοι). Το Burp απορρίπτει τα διπλότυπα αποτελέσματα.
- **Numbers:** Δημιουργεί διαδοχικούς ή τυχαίους αριθμούς μέσα σε ένα ρυθμισμένο εύρος.
- **Brute forcer:** Δημιουργεί κάθε permutation για ένα επιλεγμένο character set και ελάχιστο/μέγιστο μήκος.

## Extensions και companion tools

- Το **Collabfiltrator** δημιουργεί payloads που εκτελούν commands και κάνουν exfiltrate την έξοδό τους μέσω DNS queries προς το Burp Collaborator.<sup>[[2]](#references)</sup>
- Το **Burp Suite Exporter** εξάγει τα ευρήματα του Burp για χρήση σε άλλα reporting workflows.<sup>[[3]](#references)</sup>
- Το **HTTP Script Generator** μετατρέπει HTTP requests σε scripts σε διάφορες γλώσσες.<sup>[[4]](#references)</sup>

## References

- [1] [Τεκμηρίωση PortSwigger - Burp Intruder payload types](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
{{#include ../banners/hacktricks-training.md}}
