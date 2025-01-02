# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

Από προεπιλογή, **οποιοσδήποτε χρήστης** στο Active Directory μπορεί να **καταγράψει όλα τα DNS records** στις ζώνες DNS του Domain ή του Forest, παρόμοια με μια μεταφορά ζώνης (οι χρήστες μπορούν να καταγράψουν τα παιδικά αντικείμενα μιας ζώνης DNS σε ένα περιβάλλον AD).

Το εργαλείο [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) επιτρέπει την **καταγραφή** και **εξαγωγή** **όλων των DNS records** στη ζώνη για σκοπούς αναγνώρισης εσωτερικών δικτύων.
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
Για περισσότερες πληροφορίες διαβάστε [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
