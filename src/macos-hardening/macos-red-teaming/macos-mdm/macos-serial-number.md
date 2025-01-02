# macOS Serijski Broj

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne Informacije

Apple uređaji posle 2010. godine imaju serijske brojeve koji se sastoje od **12 alfanumeričkih karaktera**, pri čemu svaki segment prenosi specifične informacije:

- **Prva 3 Karaktera**: Oznaka **mesta proizvodnje**.
- **Karakteri 4 i 5**: Oznaka **godine i nedelje proizvodnje**.
- **Karakteri 6 do 8**: Služe kao **jedinstveni identifikator** za svaki uređaj.
- **Poslednja 4 Karaktera**: Oznaka **broja modela**.

Na primer, serijski broj **C02L13ECF8J2** prati ovu strukturu.

### **Mesta Proizvodnje (Prva 3 Karaktera)**

Određeni kodovi predstavljaju specifične fabrike:

- **FC, F, XA/XB/QP/G8**: Različite lokacije u SAD-u.
- **RN**: Meksiko.
- **CK**: Kork, Irska.
- **VM**: Foxconn, Češka Republika.
- **SG/E**: Singapur.
- **MB**: Malezija.
- **PT/CY**: Koreja.
- **EE/QT/UV**: Tajvan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Različite lokacije u Kini.
- **C0, C3, C7**: Specifični gradovi u Kini.
- **RM**: Obnovljeni uređaji.

### **Godina Proizvodnje (4. Karakter)**

Ovaj karakter varira od 'C' (predstavlja prvu polovinu 2010. godine) do 'Z' (druga polovina 2019. godine), pri čemu različita slova označavaju različite polugodišnje periode.

### **Nedelja Proizvodnje (5. Karakter)**

Brojevi 1-9 odgovaraju nedeljama 1-9. Slova C-Y (izuzev samoglasnika i 'S') predstavljaju nedelje 10-27. Za drugu polovinu godine, 26 se dodaje ovom broju.

{{#include ../../../banners/hacktricks-training.md}}
