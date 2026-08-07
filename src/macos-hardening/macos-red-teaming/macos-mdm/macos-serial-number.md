# Serijski broj macOS-a

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Apple uređaji proizvedeni nakon 2010. godine imaju serijske brojeve koji se sastoje od **12 alfanumeričkih znakova**, pri čemu svaki segment prenosi određene informacije:

- **Prva 3 znaka**: Označavaju **mesto proizvodnje**.
- **Znakovi 4 i 5**: Označavaju **godinu i nedelju proizvodnje**.
- **Znakovi od 6 do 8**: Predstavljaju **jedinstveni identifikator** svakog uređaja.
- **Poslednja 4 znaka**: Određuju **broj modela**.

Na primer, serijski broj **C02L13ECF8J2** prati ovu strukturu.

### **Mesta proizvodnje (prva 3 znaka)**

Određeni kodovi predstavljaju konkretne fabrike:

- **FC, F, XA/XB/QP/G8**: Različite lokacije u SAD.
- **RN**: Meksiko.
- **CK**: Cork, Irska.
- **VM**: Foxconn, Češka Republika.
- **SG/E**: Singapur.
- **MB**: Malezija.
- **PT/CY**: Koreja.
- **EE/QT/UV**: Tajvan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Različite lokacije u Kini.
- **C0, C3, C7**: Određeni gradovi u Kini.
- **RM**: Refurbished uređaji.

### **Godina proizvodnje (4. znak)**

Ovaj znak se kreće od „C“ (koji predstavlja prvu polovinu 2010. godine) do „Z“ (druga polovina 2019. godine), pri čemu različita slova označavaju različite polugodišnje periode.

### **Nedelja proizvodnje (5. znak)**

Cifre 1–9 odgovaraju nedeljama 1–9. Slova C–Y (isključujući samoglasnike i „S“) predstavljaju nedelje 10–27. Za drugu polovinu godine, ovom broju se dodaje 26.

{{#include ../../../banners/hacktricks-training.md}}
