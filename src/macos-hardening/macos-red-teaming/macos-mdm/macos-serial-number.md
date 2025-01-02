# macOS Serial Number

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di Base

I dispositivi Apple post-2010 hanno numeri di serie composti da **12 caratteri alfanumerici**, ciascun segmento trasmette informazioni specifiche:

- **Primi 3 Caratteri**: Indicano il **luogo di produzione**.
- **Caratteri 4 e 5**: Denotano l'**anno e la settimana di produzione**.
- **Caratteri 6 a 8**: Servono come **identificatore unico** per ciascun dispositivo.
- **Ultimi 4 Caratteri**: Specificano il **numero di modello**.

Ad esempio, il numero di serie **C02L13ECF8J2** segue questa struttura.

### **Luoghi di Produzione (Primi 3 Caratteri)**

Alcuni codici rappresentano fabbriche specifiche:

- **FC, F, XA/XB/QP/G8**: Varie località negli USA.
- **RN**: Messico.
- **CK**: Cork, Irlanda.
- **VM**: Foxconn, Repubblica Ceca.
- **SG/E**: Singapore.
- **MB**: Malesia.
- **PT/CY**: Corea.
- **EE/QT/UV**: Taiwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Diverse località in Cina.
- **C0, C3, C7**: Città specifiche in Cina.
- **RM**: Dispositivi ricondizionati.

### **Anno di Produzione (4° Carattere)**

Questo carattere varia da 'C' (che rappresenta la prima metà del 2010) a 'Z' (seconda metà del 2019), con lettere diverse che indicano diversi periodi di sei mesi.

### **Settimana di Produzione (5° Carattere)**

Le cifre 1-9 corrispondono alle settimane 1-9. Le lettere C-Y (escludendo le vocali e 'S') rappresentano le settimane 10-27. Per la seconda metà dell'anno, a questo numero viene aggiunto 26.

{{#include ../../../banners/hacktricks-training.md}}
