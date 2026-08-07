# Numero di serie macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

I dispositivi Apple prodotti dopo il 2010 hanno numeri di serie composti da **12 caratteri alfanumerici**, ciascun segmento dei quali trasmette informazioni specifiche:

- **Primi 3 caratteri**: indicano il **luogo di produzione**.
- **Caratteri 4 e 5**: indicano l'**anno e la settimana di produzione**.
- **Caratteri da 6 a 8**: fungono da **identificatore univoco** per ogni dispositivo.
- **Ultimi 4 caratteri**: specificano il **numero del modello**.

Ad esempio, il numero di serie **C02L13ECF8J2** segue questa struttura.

### **Luoghi di produzione (primi 3 caratteri)**

Alcuni codici rappresentano fabbriche specifiche:

- **FC, F, XA/XB/QP/G8**: varie località negli Stati Uniti.
- **RN**: Messico.
- **CK**: Cork, Irlanda.
- **VM**: Foxconn, Repubblica Ceca.
- **SG/E**: Singapore.
- **MB**: Malaysia.
- **PT/CY**: Corea.
- **EE/QT/UV**: Taiwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: diverse località in Cina.
- **C0, C3, C7**: città specifiche in Cina.
- **RM**: dispositivi ricondizionati.

### **Anno di produzione (4° carattere)**

Questo carattere varia da 'C' (che rappresenta la prima metà del 2010) a 'Z' (la seconda metà del 2019), con lettere diverse che indicano periodi di sei mesi differenti.

### **Settimana di produzione (5° carattere)**

Le cifre 1-9 corrispondono alle settimane dalla 1 alla 9. Le lettere C-Y (escluse le vocali e la 'S') rappresentano le settimane dalla 10 alla 27. Per la seconda metà dell'anno, a questo numero viene aggiunto 26.

{{#include ../../../banners/hacktricks-training.md}}
