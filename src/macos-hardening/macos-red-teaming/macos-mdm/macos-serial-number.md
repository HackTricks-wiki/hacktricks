# macOS-Seriennummer

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Apple-Geräte ab 2010 haben Seriennummern, die aus **12 alphanumerischen Zeichen** bestehen, wobei jedes Segment spezifische Informationen vermittelt:

- **Erste 3 Zeichen**: Geben den **Herstellungsort** an.
- **Zeichen 4 und 5**: Bezeichnen das **Herstellungsjahr und die Herstellungswoche**.
- **Zeichen 6 bis 8**: Dienen als **eindeutige Kennung** für jedes Gerät.
- **Letzte 4 Zeichen**: Geben die **Modellnummer** an.

Die Seriennummer **C02L13ECF8J2** folgt beispielsweise dieser Struktur.

### **Herstellungsorte (erste 3 Zeichen)**

Bestimmte Codes stehen für bestimmte Fabriken:

- **FC, F, XA/XB/QP/G8**: Verschiedene Standorte in den USA.
- **RN**: Mexiko.
- **CK**: Cork, Irland.
- **VM**: Foxconn, Tschechische Republik.
- **SG/E**: Singapur.
- **MB**: Malaysia.
- **PT/CY**: Korea.
- **EE/QT/UV**: Taiwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Verschiedene Standorte in China.
- **C0, C3, C7**: Bestimmte Städte in China.
- **RM**: Generalüberholte Geräte.

### **Herstellungsjahr (4. Zeichen)**

Dieses Zeichen reicht von „C“ (steht für die erste Hälfte des Jahres 2010) bis „Z“ (zweite Hälfte des Jahres 2019), wobei verschiedene Buchstaben unterschiedliche Halbjahreszeiträume angeben.

### **Herstellungswoche (5. Zeichen)**

Die Ziffern 1–9 entsprechen den Wochen 1–9. Die Buchstaben C–Y (ohne Vokale und „S“) stehen für die Wochen 10–27. Für die zweite Jahreshälfte wird zu dieser Zahl 26 addiert.

{{#include ../../../banners/hacktricks-training.md}}
