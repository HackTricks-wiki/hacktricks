# macOS Seriennummer

{{#include ../../../banners/hacktricks-training.md}}

## Grundinformationen

Apple-Geräte nach 2010 haben Seriennummern, die aus **12 alphanumerischen Zeichen** bestehen, wobei jedes Segment spezifische Informationen vermittelt:

- **Erste 3 Zeichen**: Geben den **Herstellungsort** an.
- **Zeichen 4 & 5**: Bezeichnen das **Jahr und die Woche der Herstellung**.
- **Zeichen 6 bis 8**: Dienen als **eindeutige Kennung** für jedes Gerät.
- **Letzte 4 Zeichen**: Geben die **Modellnummer** an.

Zum Beispiel folgt die Seriennummer **C02L13ECF8J2** dieser Struktur.

### **Herstellungsorte (Erste 3 Zeichen)**

Bestimmte Codes repräsentieren spezifische Fabriken:

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
- **RM**: Überholte Geräte.

### **Jahr der Herstellung (4. Zeichen)**

Dieses Zeichen variiert von 'C' (repräsentiert die erste Hälfte von 2010) bis 'Z' (zweite Hälfte von 2019), wobei verschiedene Buchstaben unterschiedliche Halbjahresperioden anzeigen.

### **Woche der Herstellung (5. Zeichen)**

Ziffern 1-9 entsprechen den Wochen 1-9. Buchstaben C-Y (ohne Vokale und 'S') repräsentieren die Wochen 10-27. Für die zweite Hälfte des Jahres wird 26 zu dieser Zahl addiert.

{{#include ../../../banners/hacktricks-training.md}}
