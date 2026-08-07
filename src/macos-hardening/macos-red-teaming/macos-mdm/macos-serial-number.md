# macOS Serial Number

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Apple-toestelle wat ná 2010 vervaardig is, het reeksnommers wat uit **12 alfanumeriese karakters** bestaan, waar elke segment spesifieke inligting oordra:

- **Eerste 3 karakters**: Dui die **vervaardigingsplek** aan.
- **Karakters 4 en 5**: Dui die **jaar en week van vervaardiging** aan.
- **Karakters 6 tot 8**: Dien as ’n **unieke identifiseerder** vir elke toestel.
- **Laaste 4 karakters**: Spesifiseer die **modelnommer**.

Byvoorbeeld, die reeksnommer **C02L13ECF8J2** volg hierdie struktuur.

### **Vervaardigingsplekke (Eerste 3 karakters)**

Sekere kodes verteenwoordig spesifieke fabrieke:

- **FC, F, XA/XB/QP/G8**: Verskeie plekke in die VSA.
- **RN**: Mexiko.
- **CK**: Cork, Ierland.
- **VM**: Foxconn, Tsjeggië.
- **SG/E**: Singapoer.
- **MB**: Maleisië.
- **PT/CY**: Korea.
- **EE/QT/UV**: Taiwan.
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: Verskillende plekke in China.
- **C0, C3, C7**: Spesifieke stede in China.
- **RM**: Gereviseerde toestelle.

### **Jaar van vervaardiging (4de karakter)**

Hierdie karakter wissel van 'C' (wat die eerste helfte van 2010 verteenwoordig) tot 'Z' (tweede helfte van 2019), met verskillende letters wat verskillende halfjaarlikse tydperke aandui.

### **Week van vervaardiging (5de karakter)**

Syfers 1-9 stem ooreen met weke 1-9. Letters C-Y (uitgesluit vokale en 'S') verteenwoordig weke 10-27. Vir die tweede helfte van die jaar word 26 by hierdie getal getel.

{{#include ../../../banners/hacktricks-training.md}}
