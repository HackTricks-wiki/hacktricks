# macOS Serial Number

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

2010 के बाद के Apple devices के serial numbers में **12 alphanumeric characters** होते हैं, जिनका प्रत्येक segment विशिष्ट जानकारी प्रदान करता है:

- **First 3 Characters**: **manufacturing location** दर्शाते हैं।
- **Characters 4 & 5**: **year and week of manufacture** दर्शाते हैं।
- **Characters 6 to 8**: प्रत्येक device के लिए **unique identifier** के रूप में कार्य करते हैं।
- **Last 4 Characters**: **model number** निर्दिष्ट करते हैं।

उदाहरण के लिए, serial number **C02L13ECF8J2** इसी structure का पालन करता है।

### **Manufacturing Locations (First 3 Characters)**

कुछ codes विशिष्ट factories को दर्शाते हैं:

- **FC, F, XA/XB/QP/G8**: USA में विभिन्न locations।
- **RN**: Mexico।
- **CK**: Cork, Ireland।
- **VM**: Foxconn, Czech Republic।
- **SG/E**: Singapore।
- **MB**: Malaysia।
- **PT/CY**: Korea।
- **EE/QT/UV**: Taiwan।
- **FK/F1/F2, W8, DL/DM, DN, YM/7J, 1C/4H/WQ/F7**: China में अलग-अलग locations।
- **C0, C3, C7**: China के विशिष्ट cities।
- **RM**: Refurbished devices।

### **Year of Manufacturing (4th Character)**

यह character 'C' (जो 2010 के first half को दर्शाता है) से लेकर 'Z' (2019 के second half) तक vary करता है, जिसमें अलग-अलग letters अलग-अलग half-year periods को दर्शाते हैं।

### **Week of Manufacturing (5th Character)**

Digits 1-9 weeks 1-9 के अनुरूप होते हैं। Letters C-Y (vowels और 'S' को छोड़कर) weeks 10-27 को दर्शाते हैं। वर्ष के second half के लिए, इस number में 26 जोड़ा जाता है।

{{#include ../../../banners/hacktricks-training.md}}
