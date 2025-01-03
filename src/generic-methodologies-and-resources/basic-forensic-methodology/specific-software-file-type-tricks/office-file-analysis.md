# Analiza Office datoteka

{{#include ../../../banners/hacktricks-training.md}}

Za više informacija proverite [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ovo je samo sažetak:

Microsoft je kreirao mnoge formate office dokumenata, pri čemu su dva glavna tipa **OLE formati** (kao što su RTF, DOC, XLS, PPT) i **Office Open XML (OOXML) formati** (kao što su DOCX, XLSX, PPTX). Ovi formati mogu uključivati makroe, što ih čini metama za phishing i malver. OOXML datoteke su strukturirane kao zip kontejneri, što omogućava inspekciju kroz raspakivanje, otkrivajući hijerarhiju datoteka i foldera i sadržaj XML datoteka.

Da bi se istražile strukture OOXML datoteka, data je komanda za raspakivanje dokumenta i struktura izlaza. Tehnike za skrivanje podataka u ovim datotekama su dokumentovane, što ukazuje na kontinuiranu inovaciju u skrivanju podataka unutar CTF izazova.

Za analizu, **oletools** i **OfficeDissector** nude sveobuhvatne alate za ispitivanje kako OLE tako i OOXML dokumenata. Ovi alati pomažu u identifikaciji i analizi ugrađenih makroa, koji često služe kao vektori za isporuku malvera, obično preuzimajući i izvršavajući dodatne zlonamerne pakete. Analiza VBA makroa može se izvršiti bez Microsoft Office-a korišćenjem Libre Office-a, koji omogućava debagovanje sa tačkama prekida i posmatranim promenljivama.

Instalacija i korišćenje **oletools** su jednostavni, sa komandama za instalaciju putem pip-a i vađenje makroa iz dokumenata. Automatsko izvršavanje makroa se pokreće funkcijama kao što su `AutoOpen`, `AutoExec` ili `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
{{#include ../../../banners/hacktricks-training.md}}
