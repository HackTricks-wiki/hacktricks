# JTAG

{{#include ../../banners/hacktricks-training.md}}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)ni chombo kinachoweza kutumika na Raspberry PI au Arduino kutafuta kujaribu pini za JTAG kutoka kwa chip isiyojulikana.\
Katika **Arduino**, ung'anishe **pini kutoka 2 hadi 11 kwa pini 10 zinazoweza kuwa za JTAG**. Pakia programu kwenye Arduino na itajaribu kujaribu nguvu zote za pini ili kuona kama pini yoyote ni ya JTAG na ambayo ni kila moja.\
Katika **Raspberry PI** unaweza kutumia tu **pini kutoka 1 hadi 6** (pini 6, hivyo utachukua muda mrefu zaidi kujaribu kila pini inayoweza kuwa ya JTAG).

### Arduino

Katika Arduino, baada ya kuunganisha nyaya (pini 2 hadi 11 kwa pini za JTAG na GND ya Arduino kwa GND ya baseboard), **pakia programu ya JTAGenum kwenye Arduino** na katika Monitor ya Serial tuma **`h`** (amri ya msaada) na unapaswa kuona msaada:

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

Sanidi **"No line ending" na 115200baud**.\
Tuma amri s kuanza skanning:

![](<../../images/image (774).png>)

Ikiwa unawasiliana na JTAG, utaona moja au kadhaa **mistari inayoanisha na FOUND!** ikionyesha pini za JTAG.

{{#include ../../banners/hacktricks-training.md}}
