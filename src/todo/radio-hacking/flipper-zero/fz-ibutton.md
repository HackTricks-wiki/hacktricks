# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

Za više informacija o tome šta je iButton pogledajte:


{{#ref}}
../ibutton.md
{{#endref}}

## Dizajn

**Plavi** deo sledeće slike pokazuje kako treba da **postavite pravi iButton** da bi Flipper mogao da ga **očita.** **Zeleni** deo pokazuje kako treba da **dodirnete čitač** uređajem Flipper Zero da biste **ispravno emulirali iButton**.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Radnje

### Čitanje

U režimu čitanja, Flipper čeka da iButton ključem dodirnete čitač i može da obradi bilo koji od tri tipa ključeva: **Dallas, Cyfral i Metakom**. Flipper će **sam prepoznati tip ključa**. Naziv protokola ključa biće prikazan na ekranu iznad ID broja.<sup>[[1]](#references)</sup>

### Ručno dodavanje

Moguće je **ručno dodati** iButton tipa: **Dallas, Cyfral i Metakom**

### **Emulacija**

Moguće je **emulirati** sačuvane iButton uređaje (pročitane ili ručno dodate).

> [!TIP]
> Ako ne možete da ostvarite očekivani kontakt između uređaja Flipper Zero i čitača, možete da **koristite eksterni GPIO:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## Reference

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
