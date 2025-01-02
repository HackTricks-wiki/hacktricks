# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Uvod

Za više informacija o tome šta je iButton pogledajte:

{{#ref}}
../ibutton.md
{{#endref}}

## Dizajn

**Plavi** deo sledeće slike je kako treba da **postavite pravi iButton** da bi Flipper mogao da **pročita.** **Zeleni** deo je kako treba da **dodirnete čitač** sa Flipper zero da bi **ispravno emulirali iButton**.

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Akcije

### Čitanje

U režimu čitanja Flipper čeka da iButton ključ dodirne i može da obradi bilo koji od tri tipa ključeva: **Dallas, Cyfral, i Metakom**. Flipper će **samo odrediti tip ključa**. Ime protokola ključa biće prikazano na ekranu iznad ID broja.

### Ručno dodavanje

Moguće je **ručno dodati** iButton tipa: **Dallas, Cyfral, i Metakom**

### **Emulacija**

Moguće je **emulirati** sačuvane iButtons (pročitane ili ručno dodate).

> [!NOTE]
> Ako ne možete da ostvarite očekivane kontakte Flipper Zero sa čitačem, možete **koristiti spoljašnji GPIO:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## Reference

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
