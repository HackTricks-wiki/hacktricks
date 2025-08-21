# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Za više informacija o tome šta je iButton pogledajte:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

**Plavi** deo sledeće slike je kako treba da **stavite pravi iButton** da bi Flipper mogao da **pročita.** **Zeleni** deo je kako treba da **dodirnete čitač** sa Flipper zero da bi **ispravno emulirali iButton**.

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Read

U režimu čitanja Flipper čeka da iButton ključ dodirne i može da obradi bilo koji od tri tipa ključeva: **Dallas, Cyfral, i Metakom**. Flipper će **sama odrediti tip ključa**. Ime protokola ključa biće prikazano na ekranu iznad ID broja.

### Add manually

Moguće je **ručno dodati** iButton tipa: **Dallas, Cyfral, i Metakom**

### **Emulate**

Moguće je **emulirati** sačuvane iButtons (pročitane ili ručno dodate).

> [!TIP]
> Ako ne možete da ostvarite očekivane kontakte Flipper Zero da dodirne čitač, možete **koristiti spoljašnji GPIO:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
