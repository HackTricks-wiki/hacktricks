# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Intro

Kwa maelezo zaidi kuhusu iButton ni nini angalia:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

Sehemu ya **bluu** ya picha ifuatayo ni jinsi unavyohitaji **kueka iButton halisi** ili Flipper iweze **kuisoma.** Sehemu ya **kijani** ni jinsi unavyohitaji **kugusa msomaji** na Flipper zero ili **kuiga iButton** kwa usahihi.

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Read

Katika Modu ya Kusoma Flipper inasubiri funguo ya iButton kugusa na inaweza kuchakata aina yoyote ya funguo tatu: **Dallas, Cyfral, na Metakom**. Flipper itajua **aina ya funguo yenyewe**. Jina la protokali ya funguo litakuwa kwenye skrini juu ya nambari ya ID.

### Add manually

Inawezekana **kuongeza kwa mkono** iButton ya aina: **Dallas, Cyfral, na Metakom**

### **Emulate**

Inawezekana **kuiga** iButtons zilizohifadhiwa (zilizosomwa au zilizoongezwa kwa mkono).

> [!NOTE]
> Ikiwa huwezi kufanya mawasiliano yanayotarajiwa ya Flipper Zero kugusa msomaji unaweza **kutumia GPIO ya nje:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
