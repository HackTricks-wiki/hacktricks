{{#include ../banners/hacktricks-training.md}}

# CBC

Ikiwa **cookie** ni **tu** jina la **mtumiaji** (au sehemu ya kwanza ya cookie ni jina la mtumiaji) na unataka kujifanya kuwa mtumiaji "**admin**". Basi, unaweza kuunda jina la mtumiaji **"bdmin"** na **bruteforce** **byte ya kwanza** ya cookie.

# CBC-MAC

**Cipher block chaining message authentication code** (**CBC-MAC**) ni njia inayotumika katika cryptography. Inafanya kazi kwa kuchukua ujumbe na kuuficha block kwa block, ambapo ulinzi wa kila block unahusishwa na ule wa kabla yake. Mchakato huu unaunda **mnyororo wa blocks**, kuhakikisha kwamba kubadilisha hata bit moja ya ujumbe wa asili kutasababisha mabadiliko yasiyotabirika katika block ya mwisho ya data iliyofichwa. Ili kufanya au kubadilisha mabadiliko kama hayo, funguo ya ulinzi inahitajika, kuhakikisha usalama.

Ili kuhesabu CBC-MAC ya ujumbe m, mtu anaficha m katika hali ya CBC na vector ya mwanzo ya sifuri na anahifadhi block ya mwisho. Mchoro ufuatao unachora hesabu ya CBC-MAC ya ujumbe unaojumuisha blocks![https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) kwa kutumia funguo ya siri k na cipher ya block E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png](<https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png>)

# Vulnerability

Kwa CBC-MAC kawaida **IV inayotumika ni 0**.\
Hii ni tatizo kwa sababu ujumbe 2 unaojulikana (`m1` na `m2`) kwa uhuru utaweza kuzalisha saini 2 (`s1` na `s2`). Hivyo:

- `E(m1 XOR 0) = s1`
- `E(m2 XOR 0) = s2`

Basi ujumbe ulio na m1 na m2 uliounganishwa (m3) utaweza kuzalisha saini 2 (s31 na s32):

- `E(m1 XOR 0) = s31 = s1`
- `E(m2 XOR s1) = s32`

**Ambayo inawezekana kuhesabu bila kujua funguo ya ulinzi.**

Fikiria unaficha jina **Administrator** katika **8bytes** blocks:

- `Administ`
- `rator\00\00\00`

Unaweza kuunda jina la mtumiaji linaloitwa **Administ** (m1) na kupata saini (s1).\
Kisha, unaweza kuunda jina la mtumiaji linaloitwa matokeo ya `rator\00\00\00 XOR s1`. Hii itazalisha `E(m2 XOR s1 XOR 0)` ambayo ni s32.\
sasa, unaweza kutumia s32 kama saini ya jina kamili **Administrator**.

### Summary

1. Pata saini ya jina la mtumiaji **Administ** (m1) ambayo ni s1
2. Pata saini ya jina la mtumiaji **rator\x00\x00\x00 XOR s1 XOR 0** ni s32**.**
3. Weka cookie kuwa s32 na itakuwa cookie halali kwa mtumiaji **Administrator**.

# Attack Controlling IV

Ikiwa unaweza kudhibiti IV inayotumika shambulio linaweza kuwa rahisi sana.\
Ikiwa cookies ni jina la mtumiaji tu lililofichwa, ili kujifanya kuwa mtumiaji "**administrator**" unaweza kuunda mtumiaji "**Administrator**" na utapata cookie yake.\
Sasa, ikiwa unaweza kudhibiti IV, unaweza kubadilisha Byte ya kwanza ya IV hivyo **IV\[0] XOR "A" == IV'\[0] XOR "a"** na kuunda upya cookie kwa mtumiaji **Administrator.** Cookie hii itakuwa halali kwa **kujifanya** mtumiaji **administrator** na **IV** ya awali.

## References

Maelezo zaidi katika [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)

{{#include ../banners/hacktricks-training.md}}
