# Hash Length Extension Attack

{{#include ../banners/hacktricks-training.md}}

## Muhtasari wa shambulio

Fikiria seva ambayo in **tishe** baadhi ya **data** kwa **kuongeza** **siri** kwa baadhi ya data ya wazi inayojulikana na kisha kuhashi data hiyo. Ikiwa unajua:

- **Urefu wa siri** (hii inaweza pia kubruteforced kutoka kwa anuwai ya urefu iliyotolewa)
- **Data ya wazi**
- **Algorithimu (na inahatarishwa kwa shambulio hili)**
- **Padding inajulikana**
- Kawaida moja ya chaguo la msingi inatumika, hivyo ikiwa mahitaji mengine 3 yanakidhi, hii pia inafanya hivyo
- Padding inatofautiana kulingana na urefu wa siri + data, ndivyo maana urefu wa siri unahitajika

Basi, inawezekana kwa **mshambuliaji** **kuongeza** **data** na **kuunda** **sahihi** halali kwa **data ya awali + data iliyoongezwa**.

### Vipi?

K基本上, algorithimu zinazohatarishwa zinaweza kuunda hash kwa kwanza **kuhashi block ya data**, na kisha, **kutoka** kwa **hash** iliyoundwa **awali** (hali), wana **ongeza block inayofuata ya data** na **kuhashi**.

Basi, fikiria kwamba siri ni "siri" na data ni "data", MD5 ya "siri data" ni 6036708eba0d11f6ef52ad44e8b74d5b.\
Ikiwa mshambuliaji anataka kuongeza mfuatano "append" anaweza:

- Kuunda MD5 ya 64 "A"s
- Kubadilisha hali ya hash iliyowekwa awali kuwa 6036708eba0d11f6ef52ad44e8b74d5b
- Kuongeza mfuatano "append"
- Kumaliza hash na hash inayotokana itakuwa **halali kwa "siri" + "data" + "padding" + "append"**

### **Chombo**

{% embed url="https://github.com/iagox86/hash_extender" %}

### Marejeleo

Unaweza kupata shambulio hili limeelezwa vizuri katika [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../banners/hacktricks-training.md}}
