# Hash Length Extension Attack

{{#include ../banners/hacktricks-training.md}}

## Samevatting van die aanval

Stel jou 'n bediener voor wat **onderteken** 'n paar **data** deur 'n **geheime** by 'n bekende duidelike teksdata te **voeg** en dan daardie data te hash. As jy weet:

- **Die lengte van die geheim** (dit kan ook gebruteforced word uit 'n gegewe lengterange)
- **Die duidelike teksdata**
- **Die algoritme (en dit is kwesbaar vir hierdie aanval)**
- **Die padding is bekend**
- Gewoonlik word 'n standaard een gebruik, so as die ander 3 vereistes nagekom word, is dit ook
- Die padding wissel afhangende van die lengte van die geheim+data, daarom is die lengte van die geheim nodig

Dan is dit moontlik vir 'n **aanvaller** om **data** te **voeg** en 'n geldige **handtekening** te **genereer** vir die **vorige data + bygevoegde data**.

### Hoe?

Basies genereer die kwesbare algoritmes die hashes deur eerstens **'n blok data te hash**, en dan, **uit** die **voorheen** geskepte **hash** (toestand), **voeg hulle die volgende blok data** by en **hash dit**.

Stel jou voor dat die geheim "secret" is en die data "data", die MD5 van "secretdata" is 6036708eba0d11f6ef52ad44e8b74d5b.\
As 'n aanvaller die string "append" wil byvoeg, kan hy:

- 'n MD5 van 64 "A"s genereer
- Die toestand van die voorheen geinitialiseerde hash verander na 6036708eba0d11f6ef52ad44e8b74d5b
- Die string "append" byvoeg
- Die hash voltooi en die resultaat sal 'n **geldige een wees vir "secret" + "data" + "padding" + "append"**

### **Gereedskap**

{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}

### Verwysings

Jy kan hierdie aanval goed verduidelik vind in [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../banners/hacktricks-training.md}}
