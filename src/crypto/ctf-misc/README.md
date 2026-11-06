# Crypto CTF Mengineyo

{{#include ../../banners/hacktricks-training.md}}

Sehemu hii inakusanya mbinu zinazojitokeza katika changamoto za cryptography lakini hazilingani vizuri na kategoria nyingine.

## Lugha za esoteriki

### Mbinu

Tumia mtiririko huu wa kazi changamoto inapohitaji kuendesha programu ya lugha ya esoteriki na kufasiri matokeo yake.

Ikiwa changamoto inakupa code ambayo haifanani na lugha ya kawaida:

- Tambua lugha kwa kutafuta tokeni au mfuatano wa maagizo unaoitofautisha.
- Tumia interpreter ya mtandaoni au image ya Docker.
- Ikiwa matokeo ni ya ajabu, tafuta tabaka za encoding/compression baada ya utekelezaji.

Orodha muhimu ya lugha ni wiki ya Esolang.<sup>[[1]](#references)</sup> Kwa tabaka za kawaida za encoding na compression, tumia [mtiririko wa kazi wa Crypto CTF](../ctf-workflow/). Ikiwa kidokezo ni maandishi yasiyoonekana badala ya sintaksia inayotekelezeka, angalia [text steganography](../../stego/text/).

### Kutoa hali iliyopakiwa awali kwenye interpreter

Ikiwa changamoto inapokea source code ya lugha ya esoteriki na kuiendesha katika **interpreter maalum**, kagua kumbukumbu yake ya awali, stack na maagizo ya kutoa matokeo kabla ya kuchukulia source code hiyo kuwa fumbo la decoding. Interpreter inapopakia siri kwenye stack ya Befunge, programu fupi inaweza kutoa na kuchapisha baiti zilizopo bila kuzihesabu. Hii inahitaji udhibiti wa source code inayotekelezwa na opcode ya kutoa matokeo; haifanyi kazi dhidi ya interpreter ya kawaida iliyo tupu. Katika changamoto ya Befunge, ingizo lililo hapa chini lilitoa herufi kutoka kwenye flag iliyopakiwa awali kwenye stack kwa mpangilio wa kinyume, mara kwa mara.<sup>[[2]](#references)[[3]](#references)</sup>

```befunge
>,<
```

`>` huanzisha utekelezaji kuelekea kulia, `,` hutoa kipengee kutoka kwenye stack na kuchapisha herufi, na `<` hurudisha pointer ya maagizo hadi `,`. Kagua tabia ya custom interpreter inapokabiliwa na underflow na kikomo cha maagizo: utekelezaji uliotajwa husimama stack inapoishiwa au baada ya maagizo 1,024. Ikiwa siri haipo moja kwa moja kwenye stack, kagua hali nyingine zilizoanzishwa na maagizo yanayopatikana ya kutoa/kusoma badala ya kudhani kuwa semantiki za kawaida za Befunge zinatumika.<sup>[[3]](#references)[[4]](#references)</sup>



## References

- [1] [Esolang, wiki ya lugha za programu za esoteric](https://esolangs.org/wiki/Main_Page)
- [2] [Maandishi asilia ya suluhisho la WolvCTF 2024 Befuddled1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/README.md)
- [3] [Msimbo chanzo wa interpreter ya WolvCTF 2024 Befuddled1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py)
- [4] [Marejeo ya lugha ya Befunge](https://esolangs.org/wiki/Befunge)
{{#include ../../banners/hacktricks-training.md}}
