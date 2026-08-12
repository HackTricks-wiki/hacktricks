# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi

Kwa maelezo ya msingi kuhusu teknolojia ya iButton, tazama:

{{#ref}}
../ibutton.md
{{#endref}}

## Muundo

Katika picha ifuatayo, eneo la **blue** linaonyesha jinsi ya kuweka iButton halisi dhidi ya viunganishi vya Flipper Zero kwa ajili ya kusoma. Eneo la **green** linaonyesha ni viunganishi gani vinapaswa kugusa reader wakati wa emulation.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Vitendo

### Soma

Katika hali ya Read, Flipper Zero husubiri key iguse viunganishi vyake, hutambua protocol, na kuonyesha protocol juu ya kitambulisho cha key. Application iliyojengewa ndani inatumia keys za access-control za Dallas, Cyfral, na Metakom.<sup>[[2]](#references)</sup>

### Ongeza kwa mkono

Unaweza kuingiza data ya key kwa mkono kwa protocols za Dallas, Cyfral, na Metakom.<sup>[[2]](#references)</sup>

### Emulate

Unaweza ku-emulate key iliyohifadhiwa, iwe ilisomwa kutoka kwenye key halisi au iliingizwa kwa mkono.<sup>[[2]](#references)</sup>

> [!TIP]
> Ikiwa viunganishi vilivyojengewa ndani haviwezi kufikia reader, unganisha viunganishi vya data na ground kupitia pini za GPIO.<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Kudhibiti iButton Keys kwa Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Nyaraka za Flipper Zero - Kusoma iButton keys](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}
