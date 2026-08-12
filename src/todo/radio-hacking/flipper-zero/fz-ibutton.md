# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## परिचय

iButton technology की पृष्ठभूमि के लिए देखें:

{{#ref}}
../ibutton.md
{{#endref}}

## डिज़ाइन

निम्नलिखित image में, **नीला** क्षेत्र दिखाता है कि physical iButton को पढ़ने के लिए Flipper Zero के contacts के सामने कैसे रखना है। **हरा** क्षेत्र दिखाता है कि emulation के दौरान reader को किन contacts को स्पर्श करना चाहिए।<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## क्रियाएँ

### पढ़ना

Read mode में, Flipper Zero किसी key के अपने contacts को स्पर्श करने की प्रतीक्षा करता है, protocol का पता लगाता है और key ID के ऊपर protocol प्रदर्शित करता है। Built-in application Dallas, Cyfral और Metakom access-control keys को support करता है।<sup>[[2]](#references)</sup>

### मैन्युअल रूप से जोड़ना

आप Dallas, Cyfral और Metakom protocols के लिए key data manually enter कर सकते हैं।<sup>[[2]](#references)</sup>

### Emulate करना

आप किसी saved key को emulate कर सकते हैं, चाहे वह physical key से पढ़ी गई हो या manually enter की गई हो।<sup>[[2]](#references)</sup>

> [!TIP]
> यदि built-in contacts reader तक नहीं पहुंच सकते, तो GPIO pins के माध्यम से data और ground contacts को connect करें।<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Flipper Zero के साथ iButton Keys को नियंत्रित करना](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Flipper Zero documentation - iButton keys पढ़ना](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}
