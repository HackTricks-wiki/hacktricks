# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Introduction

iButton technology की पृष्ठभूमि के लिए देखें:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

नीचे दी गई image में **blue** क्षेत्र दिखाता है कि पढ़ने के लिए physical iButton को Flipper Zero के contacts पर कैसे रखा जाए। **green** क्षेत्र दिखाता है कि emulation के दौरान reader को किन contacts को छूना चाहिए।<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## क्रियाएँ

### पढ़ें

Read mode में, Flipper Zero किसी key के अपने contacts को छूने का इंतज़ार करता है, protocol का पता लगाता है और key ID के ऊपर protocol दिखाता है। Built-in application Dallas, Cyfral और Metakom access-control keys को support करता है।<sup>[[2]](#references)</sup>

### मैन्युअल रूप से जोड़ें

आप Dallas, Cyfral और Metakom protocols के लिए key data मैन्युअल रूप से दर्ज कर सकते हैं।<sup>[[2]](#references)</sup>

### Emulate

आप किसी saved key को emulate कर सकते हैं, चाहे वह physical key से पढ़ी गई हो या मैन्युअल रूप से दर्ज की गई हो।<sup>[[2]](#references)</sup>

> [!TIP]
> अगर built-in contacts reader तक नहीं पहुँच पाते, तो GPIO pins के ज़रिए data और ground contacts को connect करें।<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Flipper Zero से iButton Keys को नियंत्रित करना](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Flipper Zero documentation - iButton keys पढ़ना](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}

