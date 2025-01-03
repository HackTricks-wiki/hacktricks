# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): यह प्रत्येक प्रक्रिया द्वारा बनाए गए हर कनेक्शन की निगरानी करेगा। मोड (साइलेंट अनुमति कनेक्शन, साइलेंट अस्वीकार कनेक्शन और अलर्ट) के आधार पर, यह हर बार जब एक नया कनेक्शन स्थापित होता है, आपको **एक अलर्ट दिखाएगा**। इसमें सभी जानकारी देखने के लिए एक बहुत अच्छा GUI भी है।
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See फ़ायरवॉल। यह एक बुनियादी फ़ायरवॉल है जो संदिग्ध कनेक्शनों के लिए आपको अलर्ट करेगा (इसमें एक GUI है लेकिन यह Little Snitch के जैसा फैंसी नहीं है)।

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-See एप्लिकेशन जो कई स्थानों में खोज करेगा जहाँ **malware स्थायी हो सकता है** (यह एक एकल-शॉट उपकरण है, निगरानी सेवा नहीं)।
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): KnockKnock की तरह, जो स्थिरता उत्पन्न करने वाली प्रक्रियाओं की निगरानी करता है।

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Objective-See एप्लिकेशन जो **keyloggers** को खोजने के लिए है जो कीबोर्ड "इवेंट टैप" स्थापित करते हैं&#x20;

{{#include ../../banners/hacktricks-training.md}}
