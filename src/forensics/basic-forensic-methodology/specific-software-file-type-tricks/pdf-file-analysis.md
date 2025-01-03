# PDF फ़ाइल विश्लेषण

{{#include ../../../banners/hacktricks-training.md}}

**अधिक जानकारी के लिए देखें:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

PDF प्रारूप अपनी जटिलता और डेटा को छिपाने की क्षमता के लिए जाना जाता है, जो इसे CTF फॉरेंसिक्स चुनौतियों के लिए एक केंद्र बिंदु बनाता है। यह सामान्य पाठ तत्वों को बाइनरी ऑब्जेक्ट्स के साथ मिलाता है, जो संकुचित या एन्क्रिप्टेड हो सकते हैं, और इसमें JavaScript या Flash जैसी भाषाओं में स्क्रिप्ट शामिल हो सकती हैं। PDF संरचना को समझने के लिए, कोई Didier Stevens के [परिचयात्मक सामग्री](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) का संदर्भ ले सकता है, या टेक्स्ट संपादक या Origami जैसे PDF-विशिष्ट संपादक का उपयोग कर सकता है।

PDFs के गहन अन्वेषण या हेरफेर के लिए, [qpdf](https://github.com/qpdf/qpdf) और [Origami](https://github.com/mobmewireless/origami-pdf) जैसे उपकरण उपलब्ध हैं। PDFs के भीतर छिपा डेटा निम्नलिखित में छिपा हो सकता है:

- अदृश्य परतें
- Adobe द्वारा XMP मेटाडेटा प्रारूप
- वृद्धिशील पीढ़ियाँ
- पृष्ठभूमि के समान रंग का पाठ
- छवियों के पीछे का पाठ या ओवरलैपिंग छवियाँ
- गैर-प्रदर्शित टिप्पणियाँ

कस्टम PDF विश्लेषण के लिए, Python पुस्तकालय जैसे [PeepDF](https://github.com/jesparza/peepdf) का उपयोग करके विशेष पार्सिंग स्क्रिप्ट बनाई जा सकती हैं। इसके अलावा, PDF के छिपे हुए डेटा भंडारण की क्षमता इतनी विशाल है कि NSA द्वारा PDF जोखिमों और प्रतिकृतियों पर गाइड जैसे संसाधन, हालांकि अब इसके मूल स्थान पर होस्ट नहीं किए गए हैं, फिर भी मूल्यवान अंतर्दृष्टि प्रदान करते हैं। [गाइड की एक प्रति](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%Bútmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) और Ange Albertini द्वारा [PDF प्रारूप ट्रिक्स](https://github.com/corkami/docs/blob/master/PDF/PDF.md) का एक संग्रह इस विषय पर आगे पढ़ने के लिए प्रदान कर सकता है।

{{#include ../../../banners/hacktricks-training.md}}
