# औद्योगिक नियंत्रण प्रणालियों की Hacking

{{#include ../banners/hacktricks-training.md}}

## इस अनुभाग के बारे में

इस अनुभाग में औद्योगिक नियंत्रण प्रणाली (ICS) के घटकों, आर्किटेक्चर, प्रोटोकॉल और सुरक्षा-मूल्यांकन के तरीकों का परिचय दिया गया है। ICS, ऑपरेशनल टेक्नोलॉजी (OT) के व्यापक क्षेत्र का हिस्सा है: प्रोग्राम किए जा सकने वाले सिस्टम और डिवाइस, जो भौतिक प्रक्रियाओं की निगरानी करते हैं या उनमें बदलाव करते हैं। आम उदाहरणों में सुपरवाइजरी कंट्रोल एंड डेटा एक्विज़िशन (SCADA) सिस्टम, डिस्ट्रीब्यूटेड कंट्रोल सिस्टम (DCS) और प्रोग्रामेबल लॉजिक कंट्रोलर (PLC) शामिल हैं।<sup>[[1]](#references)</sup>

इन वातावरणों में सुरक्षा के काम में उन आवश्यकताओं का ध्यान रखना चाहिए जो पारंपरिक IT से अलग होती हैं, जिनमें प्रक्रिया-सुरक्षा, विश्वसनीयता, उपलब्धता, नियतात्मक संचालन और उपकरणों का जीवनकाल शामिल हैं। तकनीकी रूप से मान्य सुरक्षा नियंत्रण भी अनुपयुक्त हो सकता है, यदि वह भौतिक प्रक्रिया में बाधा डालता हो। इसलिए परीक्षण और सुधार के काम को सिस्टम के मालिक और संचालन कर्मियों के साथ समन्वित करना चाहिए।<sup>[[1]](#references)</sup>

किसी सिस्टम से छेड़छाड़ या आकस्मिक व्यवधान से उत्पादन रुक सकता है, उपकरणों को नुकसान पहुँच सकता है, खतरनाक पदार्थ निकल सकते हैं, पर्यावरण को नुकसान हो सकता है, या चोट और जानमाल का नुकसान हो सकता है। भौतिक प्रभाव की इस संभावना के कारण, सक्रिय परीक्षण से पहले नियंत्रित प्रक्रिया और उसकी सुरक्षित संचालन सीमाओं को समझना आवश्यक है।<sup>[[1]](#references)</sup>

कई OT परिनियोजनों में पुराने ऑपरेटिंग सिस्टम, एप्लिकेशन और प्रोटोकॉल बने रहते हैं, क्योंकि उपकरणों का सेवा-जीवन लंबा होता है और बदलावों के लिए संचालन तथा सुरक्षा परीक्षण आवश्यक होते हैं। कुछ प्रोटोकॉल आधुनिक प्रमाणीकरण या एन्क्रिप्शन के बिना डिज़ाइन किए गए थे, और विक्रेता के समर्थन या रखरखाव की समय-सीमा के कारण पैच लगाना सीमित हो सकता है; जहाँ सीधे अपग्रेड संभव न हों, वहाँ नेटवर्क सेगमेंटेशन, एक्सेस कंट्रोल और मॉनिटरिंग से जोखिम कम करें।<sup>[[1]](#references)</sup>

## मूल्यांकन की प्राथमिकताएँ

सबसे पहले नियंत्रित प्रक्रिया, सिस्टम की सीमाओं, नेटवर्क टोपोलॉजी, एसेट, डेटा प्रवाह, ट्रस्ट संबंधों और बाहरी कनेक्शनों को समझें। अलग-अलग साइटों पर एक जैसे डिवाइस अलग-अलग कार्य कर सकते हैं, इसलिए यह न मानें कि एक परिनियोजन का आर्किटेक्चर या प्रभाव-मॉडल दूसरे पर भी लागू होगा।<sup>[[1]](#references)</sup>

जहाँ संभव हो, पैसिव डिस्कवरी और मौजूदा इंजीनियरिंग दस्तावेज़ों को प्राथमिकता दें। किसी भी सक्रिय स्कैनिंग या exploitation के लिए स्वीकृत टेस्ट प्लान का पालन करना चाहिए, जिसमें सुरक्षा संबंधी सीमाएँ, रखरखाव की समय-सीमा, रिकवरी प्रक्रियाएँ और परीक्षण रोकने की शर्तें तय हों। निष्कर्षों का मूल्यांकन साइबर सुरक्षा पर प्रभाव और भौतिक प्रक्रिया पर संभावित प्रभाव—दोनों के आधार पर किया जाना चाहिए।<sup>[[1]](#references)</sup>

यही आर्किटेक्चरल जानकारी एसेट इन्वेंटरी, नेटवर्क सेगमेंटेशन, मॉनिटरिंग, incident response और जोखिम-आधारित vulnerability management जैसी रक्षात्मक गतिविधियों में भी मदद करती है।<sup>[[1]](#references)</sup>

## सुपरवाइजरी रेफ्रिजरेशन कंट्रोलर का दुरुपयोग

रेफ्रिजरेशन सिस्टम मैनेजर, कंप्रेसर और केस कंट्रोलरों के काम का समन्वय करता है, लेकिन स्वयं केस को ठंडा नहीं करता। इसलिए, इसके मैनेजमेंट इंटरफ़ेस तक पहुँच सामान्य कॉन्फ़िगरेशन वितरण के माध्यम से कई अधीनस्थ डिवाइसों पर नियंत्रण दिला सकती है। यह किसी एक थर्मोस्टैट में बदलाव करने या सीधे कंप्रेसर चलाने से अलग है।<sup>[[3]](#references)[[4]](#references)</sup>

### तारीख़ से निकला maintenance-code लॉगिन

प्रभावित Danfoss सिस्टम मैनेजरों पर, एक वैकल्पिक XML लॉगिन अकाउंट पासवर्ड के बजाय कंट्रोलर की तारीख़ से निकला कोड स्वीकार करता है।<sup>[[2]](#references)[[3]](#references)</sup> SM800 और SC255 पर, Synacktiv ने `eds_only` और `quantum_only` एट्रिब्यूट को `xml_load_file` और `check_authorize` के ज़रिए `check_code_of_day` तक ट्रेस किया। इसकी एडवाइज़री यह भी दिखाती है कि `xml.cgi` पर `read_date_time`, बिना प्रमाणीकरण के कंट्रोलर की तारीख़ बताता है।<sup>[[2]](#references)</sup> Claroty को AK-SM 800A पर इससे मिलता-जुलता `getauth` पाथ मिला, लेकिन उसने इसके ट्रिगर एट्रिब्यूट छिपा दिए; पुराने मॉडल के एट्रिब्यूट नामों को उस प्लेटफ़ॉर्म पर काम करने वाला नहीं मानना चाहिए।<sup>[[3]](#references)</sup>

Synacktiv बिना प्रमाणीकरण वाली तारीख़ क्वेरी को इस तरह दस्तावेज़ित करता है:<sup>[[2]](#references)</sup>

```bash
curl -k -d '<cmd action="read_date_time"/>' https://<controller>/xml.cgi
```

कोड में device-specific secret नहीं है: [firmware](../hardware-physical-access/firmware-analysis/) से algorithm recover करने पर, समान प्रभावित implementation वाले devices के लिए तारीख़ के अनुसार मान्य credential मिल सकता है।<sup>[[2]](#references)[[3]](#references)</sup> पहले model और firmware की पुष्टि करें। केवल तारीख़ के अनुसार मिले response से यह साबित नहीं होता कि alternate login मौजूद है या session प्राप्त हुआ है।

### Bulk configuration और defrost-heater का दुरुपयोग

Administrative access मिलने के बाद, system manager से mapped case controllers की पहचान करें और पता करें कि उसका configuration-distribution function उन सभी को एक साथ update कर सकता है या नहीं। Case setpoint बदलने से आम तौर पर cabinet केवल room temperature तक गर्म होता है। इसे ambient temperature से ज़्यादा गर्म करने के लिए, case controller का electric evaporator defrost heater प्रासंगिक control है: defrost cooling रोक देता है और उस heater को तब तक चलाता है, जब तक sensor या timer cycle को समाप्त न कर दे। इसके बजाय defrost method, schedule, termination temperature और time limit बदलकर heater को सक्रिय रखा जा सकता है। Manager इन बदलावों को कई cases में वितरित कर सकता है और संबंधित alarms को दबा सकता है, जिससे एक supervisory compromise पूरे store की process में बदलाव बन सकता है।<sup>[[4]](#references)</sup>

यह एक physical-process hazard है, live system पर सुरक्षित proof of concept नहीं। जहां मौजूद हों, thermal cut-outs heater के संचालन को सीमित कर सकते हैं, लेकिन लगातार चलने से पहले से कमज़ोर electrical connection भी ज़्यादा गर्म हो सकता है। Configuration और impact की पुष्टि केवल स्वीकृत lab में या operator की process-safety योजना के तहत करें।<sup>[[4]](#references)</sup>

## Protocol entry points

- [Modbus testing](../network-services-pentesting/pentesting-modbus.md) में Modbus TCP, serial variants, function codes और register access शामिल हैं।
- [OPC UA testing](../network-services-pentesting/4840-pentesting-opc-ua.md) में industrial data-exchange service शामिल है।
- [BACnet testing](../network-services-pentesting/47808-udp-bacnet.md) में building-automation control networks शामिल हैं।

## References

- [1] [NIST SP 800-82 Rev. 3 - Operational Technology (OT) Security के लिए मार्गदर्शिका](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [2] [Synacktiv - Danfoss System-Managers SM800 और SC255 में Authentication bypass](https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800-sc255-sc355-auth-bypass.pdf)
- [3] [Claroty Team82 - Controller को Freeze करें, Food को Defrost करें](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)
- [4] [Pen Test Partners - Fridge को गर्म करने के लिए nation state की ज़रूरत नहीं](https://pentestpartners.com/security-blog/you-dont-need-a-nation-state-to-warm-up-a-fridge)
{{#include ../banners/hacktricks-training.md}}
