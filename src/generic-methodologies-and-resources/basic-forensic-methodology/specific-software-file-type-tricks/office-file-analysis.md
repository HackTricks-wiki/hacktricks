# Office फ़ाइल विश्लेषण

{{#include ../../../banners/hacktricks-training.md}}

अधिक जानकारी के लिए [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) देखें। यह केवल एक सारांश है:<sup>[[2]](#references)</sup>

Microsoft Office दस्तावेज़ आमतौर पर पुराने फ़ॉर्मैट जैसे RTF और OLE/CFBF-आधारित DOC, XLS और PPT, या नए **Office Open XML (OOXML)** फ़ॉर्मैट जैसे DOCX, XLSX और PPTX में मिलते हैं। Office दस्तावेज़ों में macros जैसी सक्रिय सामग्री हो सकती है, जिससे वे phishing और malware फैलाने के आम माध्यम बन जाते हैं। OOXML फ़ाइलें ZIP कंटेनर होती हैं, जिनकी फ़ाइल संरचना और XML सामग्री को अनज़िप करके देखा जा सकता है।<sup>[[1]](#references)[[2]](#references)</sup>

OOXML फ़ाइल संरचनाओं को देखने के लिए, दस्तावेज़ को अनज़िप करने का कमांड और आउटपुट संरचना दी गई है। इन फ़ाइलों में डेटा छिपाने की तकनीकें भी दर्ज की गई हैं, जो CTF चुनौतियों में डेटा छिपाने के तरीकों में लगातार हो रहे नए प्रयोगों को दर्शाती हैं।<sup>[[2]](#references)</sup>

विश्लेषण के लिए, **oletools** और **OfficeDissector**, OLE और OOXML दोनों दस्तावेज़ों की जाँच के लिए व्यापक टूलसेट देते हैं। ये टूल एम्बेड किए गए macros की पहचान और विश्लेषण में मदद करते हैं। ऐसे macros अक्सर malware पहुँचाने के माध्यम होते हैं और आमतौर पर अतिरिक्त दुर्भावनापूर्ण payloads डाउनलोड करके चलाते हैं। VBA macros का विश्लेषण Microsoft Office के बिना Libre Office का उपयोग करके किया जा सकता है, जो breakpoints और watch variables के साथ debugging की सुविधा देता है।<sup>[[2]](#references)</sup>

**oletools** को इंस्टॉल करना और इस्तेमाल करना आसान है; इसे pip से इंस्टॉल करने और दस्तावेज़ों से macros निकालने के कमांड दिए गए हैं। Word में, स्वचालित macros में `AutoExec` और `AutoOpen` शामिल हैं, जबकि `Document_Open` एक open-event procedure है।<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## VBA macro analysis: junk code and UserForms

## जंक कोड

Macros में विश्लेषण को धीमा करने के लिए **अप्राप्य या अप्रासंगिक कोड** हो सकता है। किसी branch को reverse करने में समय लगाने से पहले constant conditions पहचानें और पता लगाएँ कि कौन-सा व्यवहार reachable है। नीचे दिए गए उदाहरण में junk code छिपाने के लिए ऐसी `If` condition का उपयोग किया गया है जो कभी true नहीं हो सकती।

![अप्राप्य conditional branch में junk code वाला Word macro](<../../../images/image (369).png>)

## Macro Forms

VBA UserForms, text boxes जैसे controls में data स्टोर कर सकते हैं। चूँकि forms, frames और pages में से हर एक `Controls` collection उपलब्ध करा सकता है, इसलिए analysts को केवल form पर दिखाई देने वाली चीज़ों पर निर्भर रहने के बजाय पूरे control hierarchy की सूची बनानी चाहिए। नीचे दिए गए उदाहरण में overlapping text boxes में छिपा हुआ data स्टोर किया गया है।<sup>[[6]](#references)</sup>

Dynamic analysis के दौरान, VBA का `GetObject` function किसी file से Automation object प्राप्त कर सकता है या पहले से चल रहे Automation server से जुड़ सकता है। Macros इस object access का उपयोग ऐसे data तक पहुँचने के लिए कर सकते हैं जो दिखाई देने वाले document में स्पष्ट न हो; लौटाए गए object और UserForm control tree, दोनों की जाँच करें।<sup>[[7]](#references)</sup>

![Overlapping text boxes में छिपे data वाला macro UserForm](<../../../images/image (344).png>)

Password-encrypted Office documents के लिए, [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example) देखें।

---

OLE/CFBF का उपयोग करने वाली Revit RFA files के लिए, [ECC recomputation, controlled gzip, and deserializer exploitation](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md) देखें; यह parser-exploitation workflow, Office document triage से अलग है।

## References

- [1] [OLE Compound File (CFBF) दस्तावेज़](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [3] [olevba documentation (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Document.Open event (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn - Collections, controls, and objects (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn - `GetObject` function](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
