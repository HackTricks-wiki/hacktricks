# Word Macros

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Macros में analysis को धीमा करने के उद्देश्य से **unreachable या irrelevant code** हो सकता है। किसी branch को reverse करने में समय लगाने से पहले constant conditions की पहचान करें और reachable behavior को trace करें। नीचे दिए गए उदाहरण में junk code को छिपाने के लिए ऐसी `If` condition का उपयोग किया गया है जो कभी true नहीं हो सकती।

![Junk code वाली unreachable conditional branch वाला Word macro](<../images/image (369).png>)

## Macro Forms

VBA UserForms text boxes जैसे controls में data store कर सकते हैं। क्योंकि forms, frames और pages प्रत्येक `Controls` collection expose कर सकते हैं, इसलिए analysts को केवल form पर दिखाई देने वाली चीज़ों पर निर्भर रहने के बजाय पूरी control hierarchy enumerate करनी चाहिए। नीचे दिया गया उदाहरण overlapping text boxes में concealed data store करता है।<sup>[[1]](#references)</sup>

Dynamic analysis के दौरान, VBA का `GetObject` function किसी file से Automation object retrieve कर सकता है या पहले से चल रहे Automation server से attach कर सकता है। Macros उस object access का उपयोग visible document में स्पष्ट न होने वाले data तक पहुंचने के लिए कर सकते हैं; returned object और UserForm control tree दोनों का निरीक्षण करें।<sup>[[2]](#references)</sup>

![Overlapping text boxes में concealed data वाला macro UserForm](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Collections, controls, and objects (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - `GetObject` function](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../banners/hacktricks-training.md}}
