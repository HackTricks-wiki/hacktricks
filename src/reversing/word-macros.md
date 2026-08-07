# Word Macros

{{#include ../banners/hacktricks-training.md}}

### Junk Code

Macro को reverse करना अधिक कठिन बनाने के लिए **कभी उपयोग न किया जाने वाला junk code** मिलना बहुत आम है।\
उदाहरण के लिए, निम्नलिखित image में आप देख सकते हैं कि एक ऐसी `If` condition, जो कभी true नहीं होने वाली है, कुछ junk और बेकार code को execute करने के लिए उपयोग की गई है।

![Word Macros - Junk Code: उदाहरण के लिए, निम्नलिखित image में आप देख सकते हैं कि एक ऐसी If condition, जो कभी true नहीं होने वाली है, कुछ junk और बेकार code को execute करने के लिए उपयोग की गई है](<../images/image (369).png>)

### Macro Forms

**GetObject** function का उपयोग करके macro के forms से data प्राप्त करना संभव है। इसका उपयोग analysis को कठिन बनाने के लिए किया जा सकता है। निम्नलिखित एक macro form का photo है, जिसका उपयोग **text boxes के अंदर data छिपाने** के लिए किया गया है (एक text box अन्य text boxes को छिपा सकता है):

![Junk Code - Macro Forms: GetObject function का उपयोग करके macro के forms से data प्राप्त करना संभव है। इसका उपयोग analysis को कठिन बनाने के लिए किया जा सकता है। निम्नलिखित एक macro form का photo है...](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
