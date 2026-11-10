# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper किसी executable या script को Windows Installer (`.msi`) फ़ाइल के रूप में पैकेज कर सकता है। मुफ़्त संस्करण डाउनलोड करके शुरू करें, फिर पैकेज करने के लिए executable चुनें।<sup>[[3]](#references)</sup> कमांड की एक श्रृंखला चलाने के लिए, `cmd.exe` को पैकेज करने के बजाय इनपुट के रूप में `.bat` फ़ाइल चुनें।<sup>[[1]](#references)</sup>

![MSI Wrapper में सोर्स executable या batch script चुनना](<../../images/image (417).png>)

Execution context और installer की अन्य properties सावधानी से कॉन्फ़िगर करें:

![MSI Wrapper में application ID और security context कॉन्फ़िगर करना](<../../images/image (312).png>)

![MSI Wrapper में installer की properties कॉन्फ़िगर करना](<../../images/image (346).png>)

![MSI Wrapper की build settings की समीक्षा करना](<../../images/image (1072).png>)

Custom binary पैकेज करते समय इन मानों को बदला जा सकता है।

बाकी wizard पेजों पर आगे बढ़ें और installer बनाने के लिए **Build** चुनें।<sup>[[1]](#references)</sup>

## लपेटे गए command का execution context सत्यापित करें

टेस्ट पैकेज के लिए, MSI की elevation setting को child process पर लागू मानने के बजाय, ऐसा `.bat` फ़ाइल wrap करें जो उसके token को रिकॉर्ड करे।<sup>[[4]](#references)</sup> Wizard में **User** के बजाय **System** security context चुनें और, यदि यही अपेक्षित तरीका है, तो per-machine, elevated installation चुनें।<sup>[[5]](#references)</sup> **System** विकल्प authorization को bypass नहीं करता: non-admin को अब भी elevated installation के लिए कोई रास्ता चाहिए, जैसे [दो-policy वाला `AlwaysInstallElevated` misconfiguration](index.html#alwaysinstallelevated) या कोई privileged installer workflow।<sup>[[2]](#references)</sup> इसके बजाय **User** चुनने पर wrapped command, installation करने वाले user के context में चलती है; user-specific या network resources के लिए यह आवश्यक हो सकता है।<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

इस batch file को input के रूप में इस्तेमाल करके MSI build करें, फिर इसे test host पर चलाएँ और दर्ज की गई identity और privileges की जाँच करें।<sup>[[4]](#references)</sup> MSI Wrapper, batch के nonzero exit code को installation error 1603 में बदलता है, इसलिए सफल test के बाद गलत failure से बचने के लिए स्पष्ट रूप से zero exit करें।<sup>[[4]](#references)</sup> Output file एक test artifact है; केवल `msiexec` के सफल exit या quiet install के आधार पर SYSTEM execution का निष्कर्ष न निकालें।<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn` MSI UI को शांत करता है, लेकिन ज़रूरी नहीं कि wrapped executable का अपना UI भी शांत हो।<sup>[[6]](#references)[[7]](#references)</sup> Wrapped installer के लिए, wizard में उसके समर्थित silent arguments सेट करें; MSI Wrapper की dynamic `WRAPPED_ARGUMENTS` property एक PRO feature है।<sup>[[1]](#references)[[7]](#references)</sup> अगर आपको custom-action sequencing और impersonation पर सीधा नियंत्रण चाहिए, तो [WiX custom-action approach](create-msi-with-wix.md) देखें।

> [!WARNING]
> MSI बनाने से अपने आप elevated privileges नहीं मिलते। Installation elevated होगा या नहीं, यह Windows Installer policy, package context और user authorization पर निर्भर करता है। Microsoft चेतावनी देता है कि user और computer, दोनों के लिए `AlwaysInstallElevated` सक्षम करने पर non-administrators system privileges के साथ packages install कर सकते हैं।<sup>[[2]](#references)</sup>



## References

- [1] [MSI Wrapper documentation - शुरू करना](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - non-admin के लिए elevated privileges के साथ package install करना](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Download](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - batch file से MSI बनाना](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - Wizard Pages](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - Command-Line Options](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - Command Line Arguments](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
