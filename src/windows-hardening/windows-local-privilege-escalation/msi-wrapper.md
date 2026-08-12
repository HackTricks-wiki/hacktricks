# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper किसी executable या script को Windows Installer (`.msi`) file के रूप में package कर सकता है। Free edition को download करके शुरू करें, फिर package करने के लिए executable चुनें।<sup>[[3]](#references)</sup> Commands का sequence चलाने के लिए `cmd.exe` को package करने के बजाय input के रूप में `.bat` file चुनें।<sup>[[1]](#references)</sup>

![MSI Wrapper में source executable या batch script चुनना](<../../images/image (417).png>)

Execution context और अन्य installer properties को सावधानी से configure करें:

![MSI Wrapper में application ID और security context configure करना](<../../images/image (312).png>)

![MSI Wrapper में installer properties configure करना](<../../images/image (346).png>)

![MSI Wrapper की build settings की समीक्षा करना](<../../images/image (1072).png>)

Custom binary को package करते समय इन values को बदला जा सकता है।

बाकी wizard pages पर आगे बढ़ें और installer generate करने के लिए **Build** चुनें।<sup>[[1]](#references)</sup>

> [!WARNING]
> केवल MSI बनाने से elevated privileges अपने-आप नहीं मिलते। Installation elevated होगा या नहीं, यह Windows Installer policy, package context और user authorization पर निर्भर करता है। Microsoft चेतावनी देता है कि user और computer दोनों के लिए `AlwaysInstallElevated` enable करने पर non-administrators system privileges के साथ packages install कर सकते हैं।<sup>[[2]](#references)</sup>

## References

- [1] [MSI Wrapper documentation - शुरुआत करना](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - non-admin के लिए elevated privileges के साथ package install करना](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Download](https://www.exemsi.com/download/)
{{#include ../../banners/hacktricks-training.md}}
