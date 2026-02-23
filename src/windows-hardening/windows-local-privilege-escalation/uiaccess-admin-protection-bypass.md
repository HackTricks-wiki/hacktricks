# Admin Protection Bypasses via UIAccess

{{#include ../../banners/hacktricks-training.md}}

## सारांश
- Windows AppInfo `RAiLaunchAdminProcess` एक्सपोज़ करता है ताकि UIAccess processes (accessibility के लिए) लॉन्च किए जा सकें। UIAccess अधिकांश User Interface Privilege Isolation (UIPI) message filtering को बायपास करता है ताकि accessibility सॉफ्टवेयर higher-IL UI को drive कर सके।
- UIAccess को सीधे इनेबल करने के लिए `NtSetInformationToken(TokenUIAccess)` के साथ **SeTcbPrivilege** चाहिए, इसलिए low-priv कॉलर सर्विस पर निर्भर करते हैं। सर्विस target binary पर UIAccess सेट करने से पहले तीन चेक करती है:
  - Embedded manifest में `uiAccess="true"` होना चाहिए।
  - Local Machine root store द्वारा ट्रस्टेड किसी सर्टिफिकेट से साइन किया हुआ होना चाहिए (कोई EKU/Microsoft requirement नहीं)।
  - सिस्टम ड्राइव पर administrator-only path में स्थित होना चाहिए (उदा., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, कुछ writable सबपाथ्स को छोड़कर)।
- `RAiLaunchAdminProcess` UIAccess लॉन्च के लिए कोई consent prompt नहीं दिखाता (नहीं तो accessibility tooling prompt को drive नहीं कर पाती)।

## टोकन शेपिंग और इंटीग्रिटी स्तर (IL)
- यदि चेक सफल होते हैं, तो AppInfo **caller token को copy** करता है, UIAccess enable करता है, और Integrity Level (IL) को बढ़ाता है:
  - Limited admin user (user Administrators में है पर filtered रन कर रहा है) ➜ **High IL**।
  - Non-admin user ➜ IL को **+16 levels** से बढ़ाया जाता है, पर **High** कैप तक ही (System IL कभी assign नहीं होता)।
- अगर caller token में पहले से UIAccess है तो IL अपरिवर्तित रहता है।
- “Ratchet” ट्रिक: एक UIAccess process अपने आप पर UIAccess disable कर सकता है, `RAiLaunchAdminProcess` के जरिए फिर से लॉन्च कर सकता है, और हर बार +16 IL increment पा सकता है। Medium➜High के लिए 255 relaunches लगते हैं (शोर होता है, पर काम करता है)।

## क्यों UIAccess एक Admin Protection escape सक्षम करता है
- UIAccess एक lower-IL process को higher-IL विंडोज़ को window messages भेजने देता है (UIPI filters को बायपास करते हुए)। समान IL पर, क्लासिक UI primitives जैसे `SetWindowsHookEx` किसी भी process में code injection/DLL loading की अनुमति देते हैं जो विंडो का मालिक हो (message-only windows जिन्हें COM उपयोग करता है सहित)।
- Admin Protection UIAccess process को **limited user की identity** पर परंतु **High IL** पर मौन रूप से लॉन्च करता है। एक बार arbitrary code उस High-IL UIAccess process के अंदर चलने लगे, attacker अन्य High-IL processes (desktop पर, यहाँ तक कि अलग users के होने पर भी) में inject कर सकता है, और intended separation टूट जाती है।

## Secure-directory validation कमजोरियां (AppInfo `AiCheckSecureApplicationDirectory`)
AppInfo दिए गए path को `GetFinalPathNameByHandle` के जरिए resolve करता है और फिर हार्डकोडेड roots/exclusions के खिलाफ **string allow/deny checks** लागू करता है। उस सरल validation से कई bypass classes निकलते हैं:
- **Directory named streams**: Excluded writable directories (उदा., `C:\Windows\tracing`) को directory के ऊपर named stream के साथ bypass किया जा सकता है, जैसे `C:\Windows\tracing:file.exe`। string checks `C:\Windows\` को देखते हैं और excluded subpath को मिस कर देते हैं।
- **Writable file/directory inside an allowed root**: `CreateProcessAsUser` को `.exe` extension की आवश्यकता नहीं है। किसी भी writable file को allowed root के तहत overwrite कर executable payload रख देना काम करता है, या signed `uiAccess="true"` EXE को किसी writable subdirectory (उदा., update leftovers जैसे `Tasks_Migrated` अगर मौजूद हो) में कॉपी करना secure-path check पास करवा देता है।
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins signed MSIX packages install कर सकते थे जो `WindowsApps` में आ जाते थे, जो excluded नहीं था। MSIX के अंदर UIAccess बाइनरी पैकेज करके और उसे `RAiLaunchAdminProcess` से लॉन्च करके promptless High-IL UIAccess process मिलता था। Microsoft ने इस path को exclude करके mitigation दी; साथ ही `uiAccess` restricted MSIX capability खुद ही admin install की मांग करती है।

## Attack workflow (बिना prompt के High IL)
1. एक signed UIAccess binary प्राप्त/बनाएँ (manifest `uiAccess="true"`)।
2. इसे AppInfo की allowlist में आने वाली जगह पर रखें (या ऊपर बताए गए path-validation edge case/writable artifact का दुरुपयोग करें)।
3. `RAiLaunchAdminProcess` कॉल करके इसे **silent** रूप से UIAccess + elevated IL के साथ spawn करें।
4. उस High-IL foothold से, किसी अन्य High-IL process को desktop पर target करें `window hooks/DLL injection` या अन्य same-IL primitives का उपयोग करके और admin context को पूरी तरह compromise करें।

## लिखने योग्य संभावित पथों का पता लगाना
PowerShell helper चलाएँ ताकि चुने हुए token के परिप्रेक्ष्य से nominally secure roots के अंदर writable/overwritable objects का पता चल सके:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Run as Administrator व्यापक दृश्यता के लिए चलाएँ; `-ProcessId` को एक low-priv प्रक्रिया पर सेट करें ताकि वह token की access का प्रतिबिंब बने।
- `RAiLaunchAdminProcess` के साथ candidates का उपयोग करने से पहले ज्ञात निषिद्ध उपनिर्देशिकाओं को मैन्युअल रूप से फ़िल्टर करें।

## संदर्भ
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
