# Kernel-Mode File Access Check Bypasses

{{#include ../../banners/hacktricks-training.md}}

## Vulnerable driver pattern

Driver केवल caller का impersonation करके उसकी security boundary को बनाए नहीं रखता। Kernel-mode में object खोलने पर आम तौर पर access checks bypass हो जाते हैं। `OBJ_KERNEL_HANDLE` केवल resulting handle को kernel mode से accessible बनाता है। जब driver user mode की ओर से कोई object खोलता या उसमें बदलाव करता है, तो उसे `OBJ_FORCE_ACCESS_CHECK` का भी उपयोग करना चाहिए, ताकि Object Manager requested access को effective token के विरुद्ध evaluate करे।<sup>[[3]](#references)[[4]](#references)</sup>

इस sequence के लिए file-handling IOCTLs और create callbacks का audit करें:<sup>[[3]](#references)[[4]](#references)</sup>

1. User mode कोई path, source handle, desired access या operation type देता है।
2. Driver caller का impersonation करता है, लेकिन `OBJ_FORCE_ACCESS_CHECK` के बिना `IoCreateFileEx`, `ZwCreateFile` या इसी तरह की routine को call करता है।
3. Kernel-only file या directory handle को per-handle state में save किया जाता है।
4. बाद का operation यह तय करता है कि attacker-influenced state के आधार पर impersonation करना है या नहीं—उदाहरण के लिए, पहले open के दौरान requested access mask के आधार पर।
5. Privileged branch `BypassAccessCheck` information class के साथ rename या link करता है।

यह **confused-deputy file primitive** है, जरूरी नहीं कि memory corruption हो। State inversion का एक खास तौर पर खतरनाक उदाहरण है: “write requested हो तो impersonate करो; write requested न हो तो privileged बने रहो।” इस design में, जानबूझकर केवल read access मांगने से अधिक शक्तिशाली path खुल सकता है।<sup>[[3]](#references)</sup>

## vSMB उदाहरण: privileged root और privileged rename

`storvsp.sys` Virtual Server Message Block (vSMB) को implement करता है। **Virtual Machine Platform** feature enabled होने पर, user mode `\\.\STORVSP` के जरिए `\Device\STORVSP` तक पहुंच सकता है। vSMB filesystem path का रूप `\\.\STORVSP\VSMB\??\C:\path` होता है। CVE-2025-59517 और CVE-2025-64673 ने दिखाया कि access control के दो असंगत फैसले इस interface को local privilege escalation में कैसे बदल सकते हैं।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Source में function-to-CVE mapping, Microsoft source के बजाय patched binary की reverse engineering पर आधारित है। Researchers चेतावनी देते हैं कि दोनों identifiers का mapping उलटे functions से हो सकता है।<sup>[[3]](#references)</sup>

### 1. Protected directory पर rooted read-only share बनाएं

Vulnerable create path requested rights को `HasReadAccess`, `HasWriteAccess` और `HasAppendAccess` जैसे persistent flags में दर्ज करता था। फिर यह backing path को `OBJ_KERNEL_HANDLE` के साथ, लेकिन `OBJ_FORCE_ACCESS_CHECK` के बिना खोलता था। इसलिए attempted impersonation के बावजूद file open में caller की NTFS permissions लागू नहीं होती थीं।<sup>[[3]](#references)[[4]](#references)</sup>

केवल `FILE_READ_DATA` का अनुरोध करें। इससे `HasWriteAccess` clear रहता है, जबकि protected directory को internal root के रूप में इस्तेमाल करने वाला share फिर भी मिलता है:<sup>[[3]](#references)</sup>

```c
HANDLE root = CreateFileW(
    L"\\\\.\\STORVSP\\VSMB\\??\\C:\\Windows\\System32\\",
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
    NULL
);
```

महत्वपूर्ण artifact कोई user-mode System32 directory handle नहीं है। यह driver state से जुड़ा vSMB device handle है, जिसमें एक privileged kernel root handle होता है।<sup>[[3]](#references)</sup>

### 2. state mismatch को protected file replacement में बदलें

IOCTL `0x240330` ने source file handle, information class और variable-length information buffer स्वीकार किए:<sup>[[3]](#references)</sup>

```c
#define IOCTL_VSMB_SET_INFORMATION_FILE_REQUEST 0x240330

typedef struct _VSMB_SET_INFO {
    DWORD Version;
    DWORD Reserved;
    UINT64 SourceHandle;
    DWORD InformationClass;
    DWORD BufferLength;
    BYTE Buffer[1];
} VSMB_SET_INFO;
```

Vulnerable handler ने `FileRenameInformation`, `FileLinkInformation`, और `FileRenameInformationEx` स्वीकार किए। सामान्य rename path के लिए, उसने parent path को अंतिम component से अलग किया, फिर stored root handle के सापेक्ष parent को खोला। उस open में फिर से `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE` का उपयोग किया गया, लेकिन `OBJ_FORCE_ACCESS_CHECK` का नहीं। Rename structure में attacker द्वारा दिया गया गैर-शून्य `RootDirectory` अस्वीकार कर दिया गया, इसलिए driver ने अपना privileged directory handle दिया।<sup>[[3]](#references)</sup>

Exploit योग्य branch तब चुनी जाती थी जब stage 1 में write access का अनुरोध **नहीं** किया जाता था:<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1`: saved root security context को impersonate करें।
- `HasWriteAccess == 0`: impersonation छोड़ें और `FileRenameInformation` या `FileRenameInformationEx` को उसके `BypassAccessCheck` variant में बदलें।

Handler ने attacker द्वारा दिए गए source handle को `PsInitialSystemProcess` में duplicate किया, उसे file object के रूप में reference किया, privileged target-directory handle को rename structure में रखा, और `ZwSetInformationFile` को call किया। `ReplaceIfExists = TRUE` होने पर, caller द्वारा नियंत्रित file protected root के नीचे मौजूद किसी file को replace कर सकती थी।<sup>[[3]](#references)</sup>

ऐसे ही handler की समीक्षा करते समय, हर branch में **handle provenance और security context—दोनों** को track करें। Input validation, integer-overflow checks, `IO_STOP_ON_SYMLINK`, और स्वीकार किए जाने वाले information classes को सीमित करना, privileged root handle के साथ access-check-bypass operation के उपयोग की भरपाई नहीं करते।<sup>[[3]](#references)</sup>

## Protected write से SYSTEM execution तक

Protected file-replacement primitive तब code execution में बदल जाती है, जब कोई privileged process बाद में बदले गए module को load करता है। दिखाए गए chain में destination `C:\Windows\System32\wuapi.dll` था। Interface `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}` के लिए local-server COM class `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}` को activate करने और `IWaaSRemediation::LaunchDetectionOnly()` call करने से SYSTEM process ने वह DLL load की।<sup>[[3]](#references)</sup>

यह COM call एक **activation trigger** है, [COM registry hijacking](com-hijacking.md) नहीं। File primitive planted module देती है और privileged loader execution कराता है। अन्य protected-write chains के लिए, target चुनने से पहले सटीक image, DLL path, signature policy, bitness, exported functions, और विश्वसनीय trigger पहचानें। सामान्य loader-analysis workflow के लिए [arbitrary file write को DLL hijacking में chain करना](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) देखें।<sup>[[3]](#references)</sup>

### Session 0 token को interactive desktop पर ले जाना

किसी service द्वारा load किया गया payload आमतौर पर Session 0 में execute होता है। Interactive process बनाने के लिए, वह `WTSGetActiveConsoleSessionId` से active console session प्राप्त कर सकता है, आवश्यक token privileges enable कर सकता है, मौजूदा SYSTEM token को primary token के रूप में duplicate कर सकता है, और उसका `TokenSessionId` active session पर set कर सकता है। इसके बाद `CreateProcessAsUserW` उस token का उपयोग `STARTUPINFO.lpDesktop = L"winsta0\\default"` के साथ करता है।<sup>[[3]](#references)[[5]](#references)</sup>

```c
DWORD sid = WTSGetActiveConsoleSessionId();
DuplicateTokenEx(currentToken, MAXIMUM_ALLOWED, NULL,
                 SecurityImpersonation, TokenPrimary, &primary);
SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
si.lpDesktop = L"winsta0\\default";
CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe",
                     NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                     NULL, NULL, &si, &pi);
```

`SeTcbPrivilege` इस परिदृश्य में token का session ID सेट करने के लिए आवश्यक है। Interactive window station और desktop को भी token को access देना होगा। व्यापक token-copy workflow के लिए [Session 0 से token duplication](sedebug-+-seimpersonate-copy-token.md) देखें।<sup>[[3]](#references)[[5]](#references)</sup>

## Patch और समीक्षा संबंधी मार्गदर्शन

Microsoft के दिसंबर 2025 updates ने प्रदर्शित chain को ठीक कर दिया। Reverse engineering से पता चला कि patched vSMB create path उन untrusted callers की request अस्वीकार करता है जो `FILE_WRITE_DATA` के बिना share root का अनुरोध करते हैं। संबंधित operations में forced access checking भी जोड़ी गई। इससे unprivileged caller के privileged root हासिल करने से पहले state inversion रुक जाती है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Driver code के लिए ये नियम अपनाएँ:<sup>[[3]](#references)[[4]](#references)</sup>

- जब भी किसी user-mode request की ओर से object खोला जाए, `OBJ_FORCE_ACCESS_CHECK` जोड़ें। `OBJ_KERNEL_HANDLE` को authorization control न मानें।<sup>[[4]](#references)</sup>
- Requestor mode और effective subject context को capture और validate करें। Requested rights को अधिक privileged execution branch चुनने न दें।
- User handles को सही object type, access mask और `UserMode` के साथ validate करें। किसी handle को system process में duplicate करने से requested operation के अधिकार की पुष्टि नहीं होती।
- Target resolution को trusted handle के सापेक्ष रखें, लेकिन सुनिश्चित करें कि trusted handle स्वयं requestor की enforced access check के अंतर्गत खोला गया था।
- User-driven operations के लिए `File*BypassAccessCheck` classes का उपयोग न करें। यदि internal code को वास्तव में इनकी आवश्यकता हो, तो उस path को user-controlled access flags से स्वतंत्र authorization decision के अधीन रखें।
- प्रभावित systems को patch करें। Vulnerable surface तब प्रासंगिक होता है जब Virtual Machine Platform `storvsp.sys` load करता है।<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - Virtual Share से Physical Shell तक: LPE के लिए Windows के असंगत Access Control का लाभ उठाना](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - Object Handles](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - CreateProcessAsUserW function](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
{{#include ../../banners/hacktricks-training.md}}
