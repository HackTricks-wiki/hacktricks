# Lateral Movement

{{#include ../../banners/hacktricks-training.md}}

Windows कई ऐसे mechanisms का support करता है जिनका उपयोग remote systems पर commands execute करने के लिए किया जा सकता है। निम्नलिखित pages common lateral-movement techniques और उनकी prerequisites समझाते हैं:

- [**PsExec**](psexec-and-winexec.md)
- [**SmbExec**](psexec-and-winexec.md#impacket-smbexecpy-smbexec)
- [**WmiExec**](wmiexec.md)
- [**AtExec / SchtasksExec**](atexec.md)
- [**WinRM**](winrm.md)
- [**DCOM Exec**](dcomexec.md)
- [**RDPexec**](rdpexec.md)
- [**SCMexec**](scmexec.md)
- **Pass the cookie** (cloud)<sup>[[1]](#references)</sup>
- **Pass the PRT** (cloud)<sup>[[2]](#references)</sup>
- **Pass the Microsoft Entra ID certificate** (cloud)<sup>[[3]](#references)</sup>

## References

- [1] [HackTricks Cloud - कुकी पास करना](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/az-pass-the-cookie.html)
- [2] [HackTricks Cloud - PRT पास करना](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html)
- [3] [HackTricks Cloud - सर्टिफिकेट पास करना](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/az-pass-the-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
