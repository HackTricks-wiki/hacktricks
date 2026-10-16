# Lateral Movement

{{#include ../../banners/hacktricks-training.md}}

Windows में ऐसे कई तरीके हैं जिनका इस्तेमाल remote systems पर commands चलाने के लिए किया जा सकता है। नीचे दिए गए पेज सामान्य lateral-movement techniques और उनकी आवश्यक शर्तों के बारे में बताते हैं:

- [**PsExec / SCM service execution**](psexec-and-winexec.md#how-do-they-work)
- [**SmbExec**](psexec-and-winexec.md#impacket-smbexecpy-smbexec)
- [**WmiExec**](wmiexec.md)
- [**AtExec / SchtasksExec**](atexec.md)
- [**WinRM**](winrm.md)
- [**DCOM Exec**](dcomexec.md)
- [**RDPexec: authenticated RDP command execution**](../../network-services-pentesting/pentesting-rdp.md#remote-command-execution-with-an-authenticated-rdp-session)
- [**SCMExec with SharpMove**](psexec-and-winexec.md#scmexec-with-sharpmove)
- [**SCCM / MECM client execution**](../active-directory-methodology/sccm-management-point-relay-sql-policy-secrets.md#7-sccm-client-execution-for-lateral-movement)
- **Pass the cookie** (क्लाउड)<sup>[[1]](#references)</sup>
- **Pass the PRT** (क्लाउड)<sup>[[2]](#references)</sup>
- **Pass the Microsoft Entra ID certificate** (क्लाउड)<sup>[[3]](#references)</sup>

## References

- [1] [HackTricks Cloud - Pass the cookie](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/az-pass-the-cookie.html)
- [2] [HackTricks Cloud - Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html)
- [3] [HackTricks Cloud - Pass the certificate](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/az-pass-the-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
