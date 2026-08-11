# Lateral Movement

{{#include ../../banners/hacktricks-training.md}}

Windows supports several mechanisms that can be used to execute commands on remote systems. The following pages explain common lateral-movement techniques and their prerequisites:

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

- [1] [HackTricks Cloud - Pass the cookie](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/az-pass-the-cookie.html)
- [2] [HackTricks Cloud - Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html)
- [3] [HackTricks Cloud - Pass the certificate](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/az-pass-the-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
