# Laterale Bewegung

{{#include ../../banners/hacktricks-training.md}}

Windows unterstützt mehrere Mechanismen, mit denen Befehle auf Remotesystemen ausgeführt werden können. Auf den folgenden Seiten werden gängige Techniken für laterale Bewegung und ihre Voraussetzungen erläutert:

- [**PsExec / SCM service execution**](psexec-and-winexec.md#how-do-they-work)
- [**SmbExec**](psexec-and-winexec.md#impacket-smbexecpy-smbexec)
- [**WmiExec**](wmiexec.md)
- [**AtExec / SchtasksExec**](atexec.md)
- [**WinRM**](winrm.md)
- [**DCOM Exec**](dcomexec.md)
- [**RDPexec**](rdpexec.md)
- [**SCMExec with SharpMove**](psexec-and-winexec.md#scmexec-with-sharpmove)
- [**SCCM / MECM client execution**](../active-directory-methodology/sccm-management-point-relay-sql-policy-secrets.md#7-sccm-client-execution-for-lateral-movement)
- **Pass the cookie** (Cloud)<sup>[[1]](#references)</sup>
- **Pass the PRT** (Cloud)<sup>[[2]](#references)</sup>
- **Pass the Microsoft Entra ID certificate** (Cloud)<sup>[[3]](#references)</sup>

## References

- [1] [HackTricks Cloud - Pass the cookie](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/az-pass-the-cookie.html)
- [2] [HackTricks Cloud - Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html)
- [3] [HackTricks Cloud - Pass the certificate](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/az-pass-the-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
