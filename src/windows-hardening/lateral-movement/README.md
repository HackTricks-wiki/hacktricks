# Movimento lateral

{{#include ../../banners/hacktricks-training.md}}

O Windows oferece vários mecanismos que podem ser usados para executar comandos em sistemas remotos. As páginas a seguir explicam técnicas comuns de lateral movement e seus pré-requisitos:

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

- [1] [HackTricks Cloud - Passar o cookie](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/az-pass-the-cookie.html)
- [2] [HackTricks Cloud - Passar o PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html)
- [3] [HackTricks Cloud - Passar o certificado](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/az-pass-the-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
