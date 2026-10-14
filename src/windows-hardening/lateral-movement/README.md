# 횡적 이동

{{#include ../../banners/hacktricks-training.md}}

Windows는 원격 시스템에서 명령을 실행하는 데 사용할 수 있는 여러 메커니즘을 지원합니다. 다음 페이지에서는 일반적인 횡적 이동 기법과 사전 요구 사항을 설명합니다.

- [**PsExec / SCM service execution**](psexec-and-winexec.md#how-do-they-work)
- [**SmbExec**](psexec-and-winexec.md#impacket-smbexecpy-smbexec)
- [**WmiExec**](wmiexec.md)
- [**AtExec / SchtasksExec**](atexec.md)
- [**WinRM**](winrm.md)
- [**DCOM Exec**](dcomexec.md)
- [**RDPexec**](rdpexec.md)
- [**SCMExec with SharpMove**](psexec-and-winexec.md#scmexec-with-sharpmove)
- [**SCCM / MECM client execution**](../active-directory-methodology/sccm-management-point-relay-sql-policy-secrets.md#7-sccm-client-execution-for-lateral-movement)
- **Pass the cookie** (cloud)<sup>[[1]](#references)</sup>
- **Pass the PRT** (cloud)<sup>[[2]](#references)</sup>
- **Pass the Microsoft Entra ID certificate** (cloud)<sup>[[3]](#references)</sup>

## References

- [1] [HackTricks Cloud - Pass the cookie](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/az-pass-the-cookie.html)
- [2] [HackTricks Cloud - Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html)
- [3] [HackTricks Cloud - Pass the certificate](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/az-pass-the-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
