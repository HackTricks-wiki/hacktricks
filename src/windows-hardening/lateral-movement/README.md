# Lateral Movement

{{#include ../../banners/hacktricks-training.md}}

Windows는 원격 시스템에서 명령을 실행하는 데 사용할 수 있는 여러 메커니즘을 지원합니다. 다음 페이지에서 일반적인 lateral movement 기법과 필요한 사전 조건을 설명합니다.

- [**PsExec / SCM service execution**](psexec-and-winexec.md#how-do-they-work)
- [**SmbExec**](psexec-and-winexec.md#impacket-smbexecpy-smbexec)
- [**WmiExec**](wmiexec.md)
- [**AtExec / SchtasksExec**](atexec.md)
- [**WinRM**](winrm.md)
- [**DCOM Exec**](dcomexec.md)
- [**RDPexec: 인증된 RDP 명령 실행**](../../network-services-pentesting/pentesting-rdp.md#remote-command-execution-with-an-authenticated-rdp-session)
- [**SharpMove를 사용한 SCMExec**](psexec-and-winexec.md#scmexec-with-sharpmove)
- [**SCCM / MECM 클라이언트 실행**](../active-directory-methodology/sccm-management-point-relay-sql-policy-secrets.md#7-sccm-client-execution-for-lateral-movement)
- **Pass the cookie** (클라우드)<sup>[[1]](#references)</sup>
- **Pass the PRT** (클라우드)<sup>[[2]](#references)</sup>
- **Pass the Microsoft Entra ID certificate** (클라우드)<sup>[[3]](#references)</sup>

## References

- [1] [HackTricks Cloud - Pass the cookie](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/az-pass-the-cookie.html)
- [2] [HackTricks Cloud - Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html)
- [3] [HackTricks Cloud - Pass the certificate](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/az-pass-the-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
