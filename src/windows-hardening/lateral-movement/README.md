# Lateral Movement

{{#include ../../banners/hacktricks-training.md}}

Windowsでは、リモートシステム上でコマンドを実行するために、いくつかの仕組みを利用できます。以下のページでは、一般的なlateral-movementテクニックと、その前提条件について説明します。

- [**PsExec / SCMサービス実行**](psexec-and-winexec.md#how-do-they-work)
- [**SmbExec**](psexec-and-winexec.md#impacket-smbexecpy-smbexec)
- [**WmiExec**](wmiexec.md)
- [**AtExec / SchtasksExec**](atexec.md)
- [**WinRM**](winrm.md)
- [**DCOM Exec**](dcomexec.md)
- [**RDPexec: 認証済みRDPコマンド実行**](../../network-services-pentesting/pentesting-rdp.md#remote-command-execution-with-an-authenticated-rdp-session)
- [**SharpMoveを使ったSCMExec**](psexec-and-winexec.md#scmexec-with-sharpmove)
- [**SCCM / MECMクライアント実行**](../active-directory-methodology/sccm-management-point-relay-sql-policy-secrets.md#7-sccm-client-execution-for-lateral-movement)
- **Pass the cookie**（クラウド）<sup>[[1]](#references)</sup>
- **Pass the PRT**（クラウド）<sup>[[2]](#references)</sup>
- **Pass the Microsoft Entra ID certificate**（クラウド）<sup>[[3]](#references)</sup>

## References

- [1] [HackTricks Cloud - Pass the cookie](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/az-pass-the-cookie.html)
- [2] [HackTricks Cloud - Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html)
- [3] [HackTricks Cloud - Pass the certificate](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/az-pass-the-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
