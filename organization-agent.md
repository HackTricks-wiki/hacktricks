# HackTricks organization guide

## Organization principles

- Give a reusable mechanism one substantive home. Use short contextual links from service, platform, or tool entry points rather than another procedure.
- Prefer an existing chapter and a precise heading when variants share the mechanism and reader task. Keep a separate chapter when the transport, prerequisite, or task changes. Do not merge merely because a page is short.
- Main HackTricks owns general host/security techniques; HackTricks Cloud owns provider, service, and IAM-specific pivots. Cross-book links should use canonical public URLs.
- A removed Markdown chapter needs a whole-page mdBook redirect in `book.toml`; update current local links, but do not preserve historical URL fragments.

## Canonical locations and boundaries (this draft, contingent on merge)

- Windows remote service execution through SCM/SCMR—PsExec, WinExec/ScExec, SMBExec, and SCMExec—belongs in `src/windows-hardening/lateral-movement/psexec-and-winexec.md`. The SharpMove SCM example has its own `#scmexec-with-sharpmove` heading. These variants share remote service creation/start and local service rights; whether `ADMIN$` is needed depends on staging/output, so keep that distinction in the chapter. The former `scmexec.md` route redirects here.
- `src/network-services-pentesting/pentesting-smb/README.md` keeps SMB discovery and a short context link to the service-execution chapter, not a second PsExec/SMBExec procedure. `src/windows-hardening/ntlm/README.md` links directly to the Impacket PsExec examples for Pass-the-Hash.
- Keep Task Scheduler (`atexec.md`), DCOM (`dcomexec.md`), WMI (`wmiexec.md`), WinRM (`winrm.md`), and RDP (`rdpexec.md`) separate: their execution interfaces and prerequisites differ from SCM service creation. `lateral-movement/README.md` is a curated route map, not a duplicate technique chapter.
- Azure/Entra-to-AD pivots remain in Cloud's `pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/`; a cloud use of PsExec does not transfer general Windows SCM ownership there.

## Researcher lookup terms

- For a remote Windows host where service-creation rights, SMB/RPC, or an already staged executable are available, look under **Lateral Movement → Remote Service Execution**; search terms include SCM, SCMR, SCMExec, PsExec, SMBExec, WinExec, ScExec, `sc.exe`, and SharpMove.

## Revisit only with evidence

- Split the remote-service chapter only if a variant develops an independent reader task or prerequisites that make the shared flow misleading; code size alone is not a reason. Recheck repository paths, pending PR overlap, and cross-book ownership before using this guide in a later run.
