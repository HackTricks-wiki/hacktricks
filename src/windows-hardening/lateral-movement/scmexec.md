# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## 仕組み

Service Control Manager Remote Protocol (SCMR) は、リモートコンピューター上の Windows services を構成および制御するための、RPC ベースの protocol です。十分な権限があれば、operator は binary path に command を含む service を作成または再構成し、その service を開始してリモートで command を実行できます。<sup>[[1]](#references)</sup>

service account が指定されていない場合、`CreateService` は広範なローカル権限を持つ `LocalSystem` を使用します。これが、SCM 実行に成功した場合の影響が大きい理由です。SCM 実行によって UAC や Microsoft Defender が本質的に無効化されるわけではありません。caller には引き続きリモート SCM 権限が必要であり、endpoint controls によって service または payload が検査またはブロックされる可能性があります。<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

## Tools

**SharpMove** は、SCM やその他の複数の Windows mechanisms を介した authenticated remote execution をサポートします。次の例では SCM action を選択し、`WindowsDebug` という名前の service を作成して、リモート host 上にすでに存在する payload をその service に指定します。<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Service Control Manager Remote Protocolの概要](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [3] [Microsoft Learn - LocalSystemアカウント](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [4] [Microsoft Learn - `CreateService`関数](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
