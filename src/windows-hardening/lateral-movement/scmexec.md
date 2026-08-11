# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## 仕組み

Service Control Manager Remote Protocol（SCMR）は、リモートコンピューター上の Windows サービスを構成および制御するための RPC ベースのプロトコルです。十分な権限があれば、オペレーターはバイナリパスにコマンドを含むサービスを作成または再構成し、そのサービスを開始してコマンドをリモートで実行できます。<sup>[[1]](#references)</sup>

## ツール

**SharpMove** は、SCM およびその他の複数の Windows メカニズムを介した認証済みのリモート実行をサポートします。以下の例では、SCM アクションを選択し、`WindowsDebug` という名前のサービスを作成して、リモートホスト上にすでに存在する payload を指定しています。<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Service Control Manager Remote Protocol overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
{{#include ../../banners/hacktricks-training.md}}
