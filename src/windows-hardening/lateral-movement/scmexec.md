# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## SCM

**SCMExec** एक तकनीक है जो Service Control Manager (SCM) का उपयोग करके दूरस्थ सिस्टम पर कमांड निष्पादित करने के लिए एक सेवा बनाने के लिए कमांड चलाती है। यह विधि कुछ सुरक्षा नियंत्रणों, जैसे User Account Control (UAC) और Windows Defender को बायपास कर सकती है।

## Tools

- [**https://github.com/0xthirteen/SharpMove**](https://github.com/0xthirteen/SharpMove):

SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true

{{#include ../../banners/hacktricks-training.md}}
