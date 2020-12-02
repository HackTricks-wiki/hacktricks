# APK decompilers

### [JD-Gui](https://github.com/java-decompiler/jd-gui)

First famous gui Java decompiler, you could use it to investigate the Java code from the APK once you have obtained it.

### [Jadx](https://github.com/skylot/jadx)

Buildin Java \(multi-platform\)and at this moment I think it's the recommended one.  
Just **download** the **latest** version and execute it from the _**bin**_ folder:

```text
jadx-gui
```

Using the GUI you can perform **text search**, go to the **functions definitions** \(_CTRL + left click_ on the function\) and cross refs \(_right click_ --&gt; _Find Usage_\)

If you **only want** the **java code** but without using a GUI a very easy way is to use the jadx cli tool:

```text
jadx app.apk
```

Some **interesting options of jadx** \(GUI and CLI versions\) are:

```text
-d <path to output dir>
--no-res #No resources
--no-src #No source code
--no-imports #Always write entire package name (very useful to know where is the function that you might want to hook)
```

### [GDA-android-reversing-Tool](https://github.com/charles2gan/GDA-android-reversing-Tool)

GDA is also a powerful and fast reverse analysis platform. Which does not only supports the basic decompiling operation, but also many excellent functions like **Malicious behavior detection, Privacy leaking detection, Vulnerability detection, Path solving, Packer identification, Variable tracking analysis, Deobfuscation, Python& Java scripts, Device memory extraction, Data decryption and encryption** etc**.**

**Only for Windows.**

![](../../.gitbook/assets/image%20%28207%29%20%281%29.png)

### [Bytecode-Viewer](https://github.com/Konloch/bytecode-viewer/releases)

Another **interesting tool to make a Static analysis is**: [**bytecode-viewer**](https://github.com/Konloch/bytecode-viewer/releases)**.** It allows you to decompile the APK using **several decompilers at the same time**. Then, you can see for example, 2 different Java decompilers and one Smali decompiler. It allows you also to **modify** the code:

![](../../.gitbook/assets/image%20%28265%29.png)

If you modify the code, then you can **export it**.  
One bad thing of bytecode-viewer is that it **doesn't have references** or **cross-references.**

