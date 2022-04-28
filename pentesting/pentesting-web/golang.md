# Golang

### CONNECT method

In golang, the library net/http usually transforms the path to a canonical one before accessing it:

* /flag/ -- Is responded with a redirect to /flag
* /../flag --- Is responded with a redirect to /flag
* /flag/. -- Is responded with a redirect to /flag

However, when the CONNECT method is used this doesn't happen. So, if you need to access some protected resource you can abuse this trick: 

```text
curl --path-as-is -X CONNECT http://gofs.web.jctf.pro/../flag
```

[https://github.com/golang/go/blob/9bb97ea047890e900dae04202a231685492c4b18/src/net/http/server.go\#L2354-L2364](https://github.com/golang/go/blob/9bb97ea047890e900dae04202a231685492c4b18/src/net/http/server.go#L2354-L2364)

