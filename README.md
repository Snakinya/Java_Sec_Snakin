# Java_Sec_Snakin

跟随y4脚步学习java

## 0x00 基础笔记
学习参考各大师傅博客，这里记个笔记，侵删
- [反射](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x00%20%E5%9F%BA%E7%A1%80%E7%AC%94%E8%AE%B0/%E5%8F%8D%E5%B0%84.md)
- [反序列化](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x00%20%E5%9F%BA%E7%A1%80%E7%AC%94%E8%AE%B0/%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96.md)
- [代理](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x00%20%E5%9F%BA%E7%A1%80%E7%AC%94%E8%AE%B0/%E4%BB%A3%E7%90%86.md)
- [类加载器](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x00%20%E5%9F%BA%E7%A1%80%E7%AC%94%E8%AE%B0/%E7%B1%BB%E5%8A%A0%E8%BD%BD%E5%99%A8.md)
- [Java类字节码编辑](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x00%20%E5%9F%BA%E7%A1%80%E7%AC%94%E8%AE%B0/Java%E7%B1%BB%E5%AD%97%E8%8A%82%E7%A0%81%E7%BC%96%E8%BE%91.md)
- [Java动态加载字节码](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x00%20%E5%9F%BA%E7%A1%80%E7%AC%94%E8%AE%B0/Java%E5%8A%A8%E6%80%81%E5%8A%A0%E8%BD%BD%E5%AD%97%E8%8A%82%E7%A0%81.md)
- [JDBC基础](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x00%20%E5%9F%BA%E7%A1%80%E7%AC%94%E8%AE%B0/JDBC%E5%9F%BA%E7%A1%80.md)
- [RMI基础](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x00%20%E5%9F%BA%E7%A1%80%E7%AC%94%E8%AE%B0/RMI%E5%9F%BA%E7%A1%80.md)
- [JNDI注入基础](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x00%20%E5%9F%BA%E7%A1%80%E7%AC%94%E8%AE%B0/JNDI%E6%B3%A8%E5%85%A5%E5%9F%BA%E7%A1%80.md)
- [JNDI高版本绕过](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x00%20%E5%9F%BA%E7%A1%80%E7%AC%94%E8%AE%B0/JNDI%E9%AB%98%E7%89%88%E6%9C%AC%E7%BB%95%E8%BF%87.md)

## 0x01 反序列化
- [01 URLDNS](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x01%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/01%20URLDNS.md)
- [02 CommonsCollections_前置](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x01%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/02%20CommonsCollections_%E5%89%8D%E7%BD%AE.md)
- [03 CommonsCollections_1(上)](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x01%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/03%20CommonsCollections_1(%E4%B8%8A).md)
- [04 CommonsCollections_1(下)](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x01%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/04%20CommonsCollections_1(%E4%B8%8B).md)
- [05 CommonsCollections_2](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x01%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/05%20CommonsCollections_2.md)
- [06 CommonsCollections_3](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x01%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/06%20CommonsCollections_3.md)
- [07 CommonsCollections_4](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x01%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/07%20CommonsCollections_4.md)
- [08 CommonsCollections_5](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x01%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/08%20CommonsCollections_5.md)
- [09 CommonsCollections_6_HashMap](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x01%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/09%20CommonsCollections_6_HashMap.md)
- [10 CommonsCollections_6_HashSet](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x01%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/10%20CommonsCollections_6_HashSet.md)
- [11 CommonsCollections_7](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x01%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/11%20CommonsCollections_7.md)
- [12 CC链学习总结](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x01%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/12%20CC%E9%93%BE%E5%AD%A6%E4%B9%A0%E6%80%BB%E7%BB%93.md)
- [ROME1.0反序列化](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x01%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/ROME1.0%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96.md)
- [Snakeyaml反序列化](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x01%20%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96/Snakeyaml%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96.md)
## 0x02 Fastjson
- [01 Fastjson基础](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x02%20Fastjson/01%20Fastjson%E5%9F%BA%E7%A1%80.md)
- [02 Fastjson反序列化漏洞原理](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x02%20Fastjson/02%20Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%8E%9F%E7%90%86.md)
- [03 FastJason 1.2.22-1.2.24 TemplatesImpl利用链分析.md](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x02%20Fastjson/03%20FastJason%201.2.22-1.2.24%20TemplatesImpl%E5%88%A9%E7%94%A8%E9%93%BE%E5%88%86%E6%9E%90.md)
- [04 FastJason 1.2.22-1.2.24 JdbcRowSetImpl利用链分析](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x02%20Fastjson/04%20FastJason%201.2.22-1.2.24%20JdbcRowSetImpl%E5%88%A9%E7%94%A8%E9%93%BE%E5%88%86%E6%9E%90.md)
- [05 Fastjson 1.2.25-1.2.48 补丁绕过分析](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x02%20Fastjson/05%20Fastjson%201.2.25-1.2.48%20%E8%A1%A5%E4%B8%81%E7%BB%95%E8%BF%87%E5%88%86%E6%9E%90.md)

## 0x03 内存马
- [00 内存马基础](https://github.com/Snakinya/Java_Sec_Snakin/blob/main/0x03%20%E5%86%85%E5%AD%98%E9%A9%AC/00%20%E5%86%85%E5%AD%98%E9%A9%AC%E5%9F%BA%E7%A1%80.md)
