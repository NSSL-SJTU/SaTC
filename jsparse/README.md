# JsParse

用于支持front_analysise项目的JS解析

## 具体需求

1. 提供WEB接口:

   接口API: `/codeparse`


   入参:

   | 字段   | 类型    | 描述             | 例如    |
   | ------ | ------- | ---------------- | ------- |
   | engine | string  | 用于解析JS的引擎 | "acorn" |
   | code   | strings | 需要解析的JS代码 | ......  |

   返回:

   | 字段 | 类型   | 描述     | 例如 | 备注                          |
   | ---- | ------ | -------- | ---- | ----------------------------- |
   | code | int    | 状态码   | 200  | 200正常解析，500解析异常      |
   | time | string | 解析时间 | 100s | 单位为秒                      |
   | data | json   | 解析结果 | ...  | 如果状态码为500，返回空字符串 |

2. 尽可能支持多引擎，两个引擎为必须的：`acorn`，`esprima`

#### 工具库:

这类库都是用与将JS解析成AST语法树的

1. [acorn](https://github.com/acornjs/acorn)

   ```javascript
   // 从readme摘录出来的，具体使用得看下英文文档，需要考虑的是怎么转换成JSON
   const {Parser} = require("acorn")
   
   const MyParser = Parser.extend(
     require("acorn-jsx")(),
     require("acorn-bigint")
   )
   console.log(MyParser.parse("这里写JS代码"))  // 不知道输出格式是什么，得看看怎么转换成JSON，参考AST explorer项目:https://github.com/fkling/astexplorer/blob/master/website/src/parsers/js/acorn.js
   ```

   

2. [esprima](https://github.com/jquery/esprima)

   ```javascript
   var esprima = require('esprima');
   var program = 'const answer = 42';
   
   // 执行：
   esprima.parseScript(program);
   
   // 这是上面的返回结果
   { type: 'Program',
     body:
      [ { type: 'VariableDeclaration',
          declarations: [Object],
          kind: 'const' } ],
     sourceType: 'script' }
   
    //这个生成的就是dict，应该直接转JSON就可以 也可以参考 AST exporer项目:https://github.com/fkling/astexplorer/blob/master/website/src/parsers/js/esprima.js
   ```

其他的库可以看下[AST explorer项目的web页面](https://astexplorer.net/)的`parser setting`设置，里面支持了15种不同的库




#### 参考2

项目网站: [AST explorer](https://astexplorer.net/)

源代码: [AST explorer的源代码地址](https://github.com/fkling/astexplorer)



## 项目启动

```shell
$ npm run start 
```

