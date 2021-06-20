const {Parser} = require("acorn")
const acornJsx = require("acorn-jsx")()
const acornBigint = require("acorn-bigint")
const esprima = require('esprima')
class Codeparse {
    async jsparse(ctx) {
        const { engine, code } = ctx.request.body
        console.log('engine===>',engine)
        console.log('code===>',code)
        let data = null
        const start = new Date().getTime()
        console.log('startTime===>',start)
        if (engine === 'acorn') {
            const MyParser = Parser.extend(acornJsx, acornBigint)
            data = MyParser.parse(code)
        } else if (engine === 'esprima') {
            data = esprima.parseScript(code)
        } 
        const end = new Date().getTime()
        console.log('endTime===>',end)
        
        const time = end - start 
        
        ctx.body = {
            code: 200,
            time,
            data
        }
    }
}

module.exports = new Codeparse()