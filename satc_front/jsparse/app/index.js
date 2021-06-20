const Koa = require('koa')
const koaBody = require('koa-body')
const error = require('koa-json-error')
const app = new Koa()
const routing = require('./routes')

app.use(error({
  postFormat: (e, { stack, ...rest }) => process.env.NODE_ENV === 'production' ? rest : { stack, ...rest }
}))

app.use(koaBody())

routing(app)

app.listen(3000, () => console.log('server is successful this port is 3000'))