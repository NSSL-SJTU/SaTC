const Router = require('koa-router')
const router = new Router({ prefix: '/codeparse' })
const { jsparse } = require('../controllers/codeparse')

router.post('/', jsparse)

module.exports = router

