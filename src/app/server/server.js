const express = require('express')
const globalState = require('./global-state')
const app = express()
const log = require('../common/log')
const { initWs } = require('./dispatch-center')
const {
  isDev
} = require('../common/runtime-constants')
const initFileServer = require('../lib/file-server')
const appDec = require('./app-wrap')
const { tokenElecterm } = process.env

function isSessionExpired (session) {
  if (!session || !session.expiresAt) {
    return false
  }
  return Number(session.expiresAt) <= Date.now()
}

function extractSessionToken (req) {
  return req.headers['x-electerm-session'] ||
    req.query.sessionToken ||
    req.headers['session-token']
}

appDec(app)
app.post('/auth/sessions', function (req, res) {
  const headerToken = req.headers.token
  if (!tokenElecterm || headerToken !== tokenElecterm) {
    return res.status(403).json({ error: 'forbidden' })
  }
  const { sessions = [] } = req.body || {}
  globalState.replaceSessions(Array.isArray(sessions) ? sessions : [])
  globalState.authed = sessions.length > 0
  res.json({
    ok: true,
    count: Array.isArray(sessions) ? sessions.length : 0
  })
})

app.post('/auth/session/validate', function (req, res) {
  const headerToken = req.headers.token
  if (!tokenElecterm || headerToken !== tokenElecterm) {
    return res.status(403).json({ error: 'forbidden' })
  }
  const { sessionToken } = req.body || {}
  if (!sessionToken) {
    return res.status(400).json({ error: 'session token required' })
  }
  const session = globalState.getSession(sessionToken)
  if (!session || isSessionExpired(session)) {
    globalState.removeSession(sessionToken)
    return res.status(401).json({ error: 'session invalid' })
  }
  res.json({
    ok: true,
    session: {
      token: session.token,
      userId: session.userId,
      role: session.role,
      permissions: session.permissions,
      expiresAt: session.expiresAt
    }
  })
})

app.use((req, res, next) => {
  if (process.env.requireAuth !== 'yes') {
    return next()
  }
  const skipPaths = ['/auth/sessions', '/auth/session/validate']
  if (skipPaths.includes(req.path)) {
    return next()
  }
  const sessionToken = extractSessionToken(req)
  if (!sessionToken) {
    return res.status(401).json({ error: 'session token required' })
  }
  const session = globalState.getSession(sessionToken)
  if (!session || isSessionExpired(session)) {
    globalState.removeSession(sessionToken)
    return res.status(401).json({ error: 'session invalid' })
  }
  req.session = session
  next()
})

app.get('/run', function (req, res) {
  res.send('ok')
})
if (!isDev) {
  initFileServer(app)
}
initWs(app)

const runServer = function () {
  const { electermPort, electermHost } = process.env
  app.listen(electermPort, electermHost, () => {
    log.info('server', 'runs on', electermHost, electermPort)
    process.send({ serverInited: true })
  })
}

// start
runServer()

process.on('uncaughtException', (err) => {
  log.error('uncaughtException', err)
})
process.on('unhandledRejection', (err) => {
  log.error('unhandledRejection', err)
})

process.on('SIGTERM', () => {
  process.exit(0)
})
