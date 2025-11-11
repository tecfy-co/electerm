const { dbAction } = require('./db')
const defaultSetting = require('../common/config-default')
const getPort = require('./get-port')
const { userConfigId } = require('../common/constants')
const generate = require('../common/uid')
const globalState = require('./glob-state')
const { getAuthState, verifySessionToken } = require('./auth')

exports.getConfig = async (inited) => {
  const userConfig = await dbAction('data', 'findOne', {
    _id: userConfigId
  }) || {}
  const authState = await getAuthState()
  let sessionToken = ''
  let currentUser = null
  let permissions = {
    allowAll: true,
    categoryIds: [],
    bookmarkIds: []
  }
  const activeSession = globalState.get('activeSession')
  if (activeSession && activeSession.token) {
    const verified = await verifySessionToken(activeSession.token).catch(() => null)
    if (verified) {
      sessionToken = verified.session.token
      currentUser = verified.user
      permissions = verified.permissions
      globalState.set('activeSession', verified.session)
      globalState.set('activeUser', verified.user)
    } else {
      globalState.set('activeSession', null)
      globalState.set('activeUser', null)
    }
  }
  delete userConfig._id
  delete userConfig.host
  delete userConfig.terminalTypes
  delete userConfig.tokenElecterm
  delete userConfig.hashedPassword
  delete userConfig.salt
  const port = inited
    ? globalState.get('config').port
    : await getPort()
  const config = {
    ...defaultSetting,
    ...userConfig,
    requireAuth: authState.requireAuth,
    authState,
    sessionToken,
    currentUser,
    permissions,
    port,
    tokenElecterm: inited ? globalState.get('config').tokenElecterm : generate()
  }
  return {
    userConfig,
    config
  }
}

exports.getDbConfig = async () => {
  const userConfig = await dbAction('data', 'findOne', {
    _id: userConfigId
  }) || {}
  return userConfig
}
