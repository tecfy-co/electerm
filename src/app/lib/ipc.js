/**
 * ipc main
 */

const {
  ipcMain,
  app,
  BrowserWindow,
  dialog,
  powerMonitor,
  globalShortcut,
  shell
} = require('electron')
const globalState = require('./glob-state')
const ipcSyncFuncs = require('./ipc-sync')
const { dbAction } = require('./db')
const { listItermThemes } = require('./iterm-theme')
const installSrc = require('./install-src')
const { getConfig } = require('./get-config')
const loadSshConfig = require('./ssh-config')
const {
  checkMigrate,
  migrate
} = require('../migrate/migrate-1-to-2')
const {
  login,
  logout,
  initializeAdminPassword,
  updateUserPassword,
  createUser,
  removeUser,
  listAllUsers,
  updateUserRole,
  getUserPermissions,
  setUserPermissions,
  verifySessionToken,
  getAuthState
} = require('./auth')
const initServer = require('./init-server')
const {
  getLang,
  loadLocales
} = require('./locales')
const { saveUserConfig } = require('./user-config-controller')
const { changeHotkeyReg, initShortCut } = require('./shortcut')
const lastStateManager = require('./last-state')
// const { registerDeepLink } = require('./deep-link')
const {
  packInfo,
  appPath,
  isMac,
  exePath,
  isPortable,
  sshKeysPath
} = require('../common/app-props')
const {
  getScreenSize,
  maximize,
  unmaximize
} = require('./window-control')
const { loadFontList } = require('./font-list')
const { checkDbUpgrade, doUpgrade } = require('../upgrade')
const { listSerialPorts } = require('./serial-port')
const initApp = require('./init-app')
const { encryptAsync, decryptAsync } = require('./enc')
const { initCommandLine } = require('./command-line')
const { watchFile, unwatchFile } = require('./watch-file')
const lookup = require('../common/lookup')
const { AIchat, getStreamContent } = require('./ai')
const { USER_ROLES } = require('../common/user-roles')
const {
  filterGroupsResult,
  filterBookmarksResult
} = require('./permissions')

async function initAppServer () {
  const {
    config
  } = await getConfig(globalState.get('serverInited'))
  const {
    langs,
    sysLocale
  } = await loadLocales()
  const language = getLang(config, sysLocale, langs)
  config.language = language
  if (!globalState.get('serverInited')) {
    const child = await initServer(config, {
      ...process.env,
      appPath,
      sshKeysPath
    }, sysLocale)
    child.on('message', (m) => {
      if (m && m.showFileInFolder) {
        if (!isMac) {
          shell.showItemInFolder(m.showFileInFolder)
        }
      }
    })
    globalState.set('serverInited', true)
  }
  globalState.set('config', config)
}

async function ensureSession (token) {
  const sessionInfo = await verifySessionToken(token)
  if (!sessionInfo) {
    throw new Error('Session expired')
  }
  return sessionInfo
}

async function ensureAdminSession (token) {
  const sessionInfo = await ensureSession(token)
  if (sessionInfo.user.role !== USER_ROLES.ADMIN) {
    throw new Error('Admin privileges required')
  }
  return sessionInfo
}

async function securedDbAction (token, dbName, op, ...args) {
  const sessionInfo = await ensureSession(token)
  const { user, permissions } = sessionInfo
  if (user.role === USER_ROLES.ADMIN) {
    return dbAction(dbName, op, ...args)
  }
  if (new Set(['users', 'userPermissions']).has(dbName)) {
    throw new Error('Insufficient permissions')
  }
  if (!['find', 'findOne'].includes(op)) {
    throw new Error('Insufficient permissions')
  }
  if (dbName === 'bookmarks') {
    const bookmarks = await dbAction(dbName, op, ...args)
    const groups = await dbAction('bookmarkGroups', 'find', {})
    return filterBookmarksResult(bookmarks, permissions, groups)
  }
  if (dbName === 'bookmarkGroups') {
    const groups = await dbAction('bookmarkGroups', 'find', {})
    if (op === 'find') {
      return filterGroupsResult(groups, permissions, groups)
    }
    const group = await dbAction(dbName, op, ...args)
    return filterGroupsResult(group, permissions, groups)
  }
  return dbAction(dbName, op, ...args)
}

function initIpc () {
  powerMonitor.on('resume', () => {
    globalState.get('win').webContents.send('power-resume', null)
  })
  async function init () {
    const {
      langs,
      langMap
    } = await loadLocales()
    const config = globalState.get('config')
    const globs = {
      config,
      langs,
      langMap,
      installSrc,
      appPath,
      exePath,
      isPortable
    }
    initApp(langMap, config)
    initShortCut(globalShortcut, globalState.get('win'), config)
    return globs
  }

  ipcMain.on('sync-func', (event, { name, args }) => {
    event.returnValue = ipcSyncFuncs[name](...args)
  })
  const asyncGlobals = {
    confirmExit: () => {
      globalState.set('confirmExit', true)
    },
    authLogin: login,
    authLogout: async (token) => logout(token),
    authGetState: getAuthState,
    authInitializeAdminPassword: initializeAdminPassword,
    authListUsers: async (token) => {
      await ensureAdminSession(token)
      return listAllUsers()
    },
    authCreateUser: async (token, payload) => {
      await ensureAdminSession(token)
      return createUser(payload || {})
    },
    authUpdateUserPassword: async (token, userId, password, options = {}) => {
      await ensureAdminSession(token)
      return updateUserPassword(userId, password, options)
    },
    authUpdateUserRole: async (token, userId, role) => {
      await ensureAdminSession(token)
      return updateUserRole(userId, role)
    },
    authRemoveUser: async (token, userId) => {
      await ensureAdminSession(token)
      return removeUser(userId)
    },
    authGetPermissions: async (token, userId) => {
      const { user } = await ensureAdminSession(token)
      if (userId === user._id) {
        throw new Error('Use settings to manage your own permissions')
      }
      return getUserPermissions(userId)
    },
    authSetPermissions: async (token, userId, permissions) => {
      await ensureAdminSession(token)
      return setUserPermissions(userId, permissions || {})
    },
    authVerifySession: ensureSession,
    lookup,
    loadSshConfig,
    init,
    listSerialPorts,
    loadFontList,
    doUpgrade,
    checkDbUpgrade,
    checkMigrate,
    migrate,
    getExitStatus: () => globalState.get('exitStatus'),
    setExitStatus: (status) => {
      globalState.set('exitStatus', status)
    },
    encryptAsync,
    decryptAsync,
    dbAction: securedDbAction,
    getScreenSize,
    closeApp: (closeAction = '') => {
      globalState.set('closeAction', closeAction)
      const win = globalState.get('win')
      win && win.close()
    },
    exit: () => {
      const win = globalState.get('win')
      win && win.close()
    },
    restart: (closeAction = '') => {
      globalState.set('closeAction', '')
      globalState.get('win').close()
      app.relaunch()
    },
    setCloseAction: (closeAction = '') => {
      globalState.set('closeAction', closeAction)
    },
    minimize: () => {
      globalState.get('win').minimize()
    },
    listItermThemes,
    maximize,
    unmaximize,
    openDevTools: () => {
      globalState.get('win').webContents.openDevTools()
    },
    setWindowSize: (update) => {
      lastStateManager.set('windowSize', update)
    },
    saveUserConfig,
    AIchat,
    getStreamContent,
    setTitle: (title) => {
      const win = globalState.get('win')
      win && win.setTitle(packInfo.name + ' - ' + title)
    },
    setBackgroundColor: (color = '#33333300') => {
      const win = globalState.get('win')
      win && win.setBackgroundColor(color)
    },
    changeHotkey: changeHotkeyReg(globalShortcut, globalState.get('win')),
    initCommandLine,
    watchFile,
    unwatchFile
  }
  ipcMain.handle('async', (event, { name, args }) => {
    return asyncGlobals[name](...args)
  })
  ipcMain.handle('show-open-dialog-sync', async (event, ...args) => {
    const win = BrowserWindow.fromWebContents(event.sender)
    return dialog.showOpenDialogSync(win, ...args)
  })
}

exports.initIpc = initIpc
exports.initAppServer = initAppServer
