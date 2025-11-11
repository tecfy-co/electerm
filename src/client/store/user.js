import { message } from 'antd'
import deepCopy from 'json-deep-copy'
import { USER_ROLES } from '../common/user-roles'

function ensureAdmin (store) {
  if (!store.isAdminUser) {
    throw new Error('Admin privileges required')
  }
}

function ensureSessionToken () {
  return window.store.sessionToken || window.pre.sessionToken || ''
}

function normalizePermissions (permissions = {}) {
  return {
    allowAll: !!permissions.allowAll,
    categoryIds: Array.isArray(permissions.categoryIds) ? permissions.categoryIds : [],
    bookmarkIds: Array.isArray(permissions.bookmarkIds) ? permissions.bookmarkIds : []
  }
}

export default Store => {
  Store.prototype.loadUsers = async function () {
    const { store } = window
    if (!store.isAdminUser) {
      return []
    }
    ensureAdmin(store)
    const token = ensureSessionToken()
    if (!token) {
      throw new Error('Session expired. Please sign in again.')
    }
    store.usersLoading = true
    try {
      const users = await window.pre.runGlobalAsync('authListUsers', token)
      store.users = Array.isArray(users) ? users : []
      return store.users
    } catch (err) {
      store.onError(err)
      return []
    } finally {
      store.usersLoading = false
    }
  }

  Store.prototype.createUserAccount = async function (payload) {
    const { store } = window
    ensureAdmin(store)
    const token = ensureSessionToken()
    if (!token) {
      throw new Error('Session expired. Please sign in again.')
    }
    const body = {
      username: payload.username?.trim(),
      password: payload.password || '',
      role: payload.role || USER_ROLES.SESSION,
      mustResetPassword: payload.mustResetPassword === true
    }
    try {
      await window.pre.runGlobalAsync('authCreateUser', token, body)
      message.success('User created')
      await store.loadUsers()
    } catch (err) {
      store.onError(err)
      throw err
    }
  }

  Store.prototype.updateUserRole = async function (userId, role) {
    const { store } = window
    ensureAdmin(store)
    if (!userId) {
      throw new Error('User id required')
    }
    if (![USER_ROLES.ADMIN, USER_ROLES.SESSION].includes(role)) {
      throw new Error('Invalid role')
    }
    const token = ensureSessionToken()
    if (!token) {
      throw new Error('Session expired. Please sign in again.')
    }
    try {
      const target = store.users.find(user => (user._id === userId || user.id === userId))
      if (target && target.username === 'admin' && target.role === USER_ROLES.ADMIN && role !== USER_ROLES.ADMIN) {
        throw new Error('Primary admin role cannot be changed')
      }
      await window.pre.runGlobalAsync('authUpdateUserRole', token, userId, role)
      message.success('Role updated')
      await store.loadUsers()
    } catch (err) {
      store.onError(err)
      throw err
    }
  }

  Store.prototype.updateUserPassword = async function (userId, password, options = {}) {
    const { store } = window
    ensureAdmin(store)
    if (!userId) {
      throw new Error('User id required')
    }
    const token = ensureSessionToken()
    if (!token) {
      throw new Error('Session expired. Please sign in again.')
    }
    try {
      await window.pre.runGlobalAsync('authUpdateUserPassword', token, userId, password, options)
      message.success('Password updated')
      await store.loadUsers()
    } catch (err) {
      store.onError(err)
      throw err
    }
  }

  Store.prototype.removeUserAccount = async function (userId) {
    const { store } = window
    ensureAdmin(store)
    if (!userId) {
      return
    }
    const token = ensureSessionToken()
    if (!token) {
      throw new Error('Session expired. Please sign in again.')
    }
    try {
      const existing = store.users.find(user => user._id === userId || user.id === userId)
      if (existing && existing.role === USER_ROLES.ADMIN) {
        throw new Error('Cannot remove admin account')
      }
      await window.pre.runGlobalAsync('authRemoveUser', token, userId)
      message.success('User removed')
      store.userPermissionsCache.delete(userId)
      await store.loadUsers()
    } catch (err) {
      store.onError(err)
      throw err
    }
  }

  Store.prototype.fetchUserPermissions = async function (userId, { force = false } = {}) {
    const { store } = window
    ensureAdmin(store)
    if (!userId) {
      throw new Error('User id required')
    }
    if (!force && store.userPermissionsCache.has(userId)) {
      return deepCopy(store.userPermissionsCache.get(userId))
    }
    const token = ensureSessionToken()
    if (!token) {
      throw new Error('Session expired. Please sign in again.')
    }
    store.userPermissionsLoading = userId
    try {
      const permissions = await window.pre.runGlobalAsync('authGetPermissions', token, userId)
      const normalized = normalizePermissions(permissions)
      store.userPermissionsCache.set(userId, normalized)
      return deepCopy(normalized)
    } catch (err) {
      store.onError(err)
      throw err
    } finally {
      store.userPermissionsLoading = ''
    }
  }

  Store.prototype.saveUserPermissions = async function (userId, permissions) {
    const { store } = window
    ensureAdmin(store)
    if (!userId) {
      throw new Error('User id required')
    }
    const token = ensureSessionToken()
    if (!token) {
      throw new Error('Session expired. Please sign in again.')
    }
    const payload = normalizePermissions(permissions)
    try {
      const saved = await window.pre.runGlobalAsync('authSetPermissions', token, userId, payload)
      const normalized = normalizePermissions(saved)
      store.userPermissionsCache.set(userId, normalized)
      message.success('Permissions updated')
      return deepCopy(normalized)
    } catch (err) {
      store.onError(err)
      throw err
    }
  }
}

