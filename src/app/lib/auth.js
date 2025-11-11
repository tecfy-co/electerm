const crypto = require('crypto')
const axios = require('axios')
const log = require('../common/log')
const getPort = require('./get-port')
const globalState = require('./glob-state')
const uid = require('../common/uid')
const {
  USER_ROLES,
  ADMIN_USERNAME,
  DEFAULT_SESSION_EXPIRY_MINUTES
} = require('../common/user-roles')
const {
  ensureAdminSeeded,
  listUsers,
  findUserByUsername,
  findUserById,
  upsertUser,
  deleteUser,
  getPermissions,
  setPermissions,
  isAdmin
} = require('./user-store')
const sessionStore = require('./session-store')

axios.defaults.proxy = false

const MAX_FAILED_ATTEMPTS = 5
const LOCKOUT_MINUTES = 15
const PASSWORD_POLICY = Object.freeze({
  minLength: 12,
  requireUpper: true,
  requireLower: true,
  requireNumber: true,
  requireSpecial: true
})
const HASH_ITERATIONS = 150000
const HASH_LENGTH = 64
const HASH_DIGEST = 'sha512'

function nowMs () {
  return Date.now()
}

function toIso (date) {
  return new Date(date).toISOString()
}

function sanitizeUser (user) {
  if (!user) {
    return null
  }
  // eslint-disable-next-line no-unused-vars
  const {
    salt,
    hashedPassword,
    normalizedUsername,
    sessionVersion,
    ...rest
  } = user
  return rest
}

function validatePasswordStrength (password) {
  if (typeof password !== 'string') {
    throw new Error('Password must be a string')
  }
  if (password.length < PASSWORD_POLICY.minLength) {
    throw new Error(`Password must be at least ${PASSWORD_POLICY.minLength} characters`)
  }
  const checks = []
  if (PASSWORD_POLICY.requireUpper) {
    checks.push(/[A-Z]/.test(password))
  }
  if (PASSWORD_POLICY.requireLower) {
    checks.push(/[a-z]/.test(password))
  }
  if (PASSWORD_POLICY.requireNumber) {
    checks.push(/[0-9]/.test(password))
  }
  if (PASSWORD_POLICY.requireSpecial) {
    checks.push(/[^A-Za-z0-9]/.test(password))
  }
  if (checks.filter(Boolean).length < checks.length) {
    throw new Error('Password must include uppercase, lowercase, number, and special character')
  }
  return true
}

function hashPassword (password) {
  validatePasswordStrength(password)
  const salt = crypto.randomBytes(32).toString('hex')
  const hashedPassword = crypto
    .pbkdf2Sync(password, salt, HASH_ITERATIONS, HASH_LENGTH, HASH_DIGEST)
    .toString('hex')
  return { salt, hashedPassword }
}

function comparePasswords (password, salt, hashedPassword) {
  if (!salt || !hashedPassword) {
    return false
  }
  const derived = crypto
    .pbkdf2Sync(password, salt, HASH_ITERATIONS, HASH_LENGTH, HASH_DIGEST)
  const stored = Buffer.from(hashedPassword, 'hex')
  if (stored.length !== derived.length) {
    return false
  }
  return crypto.timingSafeEqual(stored, derived)
}

async function syncSessionsWithServer () {
  try {
    const port = await getPort()
    const sessions = sessionStore.listSessions()
    const token = globalState.get('config')?.tokenElecterm || process.env.tokenElecterm
    const options = token
      ? { headers: { token } }
      : {}
    await axios.post(`http://127.0.0.1:${port}/auth/sessions`, {
      sessions,
      ttlMinutes: DEFAULT_SESSION_EXPIRY_MINUTES
    }, options)
  } catch (err) {
    log.error('syncSessionsWithServer failed', err.message || err)
  }
}

async function resolvePermissions (user) {
  if (isAdmin(user)) {
    return {
      allowAll: true,
      categoryIds: [],
      bookmarkIds: []
    }
  }
  const record = await getPermissions(user._id)
  return {
    allowAll: !!record.allowAll,
    categoryIds: Array.isArray(record.categoryIds) ? record.categoryIds : [],
    bookmarkIds: Array.isArray(record.bookmarkIds) ? record.bookmarkIds : []
  }
}

async function recordFailedAttempt (user) {
  const failedAttempts = (user.failedAttempts || 0) + 1
  const lockedUntil = failedAttempts >= MAX_FAILED_ATTEMPTS
    ? toIso(nowMs() + LOCKOUT_MINUTES * 60 * 1000)
    : user.lockedUntil || null
  const updated = await upsertUser({
    ...user,
    failedAttempts,
    lockedUntil
  })
  return {
    failedAttempts: updated.failedAttempts,
    lockedUntil: updated.lockedUntil
  }
}

async function resetFailedAttempts (user) {
  if (!(user.failedAttempts || user.lockedUntil)) {
    return user
  }
  return upsertUser({
    ...user,
    failedAttempts: 0,
    lockedUntil: null
  })
}

async function refreshLastLogin (user) {
  return upsertUser({
    ...user,
    lastLoginAt: toIso(nowMs()),
    failedAttempts: 0,
    lockedUntil: null
  })
}

async function ensureNotLocked (user) {
  if (!user.lockedUntil) {
    return user
  }
  const lockedUntil = new Date(user.lockedUntil).getTime()
  if (lockedUntil > nowMs()) {
    const minutes = Math.ceil((lockedUntil - nowMs()) / 60000)
    throw new Error(`Account locked. Try again in ${minutes} minute(s).`)
  }
  if (user.failedAttempts || user.lockedUntil) {
    return upsertUser({
      ...user,
      failedAttempts: 0,
      lockedUntil: null
    })
  }
  return user
}

async function bootstrapAdminUser () {
  return ensureAdminSeeded()
}

async function login (username, password) {
  if (!username || !password) {
    throw new Error('Username and password required')
  }
  await bootstrapAdminUser()
  let user = await findUserByUsername(username)
  if (!user) {
    throw new Error('Invalid credentials')
  }
  user = await ensureNotLocked(user)
  if (!user.hashedPassword) {
    throw new Error('Password not set for this account')
  }
  const verified = comparePasswords(password, user.salt, user.hashedPassword)
  if (!verified) {
    const { failedAttempts, lockedUntil } = await recordFailedAttempt(user)
    const remaining = Math.max(0, MAX_FAILED_ATTEMPTS - failedAttempts)
    if (lockedUntil && new Date(lockedUntil).getTime() > nowMs()) {
      throw new Error('Account locked due to too many failed attempts')
    }
    throw new Error(remaining
      ? `Invalid credentials. ${remaining} attempt(s) remaining`
      : 'Invalid credentials')
  }
  const cleanUser = await refreshLastLogin(user)
  const permissions = await resolvePermissions(cleanUser)
  const session = sessionStore.createSession({
    userId: cleanUser._id,
    role: cleanUser.role,
    permissions,
    sessionVersion: cleanUser.sessionVersion
  })
  await syncSessionsWithServer()
  const sanitizedUser = sanitizeUser(cleanUser)
  globalState.set('activeSession', sessionStore.serializeSession(session))
  globalState.set('activeUser', sanitizedUser)
  return {
    user: sanitizedUser,
    sessionToken: session.token,
    expiresAt: session.expiresAt,
    permissions
  }
}

async function logout (token) {
  if (token) {
    sessionStore.invalidateSession(token)
  }
  globalState.set('activeSession', null)
  globalState.set('activeUser', null)
  await syncSessionsWithServer()
  return true
}

async function initializeAdminPassword (password) {
  await bootstrapAdminUser()
  const admin = await findUserByUsername(ADMIN_USERNAME)
  if (!admin) {
    throw new Error('Admin account missing')
  }
  if (admin.hashedPassword && !admin.mustResetPassword) {
    throw new Error('Admin password already configured')
  }
  const { salt, hashedPassword } = hashPassword(password)
  const updated = await upsertUser({
    ...admin,
    salt,
    hashedPassword,
    mustResetPassword: false,
    sessionVersion: uid()
  })
  sessionStore.invalidateUserSessions(updated._id)
  await syncSessionsWithServer()
  return sanitizeUser(updated)
}

async function updateUserPassword (userId, password, { mustResetPassword = false } = {}) {
  const user = await findUserById(userId)
  if (!user) {
    throw new Error('User not found')
  }
  const { salt, hashedPassword } = hashPassword(password)
  const updated = await upsertUser({
    ...user,
    salt,
    hashedPassword,
    mustResetPassword,
    sessionVersion: uid()
  })
  sessionStore.invalidateUserSessions(userId)
  await syncSessionsWithServer()
  return sanitizeUser(updated)
}

async function createUser ({ username, password, role = USER_ROLES.SESSION, mustResetPassword = false }) {
  if (!username) {
    throw new Error('Username required')
  }
  await bootstrapAdminUser()
  const existing = await findUserByUsername(username)
  if (existing) {
    throw new Error('Username already exists')
  }
  let salt = ''
  let hashedPassword = ''
  if (password) {
    const hashed = hashPassword(password)
    salt = hashed.salt
    hashedPassword = hashed.hashedPassword
  } else {
    mustResetPassword = true
  }
  const user = await upsertUser({
    username,
    role,
    salt,
    hashedPassword,
    mustResetPassword,
    sessionVersion: uid()
  })
  if (!isAdmin(user)) {
    await setPermissions(user._id, {
      allowAll: false,
      categoryIds: [],
      bookmarkIds: []
    })
  }
  return sanitizeUser(user)
}

async function removeUser (userId) {
  sessionStore.invalidateUserSessions(userId)
  const res = await deleteUser(userId)
  await syncSessionsWithServer()
  return res
}

async function listAllUsers () {
  await bootstrapAdminUser()
  const users = await listUsers()
  return users.map(sanitizeUser)
}

async function updateUserRole (userId, role) {
  const user = await findUserById(userId)
  if (!user) {
    throw new Error('User not found')
  }
  if (user.role === role) {
    return sanitizeUser(user)
  }
  const updated = await upsertUser({
    ...user,
    role,
    sessionVersion: uid()
  })
  sessionStore.invalidateUserSessions(userId)
  await syncSessionsWithServer()
  return sanitizeUser(updated)
}

async function getUserPermissions (userId) {
  const user = await findUserById(userId)
  if (!user) {
    throw new Error('User not found')
  }
  return resolvePermissions(user)
}

async function setUserPermissions (userId, permissions) {
  const user = await findUserById(userId)
  if (!user) {
    throw new Error('User not found')
  }
  if (isAdmin(user)) {
    throw new Error('Admin has full access and does not require explicit permissions')
  }
  const normalized = {
    allowAll: !!permissions.allowAll,
    categoryIds: Array.from(new Set(permissions.categoryIds || [])),
    bookmarkIds: Array.from(new Set(permissions.bookmarkIds || []))
  }
  const record = await setPermissions(userId, normalized)
  sessionStore.invalidateUserSessions(userId)
  await syncSessionsWithServer()
  return {
    allowAll: !!record.allowAll,
    categoryIds: normalized.categoryIds,
    bookmarkIds: normalized.bookmarkIds
  }
}

async function verifySessionToken (token) {
  if (!token) {
    return null
  }
  const session = sessionStore.validateSession(token)
  if (!session) {
    return null
  }
  const user = await findUserById(session.userId)
  if (!user) {
    sessionStore.invalidateSession(token)
    await syncSessionsWithServer()
    return null
  }
  if (user.sessionVersion && session.sessionVersion && user.sessionVersion !== session.sessionVersion) {
    sessionStore.invalidateSession(token)
    await syncSessionsWithServer()
    return null
  }
  const permissions = await resolvePermissions(user)
  return {
    user: sanitizeUser(user),
    permissions,
    session
  }
}

async function getAuthState () {
  const admin = await bootstrapAdminUser()
  const users = await listUsers()
  const needsAdminPasswordSetup = !admin.hashedPassword || admin.mustResetPassword
  return {
    requireAuth: users.length > 0,
    needsAdminPasswordSetup,
    passwordPolicy: PASSWORD_POLICY
  }
}

module.exports = {
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
  getAuthState,
  syncSessionsWithServer
}
