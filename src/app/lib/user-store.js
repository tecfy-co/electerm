const { dbAction } = require('./db')
const uid = require('../common/uid')
const {
  USER_ROLES,
  ADMIN_USERNAME
} = require('../common/user-roles')

const USERS_TABLE = 'users'
const PERMISSIONS_TABLE = 'userPermissions'

function normalizeUsername (username = '') {
  return String(username || '')
    .trim()
    .toLowerCase()
}

function buildUserId (username) {
  const normalized = normalizeUsername(username)
  if (!normalized) {
    throw new Error('Username required')
  }
  return `user:${normalized}`
}

function nowIso () {
  return new Date().toISOString()
}

async function findUserById (id) {
  if (!id) {
    return null
  }
  return dbAction(USERS_TABLE, 'findOne', { _id: id })
}

async function findUserByUsername (username) {
  if (!username) {
    return null
  }
  const id = buildUserId(username)
  return findUserById(id)
}

async function listUsers () {
  return dbAction(USERS_TABLE, 'find', {})
}

async function upsertUser (user) {
  const username = user.username || user.name
  const id = user._id || buildUserId(username)
  const existing = await findUserById(id)
  const timestamps = existing
    ? {
        createdAt: existing.createdAt,
        updatedAt: nowIso()
      }
    : {
        createdAt: nowIso(),
        updatedAt: nowIso()
      }
  const payload = {
    _id: id,
    username,
    normalizedUsername: normalizeUsername(username),
    role: user.role || USER_ROLES.SESSION,
    salt: user.salt || '',
    hashedPassword: user.hashedPassword || '',
    failedAttempts: typeof user.failedAttempts === 'number' ? user.failedAttempts : (existing ? existing.failedAttempts || 0 : 0),
    lockedUntil: user.lockedUntil || null,
    mustResetPassword: typeof user.mustResetPassword === 'boolean'
      ? user.mustResetPassword
      : (existing ? existing.mustResetPassword : false),
    sessionVersion: user.sessionVersion || (existing ? existing.sessionVersion : uid()),
    lastLoginAt: user.lastLoginAt || (existing ? existing.lastLoginAt : null),
    ...timestamps
  }
  await dbAction(USERS_TABLE, 'update', { _id: id }, { $set: payload }, { upsert: true })
  return findUserById(id)
}

async function deleteUser (id) {
  if (!id) {
    return 0
  }
  await dbAction(PERMISSIONS_TABLE, 'remove', { _id: id })
  return dbAction(USERS_TABLE, 'remove', { _id: id })
}

function emptyPermissions () {
  return {
    _id: '',
    userId: '',
    allowAll: false,
    categoryIds: [],
    bookmarkIds: [],
    createdAt: nowIso(),
    updatedAt: nowIso()
  }
}

async function getPermissions (userId) {
  if (!userId) {
    return null
  }
  const record = await dbAction(PERMISSIONS_TABLE, 'findOne', { _id: userId })
  if (record) {
    return record
  }
  return {
    ...emptyPermissions(),
    _id: userId,
    userId,
    createdAt: nowIso(),
    updatedAt: nowIso()
  }
}

async function setPermissions (userId, permissions) {
  if (!userId) {
    throw new Error('userId required')
  }
  const payload = {
    _id: userId,
    userId,
    allowAll: !!permissions.allowAll,
    categoryIds: Array.isArray(permissions.categoryIds) ? permissions.categoryIds : [],
    bookmarkIds: Array.isArray(permissions.bookmarkIds) ? permissions.bookmarkIds : [],
    createdAt: nowIso(),
    updatedAt: nowIso()
  }
  const existing = await dbAction(PERMISSIONS_TABLE, 'findOne', { _id: userId })
  if (existing) {
    payload.createdAt = existing.createdAt
  }
  await dbAction(PERMISSIONS_TABLE, 'update', { _id: userId }, { $set: payload }, { upsert: true })
  return getPermissions(userId)
}

function isAdmin (user) {
  return user && user.role === USER_ROLES.ADMIN
}

async function ensureAdminSeeded () {
  const admin = await findUserByUsername(ADMIN_USERNAME)
  if (admin) {
    return admin
  }
  return upsertUser({
    username: ADMIN_USERNAME,
    role: USER_ROLES.ADMIN,
    hashedPassword: '',
    salt: '',
    mustResetPassword: true,
    sessionVersion: uid()
  })
}

module.exports = {
  USERS_TABLE,
  PERMISSIONS_TABLE,
  normalizeUsername,
  buildUserId,
  listUsers,
  findUserById,
  findUserByUsername,
  upsertUser,
  deleteUser,
  getPermissions,
  setPermissions,
  isAdmin,
  ensureAdminSeeded
}
