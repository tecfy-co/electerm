const crypto = require('crypto')
const {
  DEFAULT_SESSION_EXPIRY_MINUTES
} = require('../common/user-roles')

const sessions = new Map()

function generateToken () {
  return crypto.randomBytes(48).toString('hex')
}

function minutesToMs (minutes) {
  return minutes * 60 * 1000
}

function createSession ({ userId, role, permissions = {}, sessionVersion }) {
  if (!userId) {
    throw new Error('userId required to create session')
  }
  const token = generateToken()
  const now = Date.now()
  const expiresAt = now + minutesToMs(DEFAULT_SESSION_EXPIRY_MINUTES)
  const session = {
    token,
    userId,
    role,
    permissions,
    sessionVersion,
    createdAt: now,
    updatedAt: now,
    expiresAt
  }
  sessions.set(token, session)
  return session
}

function validateSession (token) {
  if (!token) {
    return null
  }
  const session = sessions.get(token)
  if (!session) {
    return null
  }
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token)
    return null
  }
  return session
}

function touchSession (token, minutes = DEFAULT_SESSION_EXPIRY_MINUTES) {
  const session = sessions.get(token)
  if (!session) {
    return null
  }
  const now = Date.now()
  session.updatedAt = now
  session.expiresAt = now + minutesToMs(minutes)
  sessions.set(token, session)
  return session
}

function invalidateSession (token) {
  if (!token) {
    return false
  }
  return sessions.delete(token)
}

function invalidateUserSessions (userId) {
  if (!userId) {
    return 0
  }
  let removed = 0
  for (const [token, session] of sessions.entries()) {
    if (session.userId === userId) {
      sessions.delete(token)
      removed++
    }
  }
  return removed
}

function serializeSession (session) {
  if (!session) {
    return null
  }
  return {
    token: session.token,
    userId: session.userId,
    role: session.role,
    permissions: session.permissions,
    expiresAt: session.expiresAt,
    sessionVersion: session.sessionVersion
  }
}

function listSessions () {
  return Array.from(sessions.values()).map(serializeSession).filter(Boolean)
}

module.exports = {
  createSession,
  validateSession,
  touchSession,
  invalidateSession,
  invalidateUserSessions,
  serializeSession,
  listSessions
}

