/**
 * Shared user role constants for application logic.
 */

const USER_ROLES = Object.freeze({
  ADMIN: 'admin',
  SESSION: 'session'
})

const DEFAULT_SESSION_EXPIRY_MINUTES = 120 // 2 hours
const ADMIN_USERNAME = 'admin'

module.exports = {
  USER_ROLES,
  DEFAULT_SESSION_EXPIRY_MINUTES,
  ADMIN_USERNAME
}

