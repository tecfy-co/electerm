const log = require('../common/log')
const { dbAction } = require('../lib/db')
const { userConfigId } = require('../common/constants')
const { updateDBVersion } = require('./version-upgrade')
const {
  ensureAdminSeeded,
  findUserByUsername,
  upsertUser
} = require('../lib/user-store')
const { ADMIN_USERNAME } = require('../common/user-roles')
const uid = require('../common/uid')

async function migrateLegacyPasswordConfig () {
  const query = { _id: userConfigId }
  const config = await dbAction('data', 'findOne', query) || {}
  const hasLegacyPassword = !!(config.hashedPassword || config.salt)
  if (!hasLegacyPassword || config.legacyAuthMigrated) {
    return
  }
  log.info('Migrating legacy authentication config to new user model')
  await ensureAdminSeeded()
  const admin = await findUserByUsername(ADMIN_USERNAME)
  await upsertUser({
    ...admin,
    salt: '',
    hashedPassword: '',
    mustResetPassword: true,
    sessionVersion: uid()
  })
  const nextConfig = {
    ...config,
    hashedPassword: '',
    salt: '',
    legacyAuthMigrated: true
  }
  delete nextConfig._id
  await dbAction('data', 'update', query, {
    ...query,
    ...nextConfig
  }, {
    upsert: true
  })
  log.info('Legacy authentication config migrated')
}

module.exports = async () => {
  const versionTo = '2.3.95'
  log.info(`Start: upgrading to v${versionTo}`)
  await migrateLegacyPasswordConfig()
  await updateDBVersion(versionTo)
  log.info(`Done: upgrading to v${versionTo}`)
}

