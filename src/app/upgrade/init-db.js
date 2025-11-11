/**
 * for new user, they do not have old json db
 * just need init db
 */

const { dbAction } = require('../lib/db')
const log = require('../common/log')
const defaults = require('./db-defaults')
const { ensureAdminSeeded } = require('../lib/user-store')

async function initData () {
  log.info('start: init db')
  for (const conf of defaults) {
    const {
      db, data
    } = conf
    await dbAction(db, 'insert', data).catch(log.error)
  }
  await ensureAdminSeeded().catch(err => {
    log.error('ensureAdminSeeded failed', err)
  })
  log.info('end: init db')
}

module.exports = initData
