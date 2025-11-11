/**
 * common error handler
 */

import { notification } from 'antd'

function sanitizeMessage (msg) {
  if (!msg) {
    return ''
  }
  return msg.replace(/^Error invoking remote method '.*?':\s*/i, '')
}

export default (e = {}) => {
  const message = sanitizeMessage(e.message || 'error')
  const stack = sanitizeMessage(e.stack || '')
  log.error(e)
  const msg = (
    <div className='mw240 elli wordbreak' title={message}>
      {message}
    </div>
  )
  const description = (
    <div
      className='mw300 elli common-err-desc wordbreak'
    >
      {stack}
    </div>
  )
  notification.error({
    message: msg,
    description,
    duration: 55
  })
}
