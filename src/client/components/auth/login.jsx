import React, { useState, useEffect } from 'react'
import LogoElem from '../common/logo-elem.jsx'
import store from '../../store'
import {
  message,
  Spin,
  Input,
  Button,
  Typography,
  Form,
  Alert
} from 'antd'
import Main from '../main/main.jsx'
import AppDrag from '../tabs/app-drag'
import WindowControl from '../tabs/window-control'
import './login.styl'

const { Title, Paragraph } = Typography
const e = window.translate

window.store = store

const ADMIN_USERNAME = 'admin'

function useAuthState () {
  const [authState, setAuthState] = useState(window.pre.requireAuth ? (window.pre.authState || null) : null)
  useEffect(() => {
    if (!window.pre.requireAuth) {
      return
    }
    let mounted = true
    const load = async () => {
      try {
        const globs = await window.pre.runGlobalAsync('init')
        window.et.globs = globs
        const state = globs?.config?.authState || await window.pre.runGlobalAsync('authGetState')
        if (mounted) {
          window.pre.authState = state
          setAuthState(state)
        }
      } catch (err) {
        console.error('Failed to init auth state', err)
        message.error('Failed to load authentication state')
      }
    }
    load()
    return () => {
      mounted = false
    }
  }, [])
  return authState
}

export default function Login () {
  const authState = useAuthState()
  const needsSetup = authState?.needsAdminPasswordSetup
  const [mode, setMode] = useState(needsSetup ? 'setup' : 'login')
  const [username, setUsername] = useState(ADMIN_USERNAME)
  const [password, setPassword] = useState('')
  const [setupPassword, setSetupPassword] = useState('')
  const [setupConfirm, setSetupConfirm] = useState('')
  const [logined, setLogined] = useState(!window.pre.requireAuth)
  const [loading, setLoading] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (authState) {
      setMode(authState.needsAdminPasswordSetup ? 'setup' : 'login')
      if (!authState.needsAdminPasswordSetup) {
        setUsername(ADMIN_USERNAME)
      }
    }
  }, [authState])

  const updateSessionContext = async (result) => {
    const {
      sessionToken,
      user,
      permissions
    } = result
    const latestAuthState = await window.pre.runGlobalAsync('authGetState').catch(() => authState)
    if (latestAuthState) {
      window.pre.authState = latestAuthState
      window.store.authState = latestAuthState
    }
    window.pre.sessionToken = sessionToken
    window.store.sessionToken = sessionToken
    window.store.currentUser = user
    window.store.permissions = permissions
    if (!window.et.globs) {
      window.et.globs = { config: {} }
    }
    window.et.globs.config = {
      ...(window.et.globs.config || {}),
      sessionToken,
      currentUser: user,
      permissions,
      authState: latestAuthState || authState || {}
    }
    window.store._config = window.et.globs.config
  }

  const handleLogin = async () => {
    if (!username || !password) {
      return message.warning('Username and password required')
    }
    if (submitting) {
      return
    }
    setSubmitting(true)
    setLoading(true)
    try {
      const result = await window.pre.runGlobalAsync('authLogin', username.trim(), password)
      await updateSessionContext(result)
      window.pre.requireAuth = false
      setLogined(true)
      setLoading(false)
      message.success(`Welcome, ${result.user.username}`)
    } catch (err) {
      setLoading(false)
      const msg = err?.message || 'Login failed'
      message.error(msg)
    } finally {
      setSubmitting(false)
    }
  }

  const handleSetup = async () => {
    if (submitting) {
      return
    }
    if (!setupPassword || !setupConfirm) {
      return message.warning('Enter and confirm the new password')
    }
    if (setupPassword !== setupConfirm) {
      return message.error('Passwords do not match')
    }
    setSubmitting(true)
    setLoading(true)
    try {
      await window.pre.runGlobalAsync('authInitializeAdminPassword', setupPassword)
      message.success('Admin password configured')
      const result = await window.pre.runGlobalAsync('authLogin', ADMIN_USERNAME, setupPassword)
      await updateSessionContext(result)
      window.pre.requireAuth = false
      setLogined(true)
      message.success(`Welcome, ${result.user.username}`)
    } catch (err) {
      const msg = err?.message || 'Failed to set password'
      message.error(msg)
    } finally {
      setLoading(false)
      setSubmitting(false)
    }
  }

  const renderSetupForm = () => (
    <Form layout='vertical' className='pd3 alignleft setup-form' onFinish={handleSetup}>
      <Title level={3} className='aligncenter'>Set Admin Password</Title>
      <Paragraph type='secondary'>
        For your security we require a strong password (12+ characters including uppercase, lowercase, numbers, and special symbols).
      </Paragraph>
      <Form.Item label='Username'>
        <Input value={ADMIN_USERNAME} disabled />
      </Form.Item>
      <Form.Item label='New Password' required>
        <Input.Password
          value={setupPassword}
          onChange={e => setSetupPassword(e.target.value)}
          disabled={loading}
        />
      </Form.Item>
      <Form.Item label='Confirm Password' required>
        <Input.Password
          value={setupConfirm}
          onChange={e => setSetupConfirm(e.target.value)}
          disabled={loading}
        />
      </Form.Item>
      <Form.Item>
        <Button
          type='primary'
          htmlType='submit'
          loading={loading}
          block
        >
          Apply &amp; Sign In
        </Button>
      </Form.Item>
    </Form>
  )

  const renderLoginForm = () => (
    <Form layout='vertical' className='pd3 alignleft login-form' onFinish={handleLogin}>
      <Title level={3} className='aligncenter'>{e('login')}</Title>
      {authState?.needsAdminPasswordSetup && (
        <Alert
          type='warning'
          showIcon
          message='Password setup required'
          description='Finish the admin password setup before continuing.'
          className='mg2b'
        />
      )}
      <Form.Item label='Username' required>
        <Input
          autoFocus
          disabled={loading}
          value={username}
          onChange={e => setUsername(e.target.value)}
          placeholder='username'
        />
      </Form.Item>
      <Form.Item label='Password' required>
        <Input.Password
          disabled={loading}
          value={password}
          onChange={e => setPassword(e.target.value)}
          placeholder={e('password')}
        />
      </Form.Item>
      <Form.Item>
        <Button
          type='primary'
          htmlType='submit'
          loading={loading}
          block
        >
          Sign In
        </Button>
      </Form.Item>
    </Form>
  )

  const renderContent = () => {
    if (mode === 'setup') {
      return renderSetupForm()
    }
    return renderLoginForm()
  }

  if (!logined) {
    return (
      <div className='login-wrap'>
        <AppDrag />
        <WindowControl store={window.store} />
        <div className='pd3 aligncenter'>
          <LogoElem />
          <div className='pd3 aligncenter login-card'>
            {renderContent()}
          </div>
          <div className='aligncenter'>
            <Spin spinning={loading && submitting} />
          </div>
        </div>
      </div>
    )
  }

  return (
    <Main store={store} />
  )
}
