import { useEffect, useMemo, useState } from 'react'
import { auto } from 'manate/react'
import {
  Button,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography
} from 'antd'
import dayjs from 'dayjs'
import { USER_ROLES } from '../../common/user-roles'
import { settingMap } from '../../common/constants'
import createTitle from '../../common/create-title'
import SettingCol from './col'
const { Text } = Typography

const roleOptions = [
  { label: 'Admin', value: USER_ROLES.ADMIN },
  { label: 'Open Session', value: USER_ROLES.SESSION }
]

const EMPTY_PERMISSIONS = {
  allowAll: false,
  categoryIds: [],
  bookmarkIds: []
}

function formatDate (value) {
  if (!value) {
    return '--'
  }
  return dayjs(value).format('YYYY-MM-DD HH:mm')
}

function getRowKey (user) {
  return user._id || user.id || user.username
}

function toOption (item) {
  return {
    label: createTitle(item),
    value: item.id || item._id
  }
}

export default auto(function TabUsers (props) {
  const { store, settingTab } = props
  const [createVisible, setCreateVisible] = useState(false)
  const [createForm] = Form.useForm()
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [passwordForm] = Form.useForm()
  const [passwordTarget, setPasswordTarget] = useState(null)
  const [passwordSubmitting, setPasswordSubmitting] = useState(false)
  const [permissionsVisible, setPermissionsVisible] = useState(false)
  const [permissionsTarget, setPermissionsTarget] = useState(null)
  const [permissionsState, setPermissionsState] = useState(EMPTY_PERMISSIONS)
  const [permissionsLoading, setPermissionsLoading] = useState(false)
  const [permissionsSaving, setPermissionsSaving] = useState(false)

  useEffect(() => {
    if (settingTab === settingMap.users && store.isAdminUser) {
      store.loadUsers().catch(() => {})
    }
  }, [settingTab])

  const categoryOptions = useMemo(() => {
    return (store.bookmarkGroups || []).map(toOption)
  }, [store.bookmarkGroups])

  const bookmarkOptions = useMemo(() => {
    return (store.bookmarks || []).map(toOption)
  }, [store.bookmarks])

  if (settingTab !== settingMap.users || !store.isAdminUser) {
    return null
  }

  const handleCreate = async () => {
    try {
      const values = await createForm.validateFields()
      await store.createUserAccount(values)
      setCreateVisible(false)
      createForm.resetFields()
    } catch (err) {
      // handled in store
    }
  }

  const handleOpenPasswordModal = (user) => {
    setPasswordTarget(user)
    passwordForm.resetFields()
    passwordForm.setFieldsValue({
      mustResetPassword: false
    })
    setPasswordVisible(true)
  }

  const handlePasswordSubmit = async () => {
    try {
      const values = await passwordForm.validateFields()
      setPasswordSubmitting(true)
      await store.updateUserPassword(
        getRowKey(passwordTarget),
        values.password,
        { mustResetPassword: values.mustResetPassword }
      )
      setPasswordVisible(false)
      setPasswordTarget(null)
      passwordForm.resetFields()
    } catch (err) {
      // handled upstream
    } finally {
      setPasswordSubmitting(false)
    }
  }

  const handleRoleChange = async (user, role) => {
    const userId = getRowKey(user)
    if (!userId) {
      return
    }
    await store.updateUserRole(userId, role)
  }

  const openPermissionsModal = async (user) => {
    const userId = getRowKey(user)
    if (!userId) {
      return
    }
    setPermissionsTarget(user)
    setPermissionsVisible(true)
    setPermissionsLoading(true)
    try {
      const perms = await store.fetchUserPermissions(userId, { force: true })
      setPermissionsState(perms || EMPTY_PERMISSIONS)
    } catch (err) {
      setPermissionsVisible(false)
      setPermissionsTarget(null)
    } finally {
      setPermissionsLoading(false)
    }
  }

  const handlePermissionsSave = async () => {
    if (!permissionsTarget) {
      return
    }
    setPermissionsSaving(true)
    try {
      const saved = await store.saveUserPermissions(
        getRowKey(permissionsTarget),
        permissionsState
      )
      setPermissionsState(saved || EMPTY_PERMISSIONS)
      setPermissionsVisible(false)
      setPermissionsTarget(null)
    } catch (err) {
      // handled upstream
    } finally {
      setPermissionsSaving(false)
    }
  }

  const handleDeleteUser = async (user) => {
    const id = getRowKey(user)
    if (!id) {
      return
    }
    await store.removeUserAccount(id)
  }

  const columns = [
    {
      title: 'Username',
      dataIndex: 'username',
      key: 'username',
      render: (value, record) => {
        const tags = []
        if (record.mustResetPassword) {
          tags.push(<Tag key='mustReset' color='orange'>Reset Required</Tag>)
        }
        return (
          <Space direction='vertical' size={0}>
            <Text strong>{value}</Text>
            <Space size={4}>{tags}</Space>
          </Space>
        )
      }
    },
    {
      title: 'Role',
      dataIndex: 'role',
      key: 'role',
      render: (value, record) => {
        const isPrimaryAdmin = record.username === 'admin'
        return (
          <Select
            size='small'
            value={value}
            disabled={isPrimaryAdmin}
            options={roleOptions}
            onChange={(next) => handleRoleChange(record, next)}
          />
        )
      }
    },
    {
      title: 'Last Login',
      dataIndex: 'lastLoginAt',
      key: 'lastLoginAt',
      render: formatDate
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => {
        const userId = getRowKey(record)
        const isAdmin = record.role === USER_ROLES.ADMIN
        const isPrimaryAdmin = record.username === 'admin'
        return (
          <Space size='small'>
            <Button size='small' onClick={() => handleOpenPasswordModal(record)}>
              Set Password
            </Button>
            <Button
              size='small'
              disabled={isAdmin}
              onClick={() => openPermissionsModal(record)}
            >
              Permissions
            </Button>
            <Button
              size='small'
              danger
              disabled={isPrimaryAdmin}
              onClick={() => handleDeleteUser(record)}
            >
              Remove
            </Button>
          </Space>
        )
      }
    }
  ]

  return (
    <div className='setting-tabs-users'>
      <SettingCol>
        <div className='setting-users-sidebar'>
          <div className='pd2'>
            <Typography.Title level={4}>User Access</Typography.Title>
            <Typography.Paragraph type='secondary'>
              Create administrator or session-only users and assign bookmark/category permissions.
            </Typography.Paragraph>
            <Typography.Paragraph type='secondary'>
              Session users can launch allowed bookmarks but cannot edit them.
            </Typography.Paragraph>
          </div>
        </div>
        <div className='setting-users-content'>
          <Space style={{ marginBottom: 16 }}>
            <Button
              type='primary'
              onClick={() => {
                createForm.resetFields()
                createForm.setFieldsValue({
                  role: USER_ROLES.SESSION
                })
                setCreateVisible(true)
              }}
            >
              New User
            </Button>
          </Space>
          <Table
            dataSource={store.users}
            columns={columns}
            rowKey={getRowKey}
            loading={store.usersLoading}
            pagination={false}
            locale={{ emptyText: 'No users yet' }}
          />
        </div>
      </SettingCol>

      <Modal
        open={createVisible}
        title='Create User'
        okText='Create'
        onOk={handleCreate}
        onCancel={() => setCreateVisible(false)}
        destroyOnClose
      >
        <Form
          layout='vertical'
          form={createForm}
          initialValues={{
            role: USER_ROLES.SESSION
          }}
        >
          <Form.Item
            label='Username'
            name='username'
            rules={[
              { required: true, message: 'Username is required' },
              { min: 3, message: 'Username should be at least 3 characters' }
            ]}
          >
            <Input />
          </Form.Item>
          <Form.Item
            label='Role'
            name='role'
            rules={[{ required: true }]}
          >
            <Select options={roleOptions} />
          </Form.Item>
          <Form.Item
            label='Password'
            name='password'
            extra='Leave blank to require the user to set a password on first login.'
          >
            <Input.Password autoComplete='new-password' />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        open={passwordVisible}
        title={`Update Password${passwordTarget ? ` – ${passwordTarget.username}` : ''}`}
        okText='Update'
        confirmLoading={passwordSubmitting}
        onCancel={() => {
          setPasswordVisible(false)
          setPasswordTarget(null)
        }}
        onOk={handlePasswordSubmit}
        destroyOnClose
      >
        <Form
          form={passwordForm}
          layout='vertical'
          initialValues={{ mustResetPassword: false }}
        >
          <Form.Item
            label='New Password'
            name='password'
            rules={[
              { required: true, message: 'Password is required' },
              {
                validator: (_, value) => {
                  if (!value || value.length >= 12) {
                    return Promise.resolve()
                  }
                  return Promise.reject(new Error('Password must be at least 12 characters'))
                }
              }
            ]}
          >
            <Input.Password autoComplete='new-password' />
          </Form.Item>
          <Form.Item
            label='Require password change on next sign-in'
            name='mustResetPassword'
            valuePropName='checked'
          >
            <Switch />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        open={permissionsVisible}
        title={permissionsTarget ? `Permissions – ${permissionsTarget.username}` : 'Permissions'}
        okText='Save'
        confirmLoading={permissionsSaving}
        onCancel={() => {
          setPermissionsVisible(false)
          setPermissionsTarget(null)
        }}
        onOk={handlePermissionsSave}
        destroyOnClose
      >
        {permissionsLoading
          ? (
            <div className='pd2 aligncenter'>Loading permissions…</div>
            )
          : (
            <Form layout='vertical'>
              <Form.Item label='Allow access to all categories and bookmarks'>
                <Switch
                  checked={permissionsState.allowAll}
                  onChange={(checked) => setPermissionsState(prev => ({
                    ...prev,
                    allowAll: checked
                  }))}
                />
              </Form.Item>
              {!permissionsState.allowAll && (
                <>
                  <Form.Item label='Allowed Categories'>
                    <Select
                      mode='multiple'
                      value={permissionsState.categoryIds}
                      options={categoryOptions}
                      onChange={(values) => setPermissionsState(prev => ({
                        ...prev,
                        categoryIds: values
                      }))}
                      placeholder='Select categories'
                      allowClear
                    />
                  </Form.Item>
                  <Form.Item label='Allowed Bookmarks'>
                    <Select
                      mode='multiple'
                      value={permissionsState.bookmarkIds}
                      options={bookmarkOptions}
                      onChange={(values) => setPermissionsState(prev => ({
                        ...prev,
                        bookmarkIds: values
                      }))}
                      placeholder='Select specific bookmarks'
                      allowClear
                      showSearch
                    />
                  </Form.Item>
                </>
              )}
            </Form>
            )}
      </Modal>
    </div>
  )
})
