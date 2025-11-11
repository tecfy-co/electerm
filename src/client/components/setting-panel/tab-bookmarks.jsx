import SettingCol from './col'
import BookmarkForm from '../bookmark-form'
import TreeList from './bookmark-tree-list'
import {
  settingMap
} from '../../common/constants'

export default function TabBookmarks (props) {
  const {
    settingTab
  } = props
  if (settingTab !== settingMap.bookmarks) {
    return null
  }
  const {
    settingItem,
    treeProps,
    formProps
  } = props
  const readOnly = props.store?.isReadOnlyUser
  return (
    <div
      className='setting-tabs-bookmarks'
    >
      <SettingCol>
        <div className='model-bookmark-tree-wrap'>
          <TreeList
            {...treeProps}
            readOnly={readOnly}
            staticList={readOnly || treeProps.staticList}
          />
        </div>
        {
          readOnly
            ? (
              <div className='pd2'>
                <b>Read-only session</b>
                <p className='mg1t'>
                  Bookmark details are hidden for this account. Contact an administrator for changes.
                </p>
              </div>
              )
            : (
              <BookmarkForm
                key={settingItem.id}
                {...formProps}
                readOnly={readOnly}
              />
              )
        }
      </SettingCol>
    </div>
  )
}
