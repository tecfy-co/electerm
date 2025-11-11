const { filterGroupsResult, filterBookmarksResult } = require('../../src/app/lib/permissions')
const { expect } = require('../common/expect')
const {
  test: it
} = require('@playwright/test')
const { describe } = it

it.setTimeout(100000)

describe('permissions helpers', () => {
  const groups = [
    { _id: 'default', title: 'default', bookmarkIds: ['b0'], bookmarkGroupIds: [] },
    { _id: 'g1', title: 'group-1', bookmarkIds: ['b1'], bookmarkGroupIds: [] },
    { _id: 'g2', title: 'group-2', bookmarkIds: ['b2'], bookmarkGroupIds: [] },
    { _id: 'g3', title: 'group-3', bookmarkIds: ['b3'], bookmarkGroupIds: [] }
  ]
  const bookmarks = [
    { _id: 'b0', title: 'default-bookmark' },
    { _id: 'b1', title: 'bookmark-1' },
    { _id: 'b2', title: 'bookmark-2' },
    { _id: 'b3', title: 'bookmark-3' }
  ]
  const permissions = {
    allowAll: false,
    categoryIds: ['g1'],
    bookmarkIds: ['b2']
  }

  it('filters bookmark groups using permission scope', () => {
    const filtered = filterGroupsResult(groups, permissions, groups)
    expect(filtered.map(g => g._id)).toEqual(['default', 'g1'])
  })

  it('filters bookmarks combining categories and explicit ids', () => {
    const filtered = filterBookmarksResult(bookmarks, permissions, groups)
    expect(filtered.map(b => b._id)).toEqual(['b0', 'b1', 'b2'])
  })
})
