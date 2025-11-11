const { defaultBookmarkGroupId } = require('../common/constants')

function toArray (value) {
  if (!value) {
    return []
  }
  return Array.isArray(value) ? value : [value]
}

function toOriginalShape (list, original) {
  if (Array.isArray(original)) {
    return list
  }
  return list[0] || null
}

function computeAllowedGroupIds (permissions, groups) {
  if (permissions.allowAll) {
    return new Set(groups.map(group => group._id || group.id))
  }
  const allowedGroupIds = new Set(permissions.categoryIds || [])
  const allowedBookmarkIds = new Set(permissions.bookmarkIds || [])
  const parentMap = new Map()

  for (const group of groups) {
    const gid = group._id || group.id
    const children = group.bookmarkGroupIds || []
    for (const child of children) {
      if (!parentMap.has(child)) {
        parentMap.set(child, new Set())
      }
      parentMap.get(child).add(gid)
    }
    const bookmarkIds = group.bookmarkIds || []
    if (bookmarkIds.some(id => allowedBookmarkIds.has(id))) {
      allowedGroupIds.add(gid)
    }
  }

  const queue = [...allowedGroupIds]
  while (queue.length) {
    const current = queue.pop()
    const parents = parentMap.get(current)
    if (!parents) {
      continue
    }
    for (const parentId of parents) {
      if (!allowedGroupIds.has(parentId)) {
        allowedGroupIds.add(parentId)
        queue.push(parentId)
      }
    }
  }
  allowedGroupIds.add(defaultBookmarkGroupId)
  return allowedGroupIds
}

function buildBookmarkToGroups (groups) {
  const map = new Map()
  for (const group of groups) {
    const gid = group._id || group.id
    for (const bid of (group.bookmarkIds || [])) {
      if (!map.has(bid)) {
        map.set(bid, new Set())
      }
      map.get(bid).add(gid)
    }
  }
  return map
}

function filterGroupsResult (result, permissions, allGroups) {
  if (permissions.allowAll) {
    return result
  }
  const groups = Array.isArray(allGroups) ? allGroups : toArray(result)
  const allowedIds = computeAllowedGroupIds(permissions, groups)
  const list = toArray(result)
  const filtered = list.filter(group => allowedIds.has(group._id || group.id))
  return toOriginalShape(filtered, result)
}

function filterBookmarksResult (result, permissions, groups) {
  if (permissions.allowAll) {
    return result
  }
  const list = toArray(result)
  if (!list.length) {
    return Array.isArray(result) ? [] : null
  }
  const allowedGroups = computeAllowedGroupIds(permissions, groups)
  const allowedBookmarkIds = new Set(permissions.bookmarkIds || [])
  const bookmarkGroups = buildBookmarkToGroups(groups)
  const filtered = list.filter(bookmark => {
    const id = bookmark._id || bookmark.id
    if (!id) {
      return false
    }
    if (allowedBookmarkIds.has(id)) {
      return true
    }
    const relatedGroups = bookmarkGroups.get(id)
    if (!relatedGroups) {
      return false
    }
    for (const gid of relatedGroups) {
      if (allowedGroups.has(gid)) {
        return true
      }
    }
    return false
  })
  return toOriginalShape(filtered, result)
}

module.exports = {
  toArray,
  toOriginalShape,
  computeAllowedGroupIds,
  filterGroupsResult,
  filterBookmarksResult
}
