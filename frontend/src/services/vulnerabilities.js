import api from './api'

export const listFindings = (params = {}) =>
  api.get('/vulnerabilities/', { params })

export const getFinding = (id) =>
  api.get(`/vulnerabilities/${id}`)

export const updateClassification = (id, classification) =>
  api.patch(`/vulnerabilities/${id}/classification`, { classification })
