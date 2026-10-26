import api from './api'

export const listReports    = ()                => api.get('/reports/')
export const getReport      = (id)              => api.get(`/reports/${id}`)
export const downloadReport = (id)              => api.get(`/reports/${id}/download`, { responseType: 'blob' })
export const generateReport = (uploadIds, title) =>
  api.post('/reports/generate', { upload_ids: uploadIds || [], title })
