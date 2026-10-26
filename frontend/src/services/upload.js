import api from './api'

export const uploadFile = (file, scannerType, onProgress) => {
  const form = new FormData()
  form.append('file', file)
  form.append('scanner_type', scannerType)
  return api.post('/upload/', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (e) => onProgress && onProgress(Math.round((e.loaded / e.total) * 100)),
  })
}

export const listUploads  = (page = 1) => api.get(`/upload/?page=${page}&per_page=20`)
export const getUpload    = (id)       => api.get(`/upload/${id}`)
export const deleteUpload = (id)       => api.delete(`/upload/${id}`)
export const runPipeline  = (id, opts = {}) =>
  api.post(`/pipeline/run/${id}`, {
    run_poc: opts.runPoc ?? false,
    poc_scope: opts.pocScope || null,
    search_exploits: opts.searchExploits ?? false,
  })
export const getMLInfo    = ()         => api.get('/pipeline/ml/info')
export const getScanners  = ()         => api.get('/pipeline/scanners')
export const startAutoScan = (opts)    =>
  api.post('/pipeline/autoscan', {
    target: opts.target,
    scanners: opts.scanners,
    authorise: opts.authorise,
    search_exploits: opts.searchExploits ?? false,
    run_poc: opts.runPoc ?? false,
    poc_scope: opts.pocScope || null,
  })   // returns { job_id } immediately; poll status below
export const getAutoScanStatus = (jobId) => api.get(`/pipeline/autoscan/status/${jobId}`)
