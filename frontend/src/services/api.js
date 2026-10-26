import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
})

// Attach stored token on every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('vt_token')
  if (token) config.headers['Authorization'] = `Bearer ${token}`
  return config
})

// Global 401 handler — clear storage and redirect to login
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('vt_token')
      localStorage.removeItem('vt_user')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export default api
