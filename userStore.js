import { defineStore } from 'pinia'
import api from '../api'

export const useUserStore = defineStore('user', {
  state: () => ({
    token: localStorage.getItem('token') || '',
    username: localStorage.getItem('username') || '',
    isLoggedIn: !!localStorage.getItem('token')
  }),

  actions: {
    async login(username, password) {
      const response = await api.login(username, password)
      this.token = response.access_token
      this.username = response.username
      this.isLoggedIn = true
      localStorage.setItem('token', response.access_token)
      localStorage.setItem('username', response.username)
      // 设置 axios 默认 header
      api.setAuthToken(response.access_token)
    },

    async register(username, password, email = null) {
      await api.register(username, password, email)
    },

    logout() {
      this.token = ''
      this.username = ''
      this.isLoggedIn = false
      localStorage.removeItem('token')
      localStorage.removeItem('username')
      api.removeAuthToken()
    },

    async checkAuth() {
      if (this.token) {
        api.setAuthToken(this.token)
        try {
          await api.getMe()
          this.isLoggedIn = true
        } catch (error) {
          this.logout()
        }
      }
    }
  }
})