import { defineStore } from 'pinia'
import api from '../api'

export const useCodeStore = defineStore('code', {
  state: () => ({
    inputCode: '',
    outputCode: '',
    language: 'c',
    vulnerabilities: [],
    fixedCode: '',
    changes: [],
    validationResult: null,
    isLoading: false,
    error: null
  }),

  actions: {
    async analyzeCode() {
      this.isLoading = true
      this.error = null
      try {
        const response = await api.analyze(this.inputCode, this.language)
        this.vulnerabilities = response.data
        
        // 保存历史记录
        await api.saveHistory({
          type: 'analyze',
          language: this.language,
          original_code: this.inputCode,
          result_code: JSON.stringify(this.vulnerabilities, null, 2),
          changes: []
        })
      } catch (error) {
        this.error = error.message
      } finally {
        this.isLoading = false
      }
    },

    async generateFix() {
      this.isLoading = true
      this.error = null
      try {
        const response = await api.generate(this.inputCode, this.language)
        this.fixedCode = response.data.fixed_code
        this.changes = response.data.changes_made || []
        
        // 保存历史记录
        await api.saveHistory({
          type: 'generate',
          language: this.language,
          original_code: this.inputCode,
          result_code: this.fixedCode,
          changes: this.changes
        })
      } catch (error) {
        this.error = error.message
      } finally {
        this.isLoading = false
      }
    },

    async validateCode() {
      this.isLoading = true
      this.error = null
      try {
        const response = await api.validate(this.inputCode, this.language)
        this.validationResult = response.data
        
        // 保存历史记录
        await api.saveHistory({
          type: 'validate',
          language: this.language,
          original_code: this.inputCode,
          result_code: JSON.stringify(this.validationResult, null, 2),
          changes: []
        })
      } catch (error) {
        this.error = error.message
      } finally {
        this.isLoading = false
      }
    },

    setInputCode(code) {
      this.inputCode = code
    },

    setLanguage(lang) {
      this.language = lang
    }
  }
})