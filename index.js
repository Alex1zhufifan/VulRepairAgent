import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/LoginView.vue'),
    meta: { requiresAuth: false }
  },
  {
    path: '/',
    name: 'Home',
    component: () => import('../views/HomeView.vue'),
    meta: { requiresAuth: true }
  },
  {
    path: '/analyze',
    name: 'Analyze',
    component: () => import('../views/AnalyzeView.vue'),
    meta: { requiresAuth: true }
  },
  {
    path: '/generate',
    name: 'Generate',
    component: () => import('../views/GenerateView.vue'),
    meta: { requiresAuth: true }
  },
  {
    path: '/validate',
    name: 'Validate',
    component: () => import('../views/ValidateView.vue'),
    meta: { requiresAuth: true }
  },
  {
  path: '/history',
  name: 'History',
  component: () => import('../views/HistoryView.vue'),
  meta: { requiresAuth: true }
 }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// 简化版路由守卫
router.beforeEach((to, from, next) => {
  // 直接从 localStorage 读取 token
  const token = localStorage.getItem('token')
  const isLoggedIn = !!token

  if (to.meta.requiresAuth && !isLoggedIn) {
    // 需要登录但没有 token，跳转到登录页
    next('/login')
  } else if (to.path === '/login' && isLoggedIn) {
    // 已登录但访问登录页，跳转到首页
    next('/')
  } else {
    next()
  }
})

export default router