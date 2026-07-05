<template>
  <div class="home">
    <el-row :gutter="20">
      <el-col :span="8" v-for="feature in features" :key="feature.title">
        <el-card class="feature-card" :body-style="{ padding: '20px' }">
          <template #header>
            <div class="card-header">
              <el-icon :size="24" :color="feature.color">
                <component :is="feature.icon" />
              </el-icon>
              <h3>{{ feature.title }}</h3>
            </div>
          </template>
          <p>{{ feature.description }}</p>
          <el-button type="primary" @click="$router.push(feature.route)">
            开始使用
          </el-button>
        </el-card>
      </el-col>
    </el-row>

    <el-card class="info-card">
      <template #header>
        <div class="card-header">
          <el-icon><InfoFilled /></el-icon>
          <h3>系统简介</h3>
        </div>
      </template>
      <p>VulRepairAgent 是一个智能漏洞代码修复代理系统，可以帮助开发者：</p>
      <ul>
        <li>🔍 自动分析代码中的安全漏洞</li>
        <li>🛠️ 生成安全的修复方案</li>
        <li>✅ 验证修复后的代码安全性</li>
      </ul>
    </el-card>
  </div>
</template>

<script setup>
import { InfoFilled } from '@element-plus/icons-vue'

const features = [
  {
    icon: 'Search',
    title: '漏洞分析',
    description: '自动检测代码中的安全漏洞，包括缓冲区溢出、命令注入等常见漏洞类型。',
    route: '/analyze',
    color: '#F56C6C'
  },
  {
    icon: 'Edit',
    title: '修复生成',
    description: '基于AI模型生成安全的代码修复方案，保持原有功能不变。',
    route: '/generate',
    color: '#E6A23C'
  },
  {
    icon: 'Check',
    title: '代码验证',
    description: '在沙箱环境中验证修复后的代码，确保安全性和正确性。',
    route: '/validate',
    color: '#67C23A'
  }
]
</script>

<style scoped>
.home {
  max-width: 1200px;
  margin: 0 auto;
}

.feature-card {
  height: 250px;
  margin-bottom: 20px;
  transition: transform 0.3s;
}

.feature-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.card-header {
  display: flex;
  align-items: center;
  gap: 10px;
}

.card-header h3 {
  margin: 0;
  font-size: 18px;
}

.info-card {
  margin-top: 40px;
}

.info-card ul {
  list-style: none;
  padding: 0;
}

.info-card li {
  margin: 10px 0;
  font-size: 16px;
}
</style>