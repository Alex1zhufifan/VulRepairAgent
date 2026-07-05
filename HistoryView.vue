<template>
  <div class="history-view">
    <el-card>
      <template #header>
        <div class="card-header">
          <h2>历史记录</h2>
          <el-radio-group v-model="filterType" size="small" @change="loadHistory">
            <el-radio-button label="">全部</el-radio-button>
            <el-radio-button label="analyze">漏洞分析</el-radio-button>
            <el-radio-button label="generate">修复生成</el-radio-button>
            <el-radio-button label="validate">代码验证</el-radio-button>
          </el-radio-group>
        </div>
      </template>

      <el-table :data="historyList" stripe v-loading="loading" style="width: 100%">
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="type" label="类型" width="120">
          <template #default="scope">
            <el-tag :type="getTypeTag(scope.row.type)">
              {{ getTypeName(scope.row.type) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="language" label="语言" width="80" />
        <el-table-column prop="original_code" label="原始代码" show-overflow-tooltip />
        <el-table-column prop="created_at" label="时间" width="180" />
        <el-table-column label="操作" width="150" fixed="right">
          <template #default="scope">
            <el-button type="primary" size="small" @click="viewDetail(scope.row)">
              查看详情
            </el-button>
            <el-button type="danger" size="small" @click="deleteRecord(scope.row)">
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :total="total"
          :page-sizes="[10, 20, 50]"
          layout="total, sizes, prev, pager, next"
          @size-change="loadHistory"
          @current-change="loadHistory"
        />
      </div>
    </el-card>

    <!-- 详情弹窗 -->
    <el-dialog v-model="detailVisible" :title="detailTitle" width="70%">
      <div v-if="detailData">
        <h4>原始代码：</h4>
        <pre class="code-block">{{ detailData.original_code }}</pre>
        
        <h4 v-if="detailData.result_code">结果：</h4>
        <pre v-if="detailData.result_code" class="code-block">{{ detailData.result_code }}</pre>
        
        <h4 v-if="detailData.changes && detailData.changes.length > 0">修改内容：</h4>
        <el-timeline v-if="detailData.changes && detailData.changes.length > 0">
          <el-timeline-item
            v-for="(change, index) in detailData.changes"
            :key="index"
            :type="change.type === 'function_replacement' ? 'primary' : 'success'"
          >
            {{ change.description }}
          </el-timeline-item>
        </el-timeline>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '../api'

const historyList = ref([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(10)
const filterType = ref('')
const loading = ref(false)

const detailVisible = ref(false)
const detailData = ref(null)
const detailTitle = ref('')

const getTypeName = (type) => {
  const map = {
    'analyze': '漏洞分析',
    'generate': '修复生成',
    'validate': '代码验证'
  }
  return map[type] || type
}

const getTypeTag = (type) => {
  const map = {
    'analyze': 'warning',
    'generate': 'success',
    'validate': 'info'
  }
  return map[type] || ''
}

const loadHistory = async () => {
  loading.value = true
  try {
    const params = {
      page: page.value,
      page_size: pageSize.value
    }
    if (filterType.value) {
      params.type = filterType.value
    }
    const res = await api.getHistoryList(params)
    historyList.value = res.items || []
    total.value = res.total || 0
  } catch (error) {
    ElMessage.error('加载失败')
  } finally {
    loading.value = false
  }
}

const viewDetail = async (record) => {
  try {
    const res = await api.getHistoryDetail(record.id)
    detailData.value = res
    detailTitle.value = `${getTypeName(res.type)} - ${res.created_at}`
    detailVisible.value = true
  } catch (error) {
    ElMessage.error('加载详情失败')
  }
}

const deleteRecord = async (record) => {
  try {
    await ElMessageBox.confirm('确定删除这条记录吗？', '提示', {
      confirmButtonText: '确定',
      cancelButtonText: '取消',
      type: 'warning'
    })
    await api.deleteHistory(record.id)
    ElMessage.success('删除成功')
    loadHistory()
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('删除失败')
    }
  }
}

onMounted(() => {
  loadHistory()
})
</script>

<style scoped>
.history-view {
  max-width: 1400px;
  margin: 0 auto;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-header h2 {
  margin: 0;
  font-size: 20px;
}

.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}

.code-block {
  background-color: #f5f7fa;
  padding: 12px;
  border-radius: 4px;
  font-family: monospace;
  font-size: 13px;
  white-space: pre-wrap;
  word-wrap: break-word;
  max-height: 300px;
  overflow: auto;
}
</style>