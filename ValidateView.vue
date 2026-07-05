<template>
  <div class="validate-view">
    <el-card>
      <template #header>
        <div class="card-header">
          <h2>代码验证</h2>
          <el-radio-group v-model="language" size="small">
            <el-radio-button label="c">C</el-radio-button>
            <el-radio-button label="cpp">C++</el-radio-button>
            <el-radio-button label="python">Python</el-radio-button>
            <el-radio-button label="java">Java</el-radio-button>
            <el-radio-button label="go">Go</el-radio-button>
          </el-radio-group>
        </div>
      </template>

      <div class="editor-section">
        <CodeEditor v-model="inputCode" :language="language" />
      </div>

      <div class="action-bar">
        <el-button type="primary" @click="validate" :loading="isLoading">
          开始验证
        </el-button>
        <el-button @click="loadExample">加载示例</el-button>
        <el-button @click="clearCode">清空</el-button>
      </div>

      <div v-if="validationResult" class="result-section">
        <el-result
          :icon="validationResult.passed ? 'success' : 'error'"
          :title="validationResult.passed ? '验证通过' : '验证失败'"
          :sub-title="validationResult.passed ? '代码安全无漏洞' : '发现安全问题'"
        >
          <template #extra>
            <div class="result-details">
              <el-descriptions :column="1" border>
                <el-descriptions-item label="编译状态">
                  <el-tag :type="validationResult.compile_success ? 'success' : 'danger'">
                    {{ validationResult.compile_success ? '成功' : '失败' }}
                  </el-tag>
                </el-descriptions-item>
                
                <el-descriptions-item label="安全问题">
                  <div v-if="validationResult.security_issues.length > 0">
                    <el-tag
                      v-for="issue in validationResult.security_issues"
                      :key="issue"
                      type="danger"
                      size="small"
                      style="margin-right: 5px; margin-bottom: 5px"
                    >
                      {{ issue }}
                    </el-tag>
                  </div>
                  <span v-else>未发现</span>
                </el-descriptions-item>
              </el-descriptions>

              <el-collapse class="test-results">
                <el-collapse-item title="测试结果详情">
                  <el-table :data="validationResult.test_results" stripe>
                    <el-table-column prop="name" label="测试名称" />
                    <el-table-column prop="passed" label="结果" width="100">
                      <template #default="scope">
                        <el-tag :type="scope.row.passed ? 'success' : 'danger'">
                          {{ scope.row.passed ? '通过' : '失败' }}
                        </el-tag>
                      </template>
                    </el-table-column>
                    <el-table-column prop="output" label="输出信息" />
                  </el-table>
                </el-collapse-item>
              </el-collapse>
            </div>
          </template>
        </el-result>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import CodeEditor from '../components/CodeEditor.vue'
import { useCodeStore } from '../stores/codeStore'

const codeStore = useCodeStore()

const inputCode = ref(codeStore.inputCode)
const language = ref(codeStore.language)
const validationResult = ref(null)
const isLoading = ref(false)

// 示例代码
const examples = {
  c: `#include <stdio.h>
#include <string.h>

void safe_function(char *input) {
    char buffer[10];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
    printf("Buffer: %s\\n", buffer);
}

int main() {
    char user_input[100];
    printf("Enter input: ");
    fgets(user_input, sizeof(user_input), stdin);
    safe_function(user_input);
    return 0;
}`,
  cpp: `#include <iostream>
#include <cstring>

void safe_function(char *input) {
    char buffer[10];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
    std::cout << "Buffer: " << buffer << std::endl;
}

int main() {
    char user_input[100];
    std::cout << "Enter input: ";
    std::cin.getline(user_input, 100);
    safe_function(user_input);
    return 0;
}`,
  python: `import subprocess

def safe_function(user_input):
    # 使用参数列表避免命令注入
    subprocess.run(["echo", user_input])
    return user_input

user_data = input("Enter data: ")
result = safe_function(user_data)
print(result)`,
  java: `import java.io.*;

public class SafeClass {
    public void safeMethod(String userInput) {
        try {
            // 使用 ProcessBuilder 并传递参数列表
            ProcessBuilder pb = new ProcessBuilder("echo", userInput);
            pb.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public static void main(String[] args) {
        SafeClass obj = new SafeClass();
        obj.safeMethod(args[0]);
    }
}`,
  go: `package main

import (
    "fmt"
    "os/exec"
)

func safeFunction(userInput string) {
    // 使用参数列表避免命令注入
    cmd := exec.Command("echo", userInput)
    err := cmd.Run()
    if err != nil {
        fmt.Println("Error:", err)
    }
}

func main() {
    var input string
    fmt.Scanln(&input)
    safeFunction(input)
}`
}

watch([inputCode, language], () => {
  codeStore.setInputCode(inputCode.value)
  codeStore.setLanguage(language.value)
})

const validate = async () => {
  if (!inputCode.value.trim()) {
    ElMessage.warning('请输入代码')
    return
  }

  isLoading.value = true
  try {
    await codeStore.validateCode()
    validationResult.value = codeStore.validationResult
    ElMessage.success('验证完成')
  } catch (error) {
    ElMessage.error('验证失败')
  } finally {
    isLoading.value = false
  }
}

const loadExample = () => {
  inputCode.value = examples[language.value]
}

const clearCode = () => {
  inputCode.value = ''
  validationResult.value = null
}
</script>

<style scoped>
.validate-view {
  max-width: 1200px;
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

.editor-section {
  margin-bottom: 20px;
}

.action-bar {
  margin-bottom: 20px;
  display: flex;
  gap: 10px;
}

.result-section {
  margin-top: 20px;
  padding: 20px;
  background-color: #f9f9f9;
  border-radius: 4px;
}

.result-details {
  margin-top: 20px;
  text-align: left;
}

.test-results {
  margin-top: 20px;
}
</style>