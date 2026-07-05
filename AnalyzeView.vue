<template>
  <div class="analyze-view">
    <el-card>
      <template #header>
        <div class="card-header">
          <h2>漏洞分析</h2>
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
        <el-button type="primary" @click="analyze" :loading="isLoading">
          开始分析
        </el-button>
        <el-button @click="loadExample">加载示例</el-button>
        <el-button @click="clearCode">清空</el-button>
      </div>

      <div v-if="vulnerabilities.length > 0" class="result-section">
        <h3>分析结果</h3>
        <el-table :data="vulnerabilities" stripe style="width: 100%">
          <el-table-column prop="vulnerability_type" label="漏洞类型" width="180" />
          <el-table-column prop="confidence" label="置信度" width="100">
            <template #default="scope">
              <el-tag :type="getConfidenceType(scope.row.confidence)">
                {{ (scope.row.confidence * 100).toFixed(0) }}%
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="affected_lines" label="影响行数" width="100">
            <template #default="scope">
              <el-tag size="small">{{ scope.row.affected_lines.join(', ') }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="root_cause" label="根本原因" />
          <el-table-column prop="cwe_id" label="CWE编号" width="100" />
        </el-table>
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
const vulnerabilities = ref(codeStore.vulnerabilities)
const isLoading = ref(false)

// 示例代码
const examples = {
  c: `#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[10];
    strcpy(buffer, input);
    printf("Buffer: %s\\n", buffer);
}

int main() {
    char user_input[100];
    printf("Enter input: ");
    gets(user_input);
    vulnerable_function(user_input);
    return 0;
}`,
  cpp: `#include <iostream>
#include <cstring>

void vulnerable_function(char *input) {
    char buffer[10];
    strcpy(buffer, input);
    std::cout << "Buffer: " << buffer << std::endl;
}

int main() {
    char user_input[100];
    std::cout << "Enter input: ";
    std::cin >> user_input;
    vulnerable_function(user_input);
    return 0;
}`,
  python: `import os

def vulnerable_function(user_input):
    os.system("echo " + user_input)
    eval(user_input)
    return user_input

user_data = input("Enter data: ")
result = vulnerable_function(user_data)
print(result)`,
  java: `import java.io.*;

public class VulnerableClass {
    public void unsafeMethod(String userInput) {
        try {
            Runtime.getRuntime().exec("cmd /c " + userInput);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    public static void main(String[] args) {
        VulnerableClass obj = new VulnerableClass();
        obj.unsafeMethod(args[0]);
    }
}`,
  go: `package main

import (
    "fmt"
    "os/exec"
)

func vulnerableFunction(userInput string) {
    // 命令注入漏洞
    cmd := exec.Command("sh", "-c", "echo "+userInput)
    err := cmd.Run()
    if err != nil {
        return
    }
}

func main() {
    var input string
    fmt.Scanln(&input)
    vulnerableFunction(input)
}`
}

watch([inputCode, language], () => {
  codeStore.setInputCode(inputCode.value)
  codeStore.setLanguage(language.value)
})

const analyze = async () => {
  if (!inputCode.value.trim()) {
    ElMessage.warning('请输入代码')
    return
  }

  isLoading.value = true
  try {
    await codeStore.analyzeCode()
    vulnerabilities.value = codeStore.vulnerabilities
    ElMessage.success('分析完成')
  } catch (error) {
    ElMessage.error('分析失败')
  } finally {
    isLoading.value = false
  }
}

const loadExample = () => {
  inputCode.value = examples[language.value]
}

const clearCode = () => {
  inputCode.value = ''
  vulnerabilities.value = []
}

const getConfidenceType = (confidence) => {
  if (confidence >= 0.8) return 'danger'
  if (confidence >= 0.5) return 'warning'
  return 'info'
}
</script>

<style scoped>
.analyze-view {
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
}

.result-section h3 {
  margin-bottom: 15px;
}
</style>