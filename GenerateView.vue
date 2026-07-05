<template>
  <div class="generate-view">
    <el-row :gutter="20">
      <el-col :span="12">
        <el-card>
          <template #header>
            <div class="card-header">
              <h3>原始代码</h3>
              <el-radio-group v-model="language" size="small">
                <el-radio-button label="c">C</el-radio-button>
                <el-radio-button label="cpp">C++</el-radio-button>
                <el-radio-button label="python">Python</el-radio-button>
                <el-radio-button label="java">Java</el-radio-button>
                <el-radio-button label="go">Go</el-radio-button>
              </el-radio-group>
            </div>
          </template>
          <CodeEditor v-model="inputCode" :language="language" />
        </el-card>
      </el-col>

      <el-col :span="12">
        <el-card>
          <template #header>
            <div class="card-header">
              <h3>修复后的代码</h3>
              <el-button type="primary" size="small" @click="copyCode">
                复制代码
              </el-button>
            </div>
          </template>
          <CodeEditor v-model="fixedCode" :language="language" read-only />
        </el-card>
      </el-col>
    </el-row>

    <el-card class="action-card">
      <div class="action-bar">
        <el-button type="primary" @click="generate" :loading="isLoading">
          生成修复
        </el-button>
        <el-button @click="loadExample">加载示例</el-button>
        <el-button @click="clearCode">清空</el-button>
      </div>

      <div v-if="changes.length > 0" class="changes-section">
        <h4>修改内容：</h4>
        <el-timeline>
          <el-timeline-item
            v-for="(change, index) in changes"
            :key="index"
            :type="change.type === 'function_replacement' ? 'primary' : 'success'"
            :hollow="true"
          >
            {{ change.description }}
          </el-timeline-item>
        </el-timeline>
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
const fixedCode = ref('')
const changes = ref([])
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

const generate = async () => {
  if (!inputCode.value.trim()) {
    ElMessage.warning('请输入代码')
    return
  }

  isLoading.value = true
  try {
    await codeStore.generateFix()
    fixedCode.value = codeStore.fixedCode
    changes.value = codeStore.changes || []
    ElMessage.success('修复生成成功')
  } catch (error) {
    ElMessage.error('生成失败')
  } finally {
    isLoading.value = false
  }
}

const copyCode = () => {
  navigator.clipboard.writeText(fixedCode.value)
  ElMessage.success('已复制到剪贴板')
}

const loadExample = () => {
  inputCode.value = examples[language.value]
}

const clearCode = () => {
  inputCode.value = ''
  fixedCode.value = ''
  changes.value = []
}
</script>

<style scoped>
.generate-view {
  max-width: 1400px;
  margin: 0 auto;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-header h3 {
  margin: 0;
  font-size: 16px;
}

.action-card {
  margin-top: 20px;
}

.action-bar {
  display: flex;
  gap: 10px;
  margin-bottom: 20px;
}

.changes-section {
  margin-top: 20px;
}

.changes-section h4 {
  margin-bottom: 10px;
}
</style>