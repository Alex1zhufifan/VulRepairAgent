<template>
  <div ref="editorContainer" class="editor-container"></div>
</template>

<script setup>
import { ref, onMounted, onBeforeUnmount, watch } from 'vue'
import * as monaco from 'monaco-editor'

const props = defineProps({
  modelValue: {
    type: String,
    default: ''
  },
  language: {
    type: String,
    default: 'cpp'
  },
  readOnly: {
    type: Boolean,
    default: false
  }
})

const emit = defineEmits(['update:modelValue'])

const editorContainer = ref(null)
let editor = null

onMounted(() => {
  editor = monaco.editor.create(editorContainer.value, {
    value: props.modelValue,
    language: props.language,
    theme: 'vs-dark',
    automaticLayout: true,
    minimap: { enabled: false },
    fontSize: 14,
    readOnly: props.readOnly
  })

  editor.onDidChangeModelContent(() => {
    emit('update:modelValue', editor.getValue())
  })
})

onBeforeUnmount(() => {
  if (editor) {
    editor.dispose()
  }
})

watch(() => props.language, (newLang) => {
  if (editor) {
    monaco.editor.setModelLanguage(editor.getModel(), newLang)
  }
})

watch(() => props.modelValue, (newValue) => {
  if (editor && newValue !== editor.getValue()) {
    editor.setValue(newValue)
  }
})
</script>

<style scoped>
.editor-container {
  width: 100%;
  height: 400px;
  border: 1px solid #ddd;
  border-radius: 4px;
  overflow: hidden;
}
</style>