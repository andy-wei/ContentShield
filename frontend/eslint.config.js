/** ESLint flat config（v9）。 */
import js from '@eslint/js'
import typescript from 'typescript-eslint'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'

export default typescript.config(
  {
    ignores: ['dist/**', 'node_modules/**', '*.config.ts', '*.config.js'],
  },
  js.configs.recommended,
  ...typescript.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],
      // 允许 any 在迁移期（项目里有 as never 等绕过点）
      '@typescript-eslint/no-explicit-any': 'off',
      // 空函数体允许（hooks 占位）
      '@typescript-eslint/no-empty-function': 'off',
    },
  },
)
