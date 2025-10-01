module.exports = {
  env: {
    browser: true,
    commonjs: true,
    es2021: true,
    node: true,
    jest: true
  },
  extends: [
    'eslint:recommended'
  ],
  parserOptions: {
    ecmaVersion: 12,
    sourceType: 'module'
  },
  rules: {
    // Security rules
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'no-new-func': 'error',
    'no-script-url': 'error',
    'no-alert': 'error',
    'no-console': 'warn',

    // Best practices
    'eqeqeq': 'error',
    'no-var': 'error',
    'prefer-const': 'error',
    'no-unused-vars': 'error',
    'no-undef': 'error',
    'no-redeclare': 'error',
    'no-duplicate-imports': 'error',

    // Code quality
    'indent': ['error', 2],
    'quotes': ['error', 'single'],
    'semi': ['error', 'always'],
    'comma-dangle': ['error', 'never'],
    'object-curly-spacing': ['error', 'always'],
    'array-bracket-spacing': ['error', 'never'],
    'space-before-function-paren': ['error', 'never'],
    'keyword-spacing': 'error',
    'space-infix-ops': 'error',
    'eol-last': 'error',
    'no-trailing-spaces': 'error',
    'no-multiple-empty-lines': ['error', { max: 2 }],

    // Node.js specific
    'no-process-exit': 'error',
    'no-path-concat': 'error',
    'no-new-require': 'error',
    'no-mixed-requires': 'error',
    'handle-callback-err': 'error',
    'no-sync': 'warn'
  },
  globals: {
    process: 'readonly',
    Buffer: 'readonly',
    __dirname: 'readonly',
    __filename: 'readonly',
    global: 'readonly',
    module: 'readonly',
    require: 'readonly',
    exports: 'readonly'
  }
};
