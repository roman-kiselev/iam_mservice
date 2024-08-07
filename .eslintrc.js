module.exports = {
  parser: '@typescript-eslint/parser',
  parserOptions: {
    project: 'tsconfig.json',
    tsconfigRootDir: __dirname,
    sourceType: 'module',
  },
  plugins: ['prettier'],
  extends: ['prettier'],
  root: true,
  env: {
    node: true,
    jest: true,
  },
  ignorePatterns: ['.eslintrc.js'],
  rules: { 'prettier/prettier': ['error', { endOfLine: 'auto' }] },
  prettier: {
    endOfLine: 'auto', // Change this value to 'lf' for LF line endings or 'crlf' for CRLF line endings
  },
};
