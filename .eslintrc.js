// module.exports = {
//     parser: '@typescript-eslint/parser',
//     parserOptions: {
//         project: 'tsconfig.json',
//         tsconfigRootDir: __dirname,
//         sourceType: 'module',
//     },
//     root: true,
//     env: {
//         node: true,
//         jest: true,
//     },
//     ignorePatterns: ['.eslintrc.js'],
//     // rules: { 'prettier/prettier': ['error', { endOfLine: 'auto' }] },
//     prettier: {
//         endOfLine: 'auto', // Change this value to 'lf' for LF line endings or 'crlf' for CRLF line endings
//     },
// };
module.exports = {
    parser: '@typescript-eslint/parser',
    parserOptions: {
        project: 'tsconfig.json',
        tsconfigRootDir: __dirname,
        sourceType: 'module',
    },
    plugins: ['@typescript-eslint', 'prettier'],
    extends: [
        'eslint:recommended', // добавляем базовые правила ESLint
        'plugin:@typescript-eslint/recommended', // добавляем правила TypeScript
        'plugin:prettier/recommended', // интеграция с Prettier
    ],
    root: true,
    env: {
        node: true,
        jest: true,
    },
    ignorePatterns: ['.eslintrc.js'],
    rules: {
        'prettier/prettier': ['error', { endOfLine: 'auto' }],
        '@typescript-eslint/no-explicit-any': 'off', // отключите ошибку, когда any
        // добавьте другие ваши правила здесь
    },
};
