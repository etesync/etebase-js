module.exports = {
  presets: [
    ['@babel/preset-env', {
      useBuiltIns: "usage",
      corejs: { version: 3, proposals: true },
    }],
    '@babel/preset-typescript',
  ],
  plugins: [
    '@babel/plugin-proposal-class-properties',
    '@babel/transform-runtime',
    'syntax-async-functions',
  ],
};
