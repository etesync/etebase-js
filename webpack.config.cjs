const path = require("path");

module.exports = {
  entry: "./src/Etebase.ts",
  devtool: "source-map",
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: "ts-loader",
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: [".tsx", ".ts", ".js"],
    fallback: {
      "path": false,
      "fs": false,
      "crypto": false,
    }
  },
  output: {
    path: path.resolve(__dirname, "dist", "umd"),
    filename: "Etebase.js",
    libraryTarget: "umd",
    library: "Etebase",
    umdNamedDefine: true,
  },
  mode: "production",
};
