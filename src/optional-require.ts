if ((global as any).__non_webpack_require__ === undefined) {
  // eslint-disable-next-line
  (global as any).__non_webpack_require__ = require;
}

const optionalRequire = (global as any).__non_webpack_require__;

export default optionalRequire;
