const optionalRequire = (global as any).__non_webpack_require__ ?? require;

export default optionalRequire;
