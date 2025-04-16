module.exports = {
  // Automatically clear mock calls, instances, contexts and results before every test
  clearMocks: true,

  // Indicates whether the coverage information should be collected while executing the test
  collectCoverage: true,

  // The directory where Jest should output its coverage files
  coverageDirectory: "coverage",

  // Indicates which provider should be used to instrument code for coverage
  coverageProvider: "v8",

  // A list of paths to directories that Jest should use to search for files in
  roots: [
    "<rootDir>/src",
    "<rootDir>/tests"
  ],

  // The test environment that will be used for testing
  testEnvironment: "node",

  // A map from regular expressions to paths to transformers
  transform: {},

  // The glob patterns Jest uses to detect test files
  testMatch: [
    "**/__tests__/**/*.[jt]s?(x)",
    "**/?(*.)+(spec|test).[jt]s?(x)"
  ],

  // An array of regexp pattern strings that are matched against all test paths, matched tests are skipped
  testPathIgnorePatterns: [
    "/node_modules/"
  ],

  // An array of regexp pattern strings that are matched against all source file paths, matched files will skip transformation
  transformIgnorePatterns: [
    "/node_modules/",
    "\\.pnp\\.[^\\/]+$"
  ],

  // Indicates whether each individual test should be reported during the run
  verbose: true,

  // An array of glob patterns indicating a set of files for which coverage information should be collected
  collectCoverageFrom: [
    "src/**/*.js",
    "!src/app.js",
    "!**/node_modules/**"
  ],

  // The minimum threshold enforcement for coverage results
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 70,
      lines: 70,
      statements: 70
    }
  },
};

