/// Vitest setup file — runs before each test file.
///
/// Imports `@testing-library/jest-dom` to register custom matchers like
/// `toBeInTheDocument`, `toHaveTextContent`, etc. that the SSO callback
/// tests rely on.
import '@testing-library/jest-dom/vitest'
