import { createTheme } from '@mui/material/styles'

export const lightTheme = createTheme({
  palette: {
    mode: 'light',
    primary:   { main: '#1565C0' },
    secondary: { main: '#0288D1' },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
  },
})

export const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary:   { main: '#42A5F5' },
    secondary: { main: '#26C6DA' },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
  },
})
