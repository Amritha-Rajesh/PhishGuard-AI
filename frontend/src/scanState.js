// State machine for the scan form: idle -> loading -> success | error. Pure, so it is easy to test.

export const initialScanState = { status: 'idle', result: null, error: null, submittedUrl: '' }

export function scanReducer(state, action) {
  switch (action.type) {
    case 'submit':
      if (state.status === 'loading') return state // ignore double clicks
      return { status: 'loading', result: null, error: null, submittedUrl: action.url }
    case 'success':
      return state.status === 'loading' ? { ...state, status: 'success', result: action.result } : state
    case 'failure':
      return state.status === 'loading' ? { ...state, status: 'error', error: action.error } : state
    case 'reset':
      return initialScanState
    default:
      return state
  }
}
