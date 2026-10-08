import type { ClientKeyEvent, ClientModule } from 'claude-code'

/**
 * The secure field. A surface module, so every key stays on the drawing side
 * (dots when masked) until Enter or Save posts the value once to the vault's
 * hooks module, through `ui.message`, which no other plugin sees.
 *
 * A surface does not hand a region the clipboard, so a paste (⌘V, Ctrl+V,
 * Shift+Insert or the Paste button) asks the hooks module to read the
 * clipboard itself: the pasted value stays there and only its length comes
 * back here, drawn as dots.
 *
 * States: idle (dim border, "click to type"), hovered (brighter border),
 * focused (accent border and caret), saving, and failed (red border). The
 * caret does not blink: a timer would redraw the whole region twice a second,
 * which the desktop shows as a flicker.
 */
type Props = { masked: boolean; placeholder: string; isFocused: boolean; error: string; pasted: number }
type State = { value: string; isRevealed: boolean; isSaving: boolean; seenError: string }

const NAMED_KEYS = new Set([
  'up', 'down', 'left', 'right', 'tab', 'pageup', 'pagedown', 'home', 'end', 'delete', 'insert', 'escape', 'enter', 'return', 'backspace',
])
const SHOWN = 48

const typed = (event: ClientKeyEvent): string => {
  if (event.ctrl || event.meta) return ''
  if (event.key === 'space') return ' '
  if (NAMED_KEYS.has(event.key) || /^f\d{1,2}$/.test(event.key)) return ''
  return event.key.replace(/[\r\n]/g, '')
}

const isPasteKey = (event: ClientKeyEvent): boolean =>
  ((event.meta === true || event.ctrl === true) && event.key.toLowerCase() === 'v') || (event.shift === true && event.key === 'insert')

const dots = (length: number): string => '•'.repeat(Math.min(length, SHOWN)) + (length > SHOWN ? ` +${length - SHOWN}` : '')

const Field: ClientModule<Props, State> = (props, surface) => {
  const { Box, Text, Button } = surface.elements
  const initial: State = { value: '', isRevealed: false, isSaving: false, seenError: props.error }
  const state = surface.state ?? initial
  const current = (): State => surface.state ?? state
  // A new error from the vault ends the saving state, so the person can try again.
  const isSaving = state.isSaving && state.seenError === props.error
  // What the field holds: what was typed, or else what was pasted.
  const isPasted = state.value === '' && props.pasted > 0

  const claimFocus = () => {
    if (!props.isFocused) surface.post({ type: 'focus' })
  }
  const paste = () => {
    surface.setState({ ...current(), value: '' })
    surface.post({ type: 'paste' })
  }
  const submit = () => {
    const now = current()
    surface.setState({ ...now, isSaving: true, seenError: props.error })
    surface.post({ type: 'submit', value: now.value, usePasted: now.value === '' && props.pasted > 0 })
  }

  surface.onPointer(event => {
    if (event.type === 'down') claimFocus()
  })
  surface.onKey(event => {
    claimFocus()
    const now = current()
    if (isPasteKey(event)) return paste()
    if (event.key === 'return' || event.key === 'enter') return submit()
    if (event.key === 'backspace') {
      if (now.value === '' && props.pasted > 0) return surface.post({ type: 'unpaste' })
      return surface.setState({ ...now, value: Array.from(now.value).slice(0, -1).join('') })
    }
    if (event.ctrl && event.key === 'u') {
      if (props.pasted > 0) surface.post({ type: 'unpaste' })
      return surface.setState({ ...now, value: '' })
    }
    const text = typed(event)
    if (!text) return
    if (props.pasted > 0) surface.post({ type: 'unpaste' })
    surface.setState({ ...now, value: now.value + text })
  })

  const length = isPasted ? props.pasted : Array.from(state.value).length
  const shown = isPasted || (props.masked && !state.isRevealed) ? dots(length) : state.value
  const border = props.error !== '' && !isSaving ? 'error' : isSaving ? 'success' : props.isFocused ? 'claude' : 'promptBorder'
  const caret = props.isFocused && !isSaving ? <Text color="claude">▍</Text> : <Text> </Text>

  return (
    <Box flexDirection="column">
      <Box
        key="box"
        borderStyle="round"
        borderColor={border}
        borderDimColor={!props.isFocused && props.error === ''}
        hover={{ borderColor: props.isFocused ? 'claude' : 'suggestion' }}
        paddingX={1}
      >
        <Text color={props.isFocused ? 'claude' : 'subtle'}>{'> '}</Text>
        {length > 0 && <Text>{shown}</Text>}
        {caret}
        {length === 0 && <Text dimColor>{props.isFocused ? props.placeholder : 'Click here, then paste or type'}</Text>}
      </Box>
      <Box gap={1} paddingLeft={1}>
        <Button key="save" label={isSaving ? 'Saving…' : 'Save'} variant="primary" onPress={submit} />
        <Button key="paste" label="Paste" onPress={paste} />
        {props.masked && !isPasted && (
          <Button
            key="reveal"
            label={state.isRevealed ? 'Hide' : 'Show'}
            onPress={() => surface.setState({ ...current(), isRevealed: !current().isRevealed })}
          />
        )}
        <Button key="cancel" label="Cancel" onPress={() => surface.post({ type: 'cancel' })} />
        {length > 0 && props.masked && <Text dimColor>{isPasted ? `${length} chars pasted` : `${length} chars`}</Text>}
      </Box>
    </Box>
  )
}

export default Field
