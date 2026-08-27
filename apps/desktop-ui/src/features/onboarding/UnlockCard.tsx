export function UnlockCard({ password, setPassword, onUnlock, onOpen }: {
  password: string;
  setPassword: (value: string) => void;
  onUnlock: () => void;
  onOpen: () => void;
}) {
  return <section className="welcome-card">
    <div className="welcome-mark">U</div>
    <p className="eyebrow">Welcome back</p>
    <h2>Unlock your private vault</h2>
    <p>Your files are encrypted on this device before they reach storage.</p>
    <label>Password
      <input autoFocus type="password" value={password} onChange={event => setPassword(event.target.value)}
        onKeyDown={event => { if (event.key === "Enter" && password) onUnlock(); }} autoComplete="current-password" />
    </label>
    <button className="button primary wide" disabled={!password} onClick={onUnlock}>Unlock vault</button>
    <button className="button text-button" onClick={onOpen}>Open a different vault</button>
  </section>;
}
