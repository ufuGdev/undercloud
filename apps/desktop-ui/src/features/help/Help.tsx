import { Page } from "../../components/ui/Page";

export function Help() {
  return <Page title="Help" subtitle="Simple answers for keeping your vault protected."><div className="help-grid">
    <div className="form-card compact-form-card"><h2>How encryption works</h2><p>Undercloud encrypts file contents and metadata on your device. Storage providers receive opaque objects, not filenames or file contents.</p></div>
    <div className="form-card compact-form-card"><h2>Protection states</h2><p><strong>Protected</strong> means every connected target has a verified copy — one target means a single encrypted copy, two means a mirrored pair. <strong>Degraded</strong> means one is unavailable but restoration is still possible. Repair it when storage returns.</p></div>
    <div className="form-card compact-form-card"><h2>Recovery kits</h2><p>A kit rebuilds catalog information; it is not a copy of your files. Keep it separate and current.</p></div>
    <div className="form-card compact-form-card"><h2>Need more help?</h2><p>Use the Recovery and Storage pages for guided actions. Advanced provider details are kept there instead of on the main screen.</p></div>
  </div></Page>;
}
