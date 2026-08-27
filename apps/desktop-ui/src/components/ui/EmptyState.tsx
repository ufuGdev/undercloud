export function EmptyState({ title, body }: { title: string; body: string }) {
  return <div className="empty"><div className="empty-icon" aria-hidden="true">◇</div><h3>{title}</h3><p>{body}</p></div>;
}
