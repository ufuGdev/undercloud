import type { PageProps } from "../../app/types";

export function Page({ title, subtitle, children }: PageProps) {
  return <section className="page">
    <div className="page-heading"><h1 className="page-title">{title}</h1>{subtitle && <p className="page-subtitle">{subtitle}</p>}</div>
    {children}
  </section>;
}
