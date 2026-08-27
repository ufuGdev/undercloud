import { useEffect, useId, useRef, useState } from "react";
import { Check, ChevronDown } from "lucide-react";

export type SelectOption = { value: string; label: string; disabled?: boolean };

export function Select({ label, value, options, onChange, disabled }: { label: string; value: string; options: SelectOption[]; onChange: (value: string) => void; disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  const [flip, setFlip] = useState(false);
  const [active, setActive] = useState(Math.max(0, options.findIndex(option => option.value === value)));
  const id = useId();
  const ref = useRef<HTMLDivElement>(null);
  const selected = options.find(option => option.value === value);
  useEffect(() => { const close = (event: PointerEvent) => { if (!ref.current?.contains(event.target as Node)) setOpen(false); }; document.addEventListener("pointerdown", close); return () => document.removeEventListener("pointerdown", close); }, []);
  useEffect(() => { setActive(Math.max(0, options.findIndex(option => option.value === value))); }, [options, value]);
  useEffect(() => { if (!open || !ref.current) return; const box = ref.current.getBoundingClientRect(); setFlip(window.innerHeight - box.bottom < 260); }, [open]);
  const choose = (index: number) => { const option = options[index]; if (!option || option.disabled) return; onChange(option.value); setActive(index); setOpen(false); };
  return <div className="undercloud-select" ref={ref}>
    <span className="select-label" id={`${id}-label`}>{label}</span>
    <button type="button" className="select-trigger" aria-labelledby={`${id}-label`} aria-haspopup="listbox" aria-expanded={open} disabled={disabled} onClick={() => setOpen(current => !current)} onKeyDown={event => {
      if (event.key === "Escape") setOpen(false);
      if (event.key === "ArrowDown") { event.preventDefault(); setOpen(true); setActive(current => Math.min(options.length - 1, current + 1)); }
      if (event.key === "ArrowUp") { event.preventDefault(); setOpen(true); setActive(current => Math.max(0, current - 1)); }
      if (event.key === "Enter" && open) { event.preventDefault(); choose(active); }
    }}><span>{selected?.label ?? "Select"}</span><ChevronDown size={16} aria-hidden="true" /></button>
    {open && <div className={`select-menu ${flip ? "flip" : ""}`} role="listbox" aria-labelledby={`${id}-label`} tabIndex={-1}>{options.map((option, index) => <button type="button" role="option" aria-selected={option.value === value} disabled={option.disabled} className={`select-option ${index === active ? "active" : ""}`} key={option.value} onMouseEnter={() => setActive(index)} onClick={() => choose(index)}><span>{option.label}</span>{option.value === value && <Check size={15} aria-hidden="true" />}</button>)}</div>}
  </div>;
}
