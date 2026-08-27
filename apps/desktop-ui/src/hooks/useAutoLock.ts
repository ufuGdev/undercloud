import { useEffect, useState } from "react";
import type { Status } from "../commands";
import { AUTOLOCK_CHANGED_EVENT, AUTOLOCK_KEY } from "../app/types";

export function useAutoLock(status: Status, activityKey: string | number | null, onLocked: () => void) {
  const [settingTick, setSettingTick] = useState(0);

  useEffect(() => {
    const onSettingChanged = () => setSettingTick(tick => tick + 1);
    window.addEventListener(AUTOLOCK_CHANGED_EVENT, onSettingChanged);
    return () => window.removeEventListener(AUTOLOCK_CHANGED_EVENT, onSettingChanged);
  }, []);

  useEffect(() => {
    if (status.state !== "unlocked") return;
    const lockAfter = Number(localStorage.getItem(AUTOLOCK_KEY) ?? "0");
    if (!lockAfter) return;

    let timer = window.setTimeout(onLocked, lockAfter * 60_000);
    const reset = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(onLocked, lockAfter * 60_000);
    };
    window.addEventListener("pointerdown", reset);
    window.addEventListener("keydown", reset);
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener("pointerdown", reset);
      window.removeEventListener("keydown", reset);
    };
  }, [status.state, settingTick, activityKey, onLocked]);
}
