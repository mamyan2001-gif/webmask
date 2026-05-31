import { useMemo, useState } from "react";
import { faviconCandidates } from "../lib/favicon.js";

export default function SiteFavicon({ url, faviconUrl, size = 24, className = "" }) {
  const candidates = useMemo(() => faviconCandidates(url, faviconUrl), [url, faviconUrl]);
  const [index, setIndex] = useState(0);

  if (!candidates.length || index >= candidates.length) {
    return null;
  }

  return (
    <img
      src={candidates[index]}
      alt=""
      width={size}
      height={size}
      className={`site-favicon ${className}`.trim()}
      loading="lazy"
      decoding="async"
      onError={() => setIndex((i) => i + 1)}
    />
  );
}
