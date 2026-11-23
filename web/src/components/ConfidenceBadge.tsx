import type { Confidence } from "../api/client";

interface ConfidenceBadgeProps {
  confidence: Confidence | null | undefined;
}

// ◆ filled / ◇ hollow, three positions. Confidence is an epistemic
// gradient (how sure are we), not a discrete state, so it's rendered as
// visual weight (glyph fill + label weight/color) rather than the
// colored-pill treatment .badge uses for actual statuses below.
const GLYPHS: Record<Confidence, string> = {
  high: "◆◆◆",
  moderate: "◆◆◇",
  low: "◆◇◇",
};

/** For one of the backend's exact three confidence values. Never
 * renders free text ("likely", "probably", ...). Those words are legal
 * in prose but never in a confidence field (see assess/drafter.py). */
export default function ConfidenceBadge({ confidence }: ConfidenceBadgeProps): React.JSX.Element {
  if (!confidence) {
    return (
      <span className="confidence confidence--unattributed">
        <span className="confidence__glyphs" aria-hidden="true">
          ◇◇◇
        </span>
        <span className="confidence__label">unattributed</span>
      </span>
    );
  }
  return (
    <span className={`confidence confidence--${confidence}`}>
      <span className="confidence__glyphs" aria-hidden="true">
        {GLYPHS[confidence]}
      </span>
      <span className="confidence__label">{confidence}</span>
    </span>
  );
}

export function StatusBadge({ status }: { status: string }): React.JSX.Element {
  return <span className={`badge badge--${status}`}>{status.replace("_", " ")}</span>;
}

