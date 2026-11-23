interface VersionDiffProps {
  unifiedDiff: string;
}

/** Renders a unified diff string (from `GET .../assessment/diff`) with
 * added/removed lines colored, the JSON-vs-JSON diff of two draft
 * versions, not a prose diff. */
export default function VersionDiff({ unifiedDiff }: VersionDiffProps): React.JSX.Element {
  const lines = unifiedDiff.split("\n");
  return (
    <pre className="card mono" style={{ overflowX: "auto", fontSize: 12 }} data-testid="version-diff">
      {lines.map((line, index) => {
        let className = "";
        if (line.startsWith("+") && !line.startsWith("+++")) {
          className = "diff-add";
        } else if (line.startsWith("-") && !line.startsWith("---")) {
          className = "diff-remove";
        }
        return (
          <div key={index} className={className}>
            {line || " "}
          </div>
        );
      })}
    </pre>
  );
}

