import { useQuery } from "@tanstack/react-query";
import ReactMarkdown from "react-markdown";
import { useParams } from "react-router-dom";
import remarkGfm from "remark-gfm";

import { ApiError, api } from "../api/client";

export default function ReportViewer(): React.JSX.Element {
  const { code } = useParams<{ code: string }>();

  const reportQuery = useQuery({
    queryKey: ["report", code],
    queryFn: () => api.getReport(code!),
    enabled: !!code,
    retry: false,
  });

  if (!code) {
    return <div className="callout callout--danger">No campaign code in URL.</div>;
  }

  if (reportQuery.isLoading) {
    return <p className="page-subtitle">Loading…</p>;
  }

  if (reportQuery.isError) {
    const isNotFound = reportQuery.error instanceof ApiError && reportQuery.error.status === 404;
    return (
      <div className="stack">
        <h1 className="page-title mono">{code}: Report</h1>
        <div className="callout callout--info">
          {isNotFound
            ? "This campaign has not been published yet. Run `lh report render` or `lh publish` for it."
            : "Failed to load the report."}
        </div>
      </div>
    );
  }

  const report = reportQuery.data;
  if (!report) {
    return <></>;
  }

  return (
    <div className="stack">
      <div className="row row--between">
        <h1 className="page-title mono">{code}: Report</h1>
        {report.has_pdf && report.pdf_url && (
          <a href={report.pdf_url} target="_blank" rel="noreferrer">
            <button type="button">Download PDF</button>
          </a>
        )}
      </div>
      <div className="card markdown-body">
        <ReactMarkdown remarkPlugins={[remarkGfm]}>{report.markdown ?? ""}</ReactMarkdown>
      </div>
    </div>
  );
}

