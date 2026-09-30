import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { api } from "../services/api";

import type {
  AlertDetail as AlertDetailType,
  Investigation,
  ResponseAction,
} from "../types/api";

import SeverityBadge from "../components/SeverityBadge";
import DispositionBadge from "../components/DispositionBadge";
import ReputationBadge from "../components/ReputationBadge";
import SourceBadge from "../components/SourceBadge";
import EnrichmentStatusBadge from "../components/EnrichmentStatusBadge";
import Panel from "../components/Panel";


export default function AlertDetail() {
  const { id } = useParams<{ id: string }>();

  // Used by the Back to Dashboard button.
  const navigate = useNavigate();

  const [alert, setAlert] = useState<AlertDetailType | null>(null);

  const [investigation, setInvestigation] =
    useState<Investigation | null>(null);

  const [actions, setActions] =
    useState<ResponseAction[]>([]);

  const [investigating, setInvestigating] =
    useState(false);

  const [error, setError] =
    useState<string | null>(null);

  const [reportFormat, setReportFormat] =
    useState<"analyst" | "customer">("analyst");

  const [reportMarkdown, setReportMarkdown] =
    useState<string | null>(null);

  const [reportLoading, setReportLoading] =
    useState(false);


  // ============================================================
  // LOAD ALERT
  // ============================================================

  const loadAlert = () => {
    if (!id) return;

    api
      .getAlert(id)
      .then(setAlert)
      .catch((e) => setError(String(e)));
  };


  useEffect(loadAlert, [id]);


  // ============================================================
  // RUN INVESTIGATION
  // ============================================================

  const runInvestigation = async () => {
    if (!id) return;

    setInvestigating(true);
    setError(null);

    try {
      const result =
        await api.investigateAlert(id);

      setInvestigation(result);

      // Refresh alert status and enrichment.
      loadAlert();

      const actionsResult =
        await api
          .listResponseActions(result.id)
          .catch(() => []);

      setActions(actionsResult);
    } catch (e) {
      setError(String(e));
    } finally {
      setInvestigating(false);
    }
  };


  // ============================================================
  // LOAD REPORT
  // ============================================================

  const loadReport = async (
    format: "analyst" | "customer"
  ) => {
    if (!investigation) return;

    setReportFormat(format);
    setReportLoading(true);

    try {
      const result =
        await api.getInvestigationReport(
          investigation.id,
          format
        );

      setReportMarkdown(
        result.report_markdown
      );
    } catch (e) {
      setError(String(e));
    } finally {
      setReportLoading(false);
    }
  };


  // ============================================================
  // RESPONSE APPROVAL
  // ============================================================

  const respond = async (
    decision: "approve" | "reject"
  ) => {
    if (!investigation) return;

    const updated =
      decision === "approve"
        ? await api.approveResponse(
            investigation.id
          )
        : await api.rejectResponse(
            investigation.id
          );

    setActions(updated);
  };


  // ============================================================
  // LOADING STATE
  // ============================================================

  if (!alert) {
    return (
      <div className="text-slate-500 text-sm">
        {error ?? "Loading…"}
      </div>
    );
  }


  const investigationFailed =
    alert.status === "investigation_failed";


  // ============================================================
  // PAGE
  // ============================================================

  return (
    <div className="space-y-6">

      {/* ======================================================
          BACK BUTTON
      ====================================================== */}

      <button
        type="button"
        onClick={() => navigate("/alerts")}
        className="
          inline-flex
          items-center
          gap-2
          text-sm
          text-slate-400
          hover:text-white
          transition-colors
          duration-150
        "
      >
        <span className="text-lg leading-none">
          ←
        </span>

        <span>
          Back to Dashboard
        </span>
      </button>


      {/* ======================================================
          ALERT HEADER
      ====================================================== */}

      <div className="flex items-start justify-between">

        <div>
          <h2 className="text-xl font-semibold">
            {alert.alert_name}
          </h2>

          <div className="text-sm text-slate-500 mt-1">
            {alert.alert_id}
            {" · "}
            {alert.source}
            {" · "}
            {new Date(
              alert.timestamp
            ).toLocaleString()}
          </div>
        </div>


        <div className="flex items-center gap-2">

          <span className="text-xs text-slate-500 uppercase">
            {alert.status.replace("_", " ")}
          </span>

          <SeverityBadge
            severity={alert.severity}
          />

        </div>

      </div>


      {/* ======================================================
          ALERT DETAILS
      ====================================================== */}

      <Panel title="Alert Details">

        <dl className="
          grid
          grid-cols-2
          md:grid-cols-3
          gap-x-6
          gap-y-3
          text-sm
        ">

          <Field
            label="Hostname"
            value={alert.hostname}
          />

          <Field
            label="User"
            value={alert.user}
          />

          <Field
            label="Source IP"
            value={alert.source_ip}
            mono
          />

          <Field
            label="Destination IP"
            value={alert.destination_ip}
            mono
          />

          <Field
            label="Domain"
            value={alert.domain}
            mono
          />

          <Field
            label="File Hash"
            value={alert.file_hash}
            mono
          />

        </dl>


        {alert.command_line && (

          <div className="mt-3">

            <div className="
              text-xs
              text-slate-500
              mb-1
            ">
              Command line
            </div>

            <code className="
              block
              bg-slate-950
              border
              border-slate-800
              rounded
              p-2
              text-xs
              break-all
            ">
              {alert.command_line}
            </code>

          </div>

        )}


        {alert.description && (

          <p className="
            mt-3
            text-sm
            text-slate-300
          ">
            {alert.description}
          </p>

        )}

      </Panel>


      {/* ======================================================
          EXTRACTED IOCS
      ====================================================== */}

      <Panel
        title={`Extracted IOCs (${alert.iocs.length})`}
      >

        <div className="space-y-2">

          {alert.iocs.map((ioc) => (

            <div
              key={ioc.id}
              className="
                flex
                items-center
                justify-between
                gap-3
                flex-wrap
                border
                border-slate-800
                rounded
                p-2
                text-sm
              "
            >

              <div className="min-w-0">

                <span className="
                  text-xs
                  text-slate-500
                  uppercase
                  mr-2
                ">
                  {ioc.ioc_type}
                </span>

                <span className="font-mono">
                  {ioc.value}
                </span>

              </div>


              <div className="
                flex
                items-center
                gap-2
                text-xs
                text-slate-400
                shrink-0
              ">

                <EnrichmentStatusBadge
                  status={
                    ioc.enrichment?.status ??
                    "pending"
                  }
                />


                {ioc.enrichment && (
                  <>

                    <SourceBadge
                      source={
                        ioc.enrichment.source
                      }
                    />

                    <ReputationBadge
                      reputation={
                        ioc.enrichment.reputation
                      }
                    />


                    {ioc.enrichment
                      .malicious_count !== null && (

                      <span>
                        M:
                        {
                          ioc.enrichment
                            .malicious_count
                        }
                        /S:
                        {
                          ioc.enrichment
                            .suspicious_count
                        }
                        /H:
                        {
                          ioc.enrichment
                            .harmless_count
                        }
                      </span>

                    )}

                  </>
                )}

              </div>

            </div>

          ))}


          {alert.iocs.length === 0 && (

            <span className="
              text-sm
              text-slate-500
            ">
              None extracted.
            </span>

          )}

        </div>

      </Panel>


      {/* ======================================================
          INVESTIGATION FAILURE
      ====================================================== */}

      {investigationFailed && (

        <div className="
          text-sm
          border
          border-red-900
          bg-red-950/40
          text-red-300
          rounded-md
          px-3
          py-2
        ">

          The last investigation attempt failed
          unexpectedly. The alert itself was not
          affected — you can try running the
          investigation again.

        </div>

      )}


      {/* ======================================================
          RUN INVESTIGATION BUTTON
      ====================================================== */}

      {!investigation && (

        <button
          onClick={runInvestigation}
          disabled={investigating}
          className="
            bg-blue-600
            hover:bg-blue-500
            disabled:opacity-50
            text-white
            text-sm
            font-medium
            px-4
            py-2
            rounded
          "
        >

          {investigating
            ? "Running investigation…"
            : investigationFailed
            ? "Retry Investigation"
            : "Run AI Investigation"}

        </button>

      )}


      {error && (

        <div className="
          text-sm
          text-red-400
        ">
          {error}
        </div>

      )}


      {/* ======================================================
          INVESTIGATION RESULT
      ====================================================== */}

      {investigation && (
        <>

          <Panel
            title="AI Investigation"
            right={

              <span className="
                text-xs
                text-slate-500
              ">

                {investigation.llm_used
                  ? "LLM-authored summary"
                  : "Deterministic summary (no LLM configured)"}

              </span>

            }
          >

            <div className="
              flex
              flex-wrap
              items-center
              gap-3
              mb-3
            ">

              <SeverityBadge
                severity={
                  investigation.severity
                }
              />

              <DispositionBadge
                disposition={
                  investigation.disposition
                }
              />


              <span className="
                text-sm
                text-slate-400
              ">

                Risk score:{" "}

                <span className="
                  text-slate-200
                  font-medium
                ">
                  {investigation.risk_score}
                  /100
                </span>

              </span>


              <span className="
                text-sm
                text-slate-400
              ">

                Confidence:{" "}

                {Math.round(
                  investigation.confidence *
                    100
                )}
                %

              </span>


              {investigation
                .requires_customer_validation && (

                <span className="
                  text-xs
                  px-2
                  py-0.5
                  rounded
                  border
                  border-amber-800
                  bg-amber-950
                  text-amber-300
                ">

                  Requires customer validation

                </span>

              )}

            </div>


            <p className="
              text-sm
              text-slate-300
              mb-3
            ">

              {investigation.summary}

            </p>


            {/* FINDINGS */}

            {investigation.findings.length >
              0 && (

              <div className="space-y-2">

                <div className="
                  text-xs
                  uppercase
                  text-slate-500
                ">
                  Findings (evidence-backed)
                </div>


                {investigation.findings.map(
                  (f, i) => (

                    <div
                      key={i}
                      className="
                        text-sm
                        bg-slate-950
                        border
                        border-slate-800
                        rounded
                        p-2
                      "
                    >

                      <div className="
                        text-slate-200
                      ">
                        {f.statement}
                      </div>


                      <ul className="
                        mt-1
                        list-disc
                        list-inside
                        text-xs
                        text-slate-500
                      ">

                        {f.evidence.map(
                          (e, j) => (

                            <li key={j}>
                              {e}
                            </li>

                          )
                        )}

                      </ul>

                    </div>

                  )
                )}

              </div>

            )}

          </Panel>


          {/* ==================================================
              MITRE MAPPINGS
          ================================================== */}

          <div className="
            grid
            md:grid-cols-2
            gap-4
          ">


            {/* MITRE ATT&CK */}

            <Panel
              title="
                Traditional Security Mapping — MITRE ATT&CK
              "
            >

              {investigation
                .attack_techniques.length ===
                0 && (

                <div className="
                  text-sm
                  text-slate-500
                ">
                  No ATT&CK techniques matched.
                </div>

              )}


              <div className="space-y-2">

                {investigation
                  .attack_techniques
                  .map((t) => (

                    <div
                      key={t.technique_id}
                      className="
                        text-sm
                        border
                        border-slate-800
                        rounded
                        p-2
                      "
                    >

                      <div className="
                        font-medium
                      ">

                        {t.technique_id}
                        {" — "}
                        {t.name}

                      </div>


                      <div className="
                        text-xs
                        text-slate-500
                      ">
                        {t.tactic}
                      </div>

                    </div>

                  ))}

              </div>

            </Panel>


            {/* MITRE ATLAS */}

            <Panel
              title="
                AI Security Mapping — MITRE ATLAS
              "
            >

              {investigation
                .atlas_techniques.length ===
                0 ? (

                <div className="
                  text-sm
                  text-slate-500
                ">

                  No ATLAS mapping identified
                  from the collected evidence.

                </div>

              ) : (

                <div className="space-y-2">

                  {investigation
                    .atlas_techniques
                    .map((t) => (

                      <div
                        key={t.technique_id}
                        className="
                          text-sm
                          border
                          border-slate-800
                          rounded
                          p-2
                        "
                      >

                        <div className="
                          font-medium
                        ">

                          {t.technique_id}
                          {" — "}
                          {t.name}

                        </div>


                        <div className="
                          text-xs
                          text-slate-500
                        ">
                          {t.tactic}
                        </div>

                      </div>

                    ))}

                </div>

              )}

            </Panel>

          </div>


          {/* ==================================================
              INVESTIGATION REPORT
          ================================================== */}

          <Panel
            title="Investigation Report"
            right={

              <div className="flex gap-1">

                <button
                  onClick={() =>
                    loadReport("analyst")
                  }
                  className={`
                    text-xs
                    px-2
                    py-1
                    rounded
                    ${
                      reportFormat ===
                      "analyst"
                        ? "bg-blue-600 text-white"
                        : "bg-slate-800 text-slate-300"
                    }
                  `}
                >
                  Analyst
                </button>


                <button
                  onClick={() =>
                    loadReport("customer")
                  }
                  className={`
                    text-xs
                    px-2
                    py-1
                    rounded
                    ${
                      reportFormat ===
                      "customer"
                        ? "bg-blue-600 text-white"
                        : "bg-slate-800 text-slate-300"
                    }
                  `}
                >
                  Customer Escalation
                </button>

              </div>

            }
          >

            {!reportMarkdown &&
              !reportLoading && (

              <button
                onClick={() =>
                  loadReport("analyst")
                }
                className="
                  text-sm
                  text-blue-400
                  hover:underline
                "
              >
                Generate report
              </button>

            )}


            {reportLoading && (

              <div className="
                text-sm
                text-slate-500
              ">
                Generating…
              </div>

            )}


            {reportMarkdown && (

              <pre className="
                text-xs
                whitespace-pre-wrap
                font-mono
                bg-slate-950
                border
                border-slate-800
                rounded
                p-3
                max-h-[32rem]
                overflow-y-auto
              ">

                {reportMarkdown}

              </pre>

            )}

          </Panel>


          {/* ==================================================
              RESPONSE ACTIONS
          ================================================== */}

          <Panel
            title="
              Recommended Response — Human Approval Required
            "
          >

            <div className="space-y-2">

              {actions.map((action) => (

                <div
                  key={action.id}
                  className="
                    flex
                    items-center
                    justify-between
                    border
                    border-slate-800
                    rounded
                    p-2.5
                    text-sm
                  "
                >

                  <div>

                    <div>
                      {action.action_type}
                    </div>


                    {action.simulated_result && (

                      <div className="
                        text-xs
                        text-emerald-400
                        mt-0.5
                      ">
                        {
                          action.simulated_result
                        }
                      </div>

                    )}

                  </div>


                  <span
                    className={`
                      text-xs
                      px-2
                      py-0.5
                      rounded
                      border
                      ${
                        action.status ===
                        "recommended"
                          ? "border-slate-700 text-slate-400"
                          : action.status ===
                            "simulated_executed"
                          ? "border-emerald-800 text-emerald-400 bg-emerald-950"
                          : "border-red-800 text-red-400 bg-red-950"
                      }
                    `}
                  >

                    {action.status}

                  </span>

                </div>

              ))}


              {actions.length === 0 && (

                <div className="
                  text-sm
                  text-slate-500
                ">
                  No response actions recommended.
                </div>

              )}

            </div>


            {actions.some(
              (a) =>
                a.status === "recommended"
            ) && (

              <div className="
                flex
                gap-2
                mt-4
              ">

                <button
                  onClick={() =>
                    respond("approve")
                  }
                  className="
                    bg-emerald-600
                    hover:bg-emerald-500
                    text-white
                    text-sm
                    px-3
                    py-1.5
                    rounded
                  "
                >
                  Approve
                </button>


                <button
                  onClick={() =>
                    respond("reject")
                  }
                  className="
                    bg-slate-800
                    hover:bg-slate-700
                    text-slate-200
                    text-sm
                    px-3
                    py-1.5
                    rounded
                  "
                >
                  Reject
                </button>

              </div>

            )}


            <p className="
              text-xs
              text-slate-600
              mt-3
            ">

              Approving a recommendation only
              simulates and logs the action — no
              real system is ever modified by this
              application.

            </p>

          </Panel>

        </>
      )}

    </div>
  );
}


// ============================================================
// FIELD COMPONENT
// ============================================================

function Field({
  label,
  value,
  mono,
}: {
  label: string;
  value: string | null;
  mono?: boolean;
}) {
  return (
    <div>

      <dt className="
        text-xs
        text-slate-500
      ">
        {label}
      </dt>


      <dd
        className={`
          text-slate-200
          ${
            mono
              ? "font-mono text-xs"
              : ""
          }
        `}
      >
        {value ?? "—"}
      </dd>

    </div>
  );
}