import { useEffect, useState } from "react";

import {
  getBackendHealth,
  getRiskScore,
  type SecurityAlert,
} from "./api";

import "./App.css";


function App() {
  // --------------------------------------------------
  // Backend health status
  // --------------------------------------------------

  const [backendStatus, setBackendStatus] =
    useState("Checking...");


  // --------------------------------------------------
  // Risk analysis result
  // --------------------------------------------------

  const [riskResult, setRiskResult] =
    useState<any>(null);


  // --------------------------------------------------
  // Loading state
  // --------------------------------------------------

  const [loadingRisk, setLoadingRisk] =
    useState(false);


  // --------------------------------------------------
  // Error message
  // --------------------------------------------------

  const [errorMessage, setErrorMessage] =
    useState("");


  // --------------------------------------------------
  // Check backend when page loads
  // --------------------------------------------------

  useEffect(() => {
    async function checkBackend() {
      try {
        const data = await getBackendHealth();

        if (data.status === "healthy") {
          setBackendStatus("Online");
        } else {
          setBackendStatus("Unknown");
        }
      } catch {
        setBackendStatus("Offline");
      }
    }

    checkBackend();
  }, []);


  // --------------------------------------------------
  // Run Demo Risk Analysis
  // --------------------------------------------------

  async function runDemoRiskAnalysis() {
    setLoadingRisk(true);
    setErrorMessage("");
    setRiskResult(null);

    const demoAlert: SecurityAlert = {
      alert_id: "SOC-1001",

      alert_name:
        "Multiple Failed Login Attempts",

      severity: "high",

      source:
        "Microsoft Sentinel",

      source_ip:
        "185.220.101.10",

      username:
        "administrator",

      hostname:
        "WIN-SERVER-01",

      failed_attempts:
        25,

      time_window_minutes:
        5,
    };


    try {
      const result =
        await getRiskScore(demoAlert);

      setRiskResult(result);
    } catch {
      setErrorMessage(
        "Risk analysis failed. Check whether the FastAPI backend is running."
      );
    } finally {
      setLoadingRisk(false);
    }
  }


  // --------------------------------------------------
  // UI
  // --------------------------------------------------

  return (
    <div className="dashboard">

      {/* Header */}

      <h1 className="title">
        AI SOC Investigation Agent
      </h1>

      <p className="subtitle">
        AI-assisted security alert investigation platform
      </p>


      {/* Backend Status */}

      <div className="card">

        <h2>
          Backend Status
        </h2>

        <p className="online">

          {backendStatus === "Online"
            ? "🟢"
            : backendStatus === "Checking..."
            ? "🟡"
            : "🔴"}

          {" "}

          {backendStatus}

        </p>

      </div>


      {/* Risk Analysis */}

      <div className="card">

        <h2>
          Risk Analysis
        </h2>

        <p>
          Run a sample SOC alert through the
          deterministic risk engine.
        </p>


        <button
          onClick={runDemoRiskAnalysis}
          disabled={loadingRisk}
        >

          {loadingRisk
            ? "Analyzing..."
            : "Run Demo Risk Analysis"}

        </button>


        {/* Error */}

        {errorMessage && (

          <p>
            🔴 {errorMessage}
          </p>

        )}


        {/* Risk Result */}

        {riskResult && (

          <div>

            <h3>
              Alert
            </h3>

            <p>
              {riskResult.alert_name}
            </p>


            <h3>
              Risk Score
            </h3>

            <h1>
              {riskResult.risk.score}
              /100
            </h1>


            <p>
              Risk Level:{" "}

              <strong>
                {riskResult.risk.level.toUpperCase()}
              </strong>

            </p>


            {/* Risk Reasons */}

            <h3>
              Why this score?
            </h3>

            <ul>

              {riskResult.risk.reasons.map(
                (
                  reason: {
                    signal: string;
                    points: number;
                    reason: string;
                  },
                  index: number
                ) => (

                  <li key={index}>

                    <strong>
                      +{reason.points}{" "}
                      {reason.signal}
                    </strong>

                    {" — "}

                    {reason.reason}

                  </li>

                )
              )}

            </ul>


            {/* Threat Intelligence */}

            <h3>
              Threat Intelligence
            </h3>

            <p>
              Reputation:{" "}

              <strong>
                {
                  riskResult
                    .threat_intelligence
                    .reputation
                }
              </strong>
            </p>

            <p>
              Confidence:{" "}

              {
                riskResult
                  .threat_intelligence
                  .confidence
              }
              %
            </p>


            {/* MITRE ATT&CK */}

            <h3>
              MITRE ATT&CK
            </h3>


            {riskResult.mitre_mappings.length > 0 ? (

              <ul>

                {riskResult.mitre_mappings.map(
                  (
                    mapping: {
                      technique_id: string;
                      technique_name: string;
                      tactic: string;
                    },
                    index: number
                  ) => (

                    <li key={index}>

                      <strong>
                        {mapping.technique_id}
                      </strong>

                      {" — "}

                      {mapping.technique_name}

                      {" | "}

                      {mapping.tactic}

                    </li>

                  )
                )}

              </ul>

            ) : (

              <p>
                No MITRE ATT&CK mappings identified.
              </p>

            )}

          </div>

        )}

      </div>

    </div>
  );
}


export default App;