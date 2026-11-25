package tools

import (
	"strings"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/adk/v2/tool/functiontool"

	"github.com/leo-hoet/kubeguard/internal/memory"
)

// BuildKnowledgeTools constructs KubeGuard's SRE runbook and historical postmortem
// retrieval tools backed by PersistentKnowledgeStore.
func BuildKnowledgeTools(store *memory.PersistentKnowledgeStore) ([]tool.Tool, error) {
	rbTool, err := newSearchSRERunbooksTool(store)
	if err != nil {
		return nil, err
	}
	pmTool, err := newQueryPastPostmortemsTool(store)
	if err != nil {
		return nil, err
	}
	return []tool.Tool{rbTool, pmTool}, nil
}

// newSearchSRERunbooksTool creates the search_sre_runbooks tool.
func newSearchSRERunbooksTool(store *memory.PersistentKnowledgeStore) (tool.Tool, error) {
	inSchema, err := MustSchema[SearchRunbooksInput]()
	if err != nil {
		return nil, err
	}
	outSchema, err := MustSchema[SearchRunbooksOutput]()
	if err != nil {
		return nil, err
	}

	return functiontool.New(functiontool.Config{
		Name: "search_sre_runbooks",
		Description: "Searches KubeGuard's persistent SRE runbook database for authoritative remediation playbooks matching Kubernetes failure symptoms (e.g. 'OOMKilled exit 137', 'CrashLoopBackOff config validation', 'CPU throttling backlog', 'PII token log leak'). " +
			"Returns runbook IDs, mandatory pre-checks, step-by-step remediation guidance, and HITL requirements.",
		InputSchema:  inSchema,
		OutputSchema: outSchema,
	}, func(ctx agent.Context, in SearchRunbooksInput) (SearchRunbooksOutput, error) {
		q := strings.TrimSpace(in.SymptomQuery)
		if q == "" {
			return SearchRunbooksOutput{
				Status: "recoverable_error",
				Recovery: &GuidedRecoveryInfo{
					ErrorCode:    "EMPTY_SYMPTOM_QUERY",
					ErrorMessage: "symptom_query must contain at least one symptom keyword.",
					RecoveryHint: "Pass concrete Kubernetes symptoms such as 'OOMKilled memory limit', 'CrashLoopBackOff env', or 'CPU throttling scale'.",
				},
			}, nil
		}
		maxRes := in.MaxResults
		if maxRes <= 0 || maxRes > 10 {
			maxRes = 3
		}
		rbs, err := store.SearchRunbooks(ctx, q, maxRes)
		if err != nil {
			return SearchRunbooksOutput{
				Status: "recoverable_error",
				Recovery: &GuidedRecoveryInfo{
					ErrorCode:    "RUNBOOK_STORE_UNAVAILABLE",
					ErrorMessage: "Failed to query persistent runbook store.",
					RecoveryHint: "Proceed using standard Kubernetes SRE safety principles and rollout history evidence.",
				},
			}, nil
		}
		return SearchRunbooksOutput{
			Status:   "succeeded",
			Runbooks: rbs,
		}, nil
	})
}

// newQueryPastPostmortemsTool creates the query_past_incident_postmortems tool.
func newQueryPastPostmortemsTool(store *memory.PersistentKnowledgeStore) (tool.Tool, error) {
	inSchema, err := MustSchema[QueryPostmortemsInput]()
	if err != nil {
		return nil, err
	}
	outSchema, err := MustSchema[QueryPostmortemsOutput]()
	if err != nil {
		return nil, err
	}

	return functiontool.New(functiontool.Config{
		Name: "query_past_incident_postmortems",
		Description: "Queries KubeGuard's persistent postmortem memory database for prior resolved incidents involving a workload (e.g. 'payments/checkout-api') or failure pattern. " +
			"All stored postmortems are PII-redacted and capture what remediation previously restored service health.",
		InputSchema:  inSchema,
		OutputSchema: outSchema,
	}, func(ctx agent.Context, in QueryPostmortemsInput) (QueryPostmortemsOutput, error) {
		q := strings.TrimSpace(in.ServiceOrSymptom)
		if q == "" {
			return QueryPostmortemsOutput{
				Status: "recoverable_error",
				Recovery: &GuidedRecoveryInfo{
					ErrorCode:    "EMPTY_POSTMORTEM_QUERY",
					ErrorMessage: "service_or_symptom must not be empty.",
					RecoveryHint: "Pass the 'namespace/deployment' name (e.g. 'payments/checkout-api') or symptom keyword (e.g. 'OOMKilled').",
				},
			}, nil
		}
		maxRes := in.MaxResults
		if maxRes <= 0 || maxRes > 10 {
			maxRes = 3
		}
		pms, err := store.SearchPostmortems(ctx, q, maxRes)
		if err != nil {
			return QueryPostmortemsOutput{
				Status: "recoverable_error",
				Recovery: &GuidedRecoveryInfo{
					ErrorCode:    "POSTMORTEM_QUERY_FAILED",
					ErrorMessage: "Unable to query historical postmortems.",
					RecoveryHint: "Rely on 'search_sre_runbooks' and live pod telemetry for root-cause analysis.",
				},
			}, nil
		}
		return QueryPostmortemsOutput{
			Status:      "succeeded",
			Postmortems: pms,
		}, nil
	})
}
