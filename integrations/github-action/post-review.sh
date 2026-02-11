#!/usr/bin/env bash
# post-review.sh -- Read AIShield JSON results and post a GitHub PR review
# with inline comments for each finding that meets the severity threshold.
#
# Required environment variables:
#   RESULTS_FILE         Path to the AIShield JSON results file
#   GITHUB_TOKEN         GitHub token with pull-requests:write scope
#   SEVERITY_THRESHOLD   Minimum severity to report (critical|high|medium|low|info)
#   MAX_COMMENTS         Maximum inline comments per review
#   PR_NUMBER            Pull request number
#   REPO                 owner/repo string
#   COMMIT_SHA           HEAD commit SHA of the pull request
set -euo pipefail

# ---------------------------------------------------------------------------
# Severity ranking (higher = more severe)
# ---------------------------------------------------------------------------
severity_rank() {
  case "$1" in
    critical) echo 5 ;;
    high)     echo 4 ;;
    medium)   echo 3 ;;
    low)      echo 2 ;;
    info)     echo 1 ;;
    *)        echo 0 ;;
  esac
}

# ---------------------------------------------------------------------------
# Validate inputs
# ---------------------------------------------------------------------------
if [[ -z "${RESULTS_FILE:-}" ]]; then
  echo "::error::RESULTS_FILE is not set"
  exit 1
fi

if [[ ! -f "$RESULTS_FILE" ]]; then
  echo "::notice::Results file not found at ${RESULTS_FILE} -- nothing to review."
  exit 0
fi

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "::error::GITHUB_TOKEN is not set"
  exit 1
fi

if [[ -z "${PR_NUMBER:-}" || "$PR_NUMBER" == "null" ]]; then
  echo "::notice::Not a pull-request context (PR_NUMBER is empty). Skipping review."
  exit 0
fi

THRESHOLD_RANK=$(severity_rank "${SEVERITY_THRESHOLD:-high}")
MAX_COMMENTS="${MAX_COMMENTS:-25}"

# ---------------------------------------------------------------------------
# Parse results
# ---------------------------------------------------------------------------
TOTAL=$(jq -r '.summary.total // 0' "$RESULTS_FILE")

if [[ "$TOTAL" -eq 0 ]]; then
  echo "::notice::AIShield found 0 issues. Clean scan!"
  exit 0
fi

# Count by severity from the summary object
COUNT_CRITICAL=$(jq -r '.summary.by_severity.critical // 0' "$RESULTS_FILE")
COUNT_HIGH=$(jq -r '.summary.by_severity.high // 0' "$RESULTS_FILE")
COUNT_MEDIUM=$(jq -r '.summary.by_severity.medium // 0' "$RESULTS_FILE")
COUNT_LOW=$(jq -r '.summary.by_severity.low // 0' "$RESULTS_FILE")
COUNT_INFO=$(jq -r '.summary.by_severity.info // 0' "$RESULTS_FILE")

# Average AI confidence across all findings
AVG_AI_CONF=$(jq -r '
  [.findings[].ai_confidence] |
  if length == 0 then 0
  else (add / length * 10 | round) / 10
  end
' "$RESULTS_FILE")

# Count of findings estimated as AI-generated (ai_confidence >= 70)
AI_ESTIMATED=$(jq -r '
  [.findings[] | select(.ai_confidence >= 70)] | length
' "$RESULTS_FILE")

AI_GENERATED_PCT=0
if [[ "$TOTAL" -gt 0 ]]; then
  AI_GENERATED_PCT=$(( AI_ESTIMATED * 100 / TOTAL ))
fi

# ---------------------------------------------------------------------------
# Build the summary body
# ---------------------------------------------------------------------------
SUMMARY=$'\xf0\x9f\x9b\xa1\xef\xb8\x8f'" AIShield found ${TOTAL} issues"

# Append non-zero severity counts
SEVERITY_PARTS=()
[[ "$COUNT_CRITICAL" -gt 0 ]] && SEVERITY_PARTS+=("${COUNT_CRITICAL} critical")
[[ "$COUNT_HIGH"     -gt 0 ]] && SEVERITY_PARTS+=("${COUNT_HIGH} high")
[[ "$COUNT_MEDIUM"   -gt 0 ]] && SEVERITY_PARTS+=("${COUNT_MEDIUM} medium")
[[ "$COUNT_LOW"      -gt 0 ]] && SEVERITY_PARTS+=("${COUNT_LOW} low")
[[ "$COUNT_INFO"     -gt 0 ]] && SEVERITY_PARTS+=("${COUNT_INFO} info")

if [[ ${#SEVERITY_PARTS[@]} -gt 0 ]]; then
  JOINED=$(printf ", %s" "${SEVERITY_PARTS[@]}")
  JOINED="${JOINED:2}"  # strip leading ", "
  SUMMARY+=" (${JOINED})"
fi

SUMMARY+=" | AI-generated: ${AI_GENERATED_PCT}%"

REVIEW_BODY="## ${SUMMARY}

| Metric | Value |
|--------|-------|
| Total findings | ${TOTAL} |
| Severity threshold | ${SEVERITY_THRESHOLD:-high} |
| Avg AI confidence | ${AVG_AI_CONF}% |
| Showing up to | ${MAX_COMMENTS} comments |

> Findings below **${SEVERITY_THRESHOLD:-high}** severity are omitted from inline comments."

# ---------------------------------------------------------------------------
# Build inline comments array via jq
# Each finding needs: path (file), line, body
# ---------------------------------------------------------------------------
COMMENTS_JSON=$(jq -r --arg threshold "$THRESHOLD_RANK" --arg max "$MAX_COMMENTS" '
  # Map severity name to numeric rank
  def sev_rank:
    if   . == "critical" then 5
    elif . == "high"     then 4
    elif . == "medium"   then 3
    elif . == "low"      then 2
    elif . == "info"     then 1
    else 0
    end;

  def sev_emoji:
    if   . == "critical" then "\ud83d\udd34"
    elif . == "high"     then "\ud83d\udfe0"
    elif . == "medium"   then "\ud83d\udfe1"
    elif . == "low"      then "\ud83d\udd35"
    elif . == "info"     then "\u2139\ufe0f"
    else "\u26aa"
    end;

  [
    .findings[]
    | select((.severity | sev_rank) >= ($threshold | tonumber))
    | {
        path: .file,
        line: (if .line > 0 then .line else 1 end),
        body: (
          (.severity | sev_emoji) + " **" + (.severity | ascii_upcase) + "**: " + .title + "\n\n"
          + "**Rule:** `" + .id + "`\n"
          + (if .category then "**Category:** " + .category + "\n" else "" end)
          + (if .cwe_id then "**CWE:** " + .cwe_id + "\n" else "" end)
          + "**AI Confidence:** " + (.ai_confidence | tostring) + "%\n"
          + "**Risk Score:** " + (.risk_score | tostring) + "\n"
          + "\n"
          + (if .fix_suggestion then
              "**Suggested fix:**\n> " + .fix_suggestion + "\n"
            else
              ""
            end)
          + "\n"
          + (if .snippet and .snippet != "" then
              "<details><summary>Matched snippet</summary>\n\n```\n" + .snippet + "\n```\n</details>"
            else
              ""
            end)
        )
      }
  ]
  | sort_by(
      -(.path | explode | .[0])
    )
  | unique_by(.path + ":" + (.line | tostring))
  | .[:($max | tonumber)]
' "$RESULTS_FILE")

COMMENT_COUNT=$(echo "$COMMENTS_JSON" | jq 'length')

if [[ "$COMMENT_COUNT" -eq 0 ]]; then
  echo "::notice::No findings meet the ${SEVERITY_THRESHOLD:-high} threshold. Posting summary only."
  COMMENTS_JSON="[]"
fi

echo "::notice::Posting review with ${COMMENT_COUNT} inline comments (threshold: ${SEVERITY_THRESHOLD:-high})"

# ---------------------------------------------------------------------------
# Post the review via GitHub API
# ---------------------------------------------------------------------------
PAYLOAD=$(jq -n \
  --arg event "COMMENT" \
  --arg body "$REVIEW_BODY" \
  --arg commit "$COMMIT_SHA" \
  --argjson comments "$COMMENTS_JSON" \
  '{
    event: $event,
    body: $body,
    commit_id: $commit,
    comments: $comments
  }')

RESPONSE=$(gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "/repos/${REPO}/pulls/${PR_NUMBER}/reviews" \
  --input - <<< "$PAYLOAD" 2>&1) || {
    echo "::error::Failed to post PR review"
    echo "$RESPONSE"
    exit 1
  }

REVIEW_ID=$(echo "$RESPONSE" | jq -r '.id // empty')
if [[ -n "$REVIEW_ID" ]]; then
  echo "::notice::Review posted successfully (review ID: ${REVIEW_ID})"
else
  echo "::warning::Review response did not include an ID. Response:"
  echo "$RESPONSE"
fi
