package audit

// AuditScore calculates the 0-100 health/security score based on audit findings.
type AuditScore struct {
	Value      int              `json:"value"`  // 0 - 100
	Grade      string           `json:"grade"`  // "A", "B", "C", "D", "F"
	Status     string           `json:"status"` // e.g. "Hardened", "Needs Attention", "At Risk"
	Counts     map[Severity]int `json:"counts"`
	TotalRisks int              `json:"total_risks"`
}

// CalculateScore computes the score and categorizes the results.
func CalculateScore(findings []Finding) AuditScore {
	counts := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
		SeverityInfo:     0,
	}

	for _, f := range findings {
		counts[f.Severity]++
	}

	// Deduction weights
	// Critical: -25 pts
	// High:     -15 pts
	// Medium:   -8 pts
	// Low:      -3 pts
	deduction := (counts[SeverityCritical] * 25) +
		(counts[SeverityHigh] * 15) +
		(counts[SeverityMedium] * 8) +
		(counts[SeverityLow] * 3)

	scoreVal := 100 - deduction
	if scoreVal < 0 {
		scoreVal = 0
	}

	var grade string
	var status string

	switch {
	case scoreVal >= 90:
		grade = "A"
		status = "Hardened & Secure"
	case scoreVal >= 75:
		grade = "B"
		status = "Good / Low Exposure"
	case scoreVal >= 60:
		grade = "C"
		status = "Fair / Needs Attention"
	case scoreVal >= 40:
		grade = "D"
		status = "High Exposure"
	default:
		grade = "F"
		status = "Critical Risks Detected"
	}

	return AuditScore{
		Value:      scoreVal,
		Grade:      grade,
		Status:     status,
		Counts:     counts,
		TotalRisks: len(findings),
	}
}
