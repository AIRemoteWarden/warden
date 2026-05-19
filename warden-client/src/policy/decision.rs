#[derive(Debug, Clone)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
    RequireApproval { reason: String, risk: RiskLevel },
}

#[derive(Debug, Clone)]
pub enum RiskLevel {
    High,
}
