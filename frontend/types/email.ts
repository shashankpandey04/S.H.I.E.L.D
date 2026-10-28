export interface HealthResponse {
  status: string;
  service: string;
  version: string;
}

export interface EmailHeaders {
  subject?: string | null;
  from?: string | null;
  sender: string[];
  to: string[];
  recipient: string[];
  cc: string[];
  bcc: string[];
  reply_to: string[];
  return_path?: string | null;
  date?: string | null;
  message_id?: string | null;
  received: string[];
}

export interface EmailAuthenticationHeaders {
  authentication_results: string[];
  received_spf: string[];
  dkim_signatures: string[];
  arc_authentication_results: string[];
}

export interface EmailBody {
  body_text?: string | null;
  body_html?: string | null;
}

export interface EmailAttachment {
  filename: string;
  content_type: string;
  size: number;
}

export interface ParsedEmail {
  filename: string;
  headers: EmailHeaders;
  authentication_headers: EmailAuthenticationHeaders;
  body: EmailBody;
  attachments: EmailAttachment[];
}

export interface ReportedAuthStatus {
  result?: string | null;
  note?: string;
}

export interface ReportedResults {
  raw_headers: EmailAuthenticationHeaders;
  parsed: {
    spf?: ReportedAuthStatus;
    dkim?: ReportedAuthStatus;
    dmarc?: ReportedAuthStatus;
  };
}

export interface DNSAuthCheck {
  status: "pass" | "fail" | "configured" | "missing" | "invalid" | "unknown" | "unverified" | "not_checked" | string;
  records?: string[];
  details: string;
}

export interface DKIMSignatureDetail {
  domain?: string | null;
  selector?: string | null;
  algorithm?: string | null;
  identity?: string | null;
  raw: string;
}

export interface DKIMCheck {
  status: "pass" | "fail" | "configured" | "missing" | "invalid" | "unknown" | "unverified" | "not_checked" | string;
  signatures: DKIMSignatureDetail[];
  details: string;
}

export interface DMARCEvaluation {
  status: string;
  details: string;
}

export interface AuthenticationAnalysis {
  domains: {
    sender_domain?: string | null;
    return_path_domain?: string | null;
    dkim_domains: string[];
  };
  reported_results: ReportedResults;
  spf: DNSAuthCheck;
  dkim: DKIMCheck;
  dmarc: DNSAuthCheck;
  dmarc_evaluation: DMARCEvaluation;
}

export interface URLFinding {
  type: string;
  severity: "low" | "medium" | "high" | "critical" | string;
  description: string;
}

export interface URLResult {
  url: string;
  host?: string | null;
  status: "no_obvious_indicators" | "suspicious" | "invalid" | string;
  findings: URLFinding[];
}

export interface URLAnalysis {
  total: number;
  suspicious_count: number;
  invalid_count: number;
  results: URLResult[];
}

export interface ExtractedURLs {
  total: number;
  text_urls: string[];
  html_urls: string[];
  all_urls: string[];
}

export interface HeaderFinding {
  type: string;
  severity: "low" | "medium" | "high" | "critical" | string;
  evidence: string;
  explanation: string;
}

export interface HeaderAnalysis {
  total_findings: number;
  inconsistencies_detected: boolean;
  domains: {
    from_domain?: string | null;
    reply_to_domains: string[];
    return_path_domain?: string | null;
    dkim_domains: string[];
  };
  received_hops_count: number;
  findings: HeaderFinding[];
}

export interface RiskFinding {
  source: string;
  type: string;
  severity: "low" | "medium" | "high" | "critical" | string;
  points: number;
  description: string;
}

export interface RiskAssessment {
  score: number;
  category: "low" | "moderate" | "high" | "critical" | string;
  findings: RiskFinding[];
  limitations: string[];
}

export interface EmailAnalysisRecord {
  id: string;
  filename: string;
  sha256: string;
  storage_path?: string | null;
  uploaded_at: string;
  status: string;
  email: ParsedEmail;
  authentication: AuthenticationAnalysis;
  urls: ExtractedURLs;
  url_analysis: URLAnalysis;
  header_analysis: HeaderAnalysis;
  risk_assessment: RiskAssessment;
}

export interface EmailListItem {
  id: string;
  filename: string;
  sha256: string;
  uploaded_at: string;
  status: string;
  email?: {
    filename?: string;
    headers?: Partial<EmailHeaders>;
    attachments?: EmailAttachment[];
  };
  authentication?: Partial<AuthenticationAnalysis>;
  urls?: Partial<ExtractedURLs>;
  url_analysis?: Partial<URLAnalysis>;
  header_analysis?: Partial<HeaderAnalysis>;
  risk_assessment?: Partial<RiskAssessment>;
}

export interface EmailListResponse {
  total: number;
  limit: number;
  skip: number;
  emails: EmailListItem[];
}
