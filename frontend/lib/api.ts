import {
  EmailAnalysisRecord,
  EmailListResponse,
  HealthResponse,
} from "../types/email";

const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/+$/, "") ||
  "http://localhost:8000";

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = `Request failed with status ${res.status}`;
    try {
      const errorJson = await res.json();
      if (errorJson && typeof errorJson.detail === "string") {
        detail = errorJson.detail;
      } else if (errorJson && typeof errorJson.message === "string") {
        detail = errorJson.message;
      }
    } catch {
      // Body is not json, fallback to status
    }
    throw new ApiError(detail, res.status);
  }
  return res.json() as Promise<T>;
}

export async function checkBackendHealth(): Promise<HealthResponse> {
  const res = await fetch(`${API_BASE_URL}/api/v1/health/`, {
    cache: "no-store",
  });
  return handleResponse<HealthResponse>(res);
}

export async function uploadEmailFile(file: File): Promise<EmailAnalysisRecord> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_BASE_URL}/api/v1/emails/upload`, {
    method: "POST",
    body: formData,
  });

  return handleResponse<EmailAnalysisRecord>(res);
}

export async function listEmails(
  limit: number = 20,
  skip: number = 0
): Promise<EmailListResponse> {
  const params = new URLSearchParams({
    limit: limit.toString(),
    skip: skip.toString(),
  });

  const res = await fetch(`${API_BASE_URL}/api/v1/emails/?${params.toString()}`, {
    cache: "no-store",
  });

  return handleResponse<EmailListResponse>(res);
}

export async function getEmailAnalysis(id: string): Promise<EmailAnalysisRecord> {
  const res = await fetch(`${API_BASE_URL}/api/v1/emails/${encodeURIComponent(id)}`, {
    cache: "no-store",
  });

  return handleResponse<EmailAnalysisRecord>(res);
}
