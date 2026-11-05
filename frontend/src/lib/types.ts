// Mirrors the backend response models (backend/src/cvenom/api/*). Datetimes are ISO-8601
// UTC strings; `date` fields are "YYYY-MM-DD". Text fields (summary, title, label,
// affected, story source) arrive HTML-entity-escaped: render them only via <Text>.

export type Role = "admin" | "member";
export type Lane = "EXPLOITED" | "LIKELY" | "LOUD" | "FRESH";

// ---- errors -------------------------------------------------------------
export interface ErrorBody {
  error: string;
}
export interface ValidationDetail {
  loc: (string | number)[];
  msg: string;
  type: string;
}
export interface ValidationErrorBody extends ErrorBody {
  error: "validation_error";
  detail?: ValidationDetail[];
}

// ---- health / auth ------------------------------------------------------
export interface Health {
  status: "ok";
  public_read: boolean;
}
export interface TokenResponse {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
}
export interface Me {
  id: number;
  email: string;
  role: Role;
}
export interface LoginBody {
  email: string;
  password: string;
}
export interface PasswordBody {
  current_password: string;
  new_password: string;
}
export interface AcceptInviteBody {
  token: string;
  password: string;
}
/** GET /auth/sessions */
export interface SessionInfo {
  id: string;
  user_agent: string | null;
  ip: string | null;
  created_at: string;
  last_used_at: string;
  current: boolean;
}

// ---- read API -----------------------------------------------------------
export interface CveItem {
  cve_id: string;
  cvss: number | null;
  epss_percentile: number | null;
  kev: boolean;
  kev_added: string | null;
  kev_source: string | null;
  poc_badge: boolean;
  patch_available: boolean | null;
  published: string | null;
  summary: string;
  recent_story_count: number;
}
export type LanesOut = Record<Lane, CveItem[]>;
export interface CveListOut {
  items: CveItem[];
  page: number;
  page_size: number;
  total: number;
}
export interface StoryRef {
  title: string;
  url: string;
  source: string;
  published: string;
}
export interface GeoEventOut {
  kind: string;
  country_code: string | null;
  label: string | null;
  magnitude: number;
  observed_at: string;
  details: Record<string, unknown>;
}
export interface CveDetail extends CveItem {
  epss: number | null;
  affected: unknown[];
  stories: StoryRef[];
  geo_events: GeoEventOut[];
}
export interface VelocityPoint {
  day: string;
  count: number;
}
export interface VelocityOut {
  series: VelocityPoint[];
  current: number;
  rising: boolean;
}
export interface GeoSummaryItem {
  country_code: string;
  kind: string;
  magnitude: number;
  events: number;
  last_seen: string;
}
export interface LoudStory {
  title: string;
  summary: string;
  url: string;
  source: string;
  published: string;
  cve_ids: string[];
}
export interface CveQuery {
  q?: string;
  source?: "cisa" | "vulncheck";
  lane?: Lane;
  min_cvss?: number;
  kev?: boolean;
  from?: string;
  to?: string;
  page?: number;
  page_size?: number;
}

// ---- users / invites (admin) -------------------------------------------
/** GET /auth/users, PATCH /auth/users/{id} */
export interface UserAdmin {
  id: number;
  email: string;
  role: Role;
  is_active: boolean;
  created_at: string;
  active_sessions: number;
}
export interface UserPatch {
  role?: Role;
  is_active?: boolean;
}
/** GET /auth/invites (pending only). `purpose`: invite creates an account, reset sets a password. */
export interface InviteOut {
  id: number;
  email: string;
  role: Role;
  purpose: "invite" | "reset";
  expires_at: string;
  created_at: string;
  created_by: number | null;
}
export interface InviteBody {
  email: string;
  role: Role;
}
/** POST /auth/invites and POST /auth/users/{id}/reset: the raw token is shown once. */
export interface TokenIssued {
  token: string;
  expires_at: string;
}

// ---- alerts -------------------------------------------------------------
export type RuleKind = "kev_added" | "cvss_min" | "epss_min" | "keyword";
export interface EmailRecipient {
  id: number;
  channel: "email";
  email: string;
}
export interface WebhookRecipient {
  id: number;
  channel: "webhook";
  url_masked?: string;
  /** present only in the response that created the recipient: shown once */
  secret?: string;
}
export type Recipient = EmailRecipient | WebhookRecipient;
export interface AlertRule {
  id: number;
  name: string;
  kind: RuleKind;
  threshold: number | null;
  keyword: string | null;
  enabled: boolean;
  created_at: string;
  recipients: Recipient[];
}
export type RecipientIn =
  | { channel: "email"; email: string }
  | { channel: "webhook"; url: string; secret?: string | null };
export interface RuleCreate {
  name: string;
  kind: RuleKind;
  threshold?: number | null;
  keyword?: string | null;
  enabled?: boolean;
  recipients: RecipientIn[];
}
export interface RulePatch {
  name?: string;
  threshold?: number | null;
  keyword?: string | null;
  enabled?: boolean;
}
export type DeliveryStatus = "pending" | "sent" | "failed";
export interface Delivery {
  id: number;
  rule_id: number;
  recipient_id: number;
  channel: "email" | "webhook";
  cve_id: string;
  status: DeliveryStatus;
  attempts: number;
  last_error: string | null;
  created_at: string;
  sent_at: string | null;
  next_attempt_at: string | null;
}
export interface DeliveriesOut {
  items: Delivery[];
  page: number;
  page_size: number;
  total: number;
}
/** POST /alerts/rules/{id}/test: one entry per recipient. */
export interface TestSendResult {
  recipient_id: number;
  channel: "email" | "webhook";
  ok: boolean;
  error: string | null;
}

// ---- websocket ----------------------------------------------------------
// The socket protocol is typed with the live-update hook (Task 2); the auth first
// message is {"type":"auth","token":...} sent only after the socket opens.
