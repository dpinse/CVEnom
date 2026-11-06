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
/** POST /auth/login (and invite accept): step one of sign-in. Never a session. */
export interface MfaChallenge {
  /** short-lived, single-use; held only in component memory */
  ticket: string;
  enroll_required: boolean;
  expires_in: number;
}
/** POST /auth/mfa/enroll/start: shown once, never stored or cached */
export interface MfaEnrollStart {
  secret: string;
  otpauth_uri: string;
}
/** POST /auth/mfa/enroll/finish */
export interface MfaEnrolled extends TokenResponse {
  recovery_codes: string[];
}
/** GET /auth/mfa */
export interface MfaStatus {
  enabled: boolean;
  enrolled_at: string | null;
  recovery_codes_remaining: number;
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
  /** "Vendor Product" label derived from the affected list; entity-escaped */
  product: string | null;
  /** newest story/event time that mentions the CVE (ISO-8601 UTC) */
  last_seen: string | null;
}
/** One lane of GET /lanes: `total` counts the whole lane in range, `items` is capped by `limit`. */
export interface LaneOut {
  total: number;
  items: CveItem[];
}
export type LanesOut = Record<Lane, LaneOut>;

/** GET /summary?range= */
export interface SummaryOut {
  range: string;
  new_kev: number;
  kev_due_soon: number;
  new_critical: number;
  public_exploits: number;
  /** "YYYY-MM-DD" or null */
  latest_kev_added: string | null;
}
/** GET /volume?range=: CVE publications bucketed by CVSS band. */
export interface VolumeBucket {
  start: string;
  crit: number;
  high: number;
  med: number;
  low: number;
}
export interface VolumeOut {
  range: string;
  unit: "hour" | "day";
  buckets: VolumeBucket[];
  total: number;
  unscored: number;
}
export interface CveListOut {
  items: CveItem[];
  page: number;
  page_size: number;
  total: number;
  /** q was an exact CVE id (all other filters are ignored for it) */
  exact_match?: boolean;
  /** that CVE exists but the other filters would have hidden it */
  exact_match_filtered_out?: boolean;
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
export interface CveReference {
  url: string;
  tags: string[];
}
export type CveEventKind =
  | "reserved"
  | "published"
  | "nvd_modified"
  | "fix_released"
  | "poc_published"
  | "detection"
  | "first_news"
  | "kev_added"
  | "epss_crossed";
/** Threat-page timeline row; ascending by occurred_at. `detail` strings are entity-escaped. */
export interface CveEvent {
  kind: CveEventKind;
  occurred_at: string;
  source: string;
  detail: Record<string, unknown>;
}
export interface AffectedVersion {
  product: string;
  vendor: string | null;
  ecosystem: string | null;
  introduced: string | null;
  fixed: string | null;
  last_affected: string | null;
  source: "OSV" | "NVD";
}
export interface RelatedCve {
  cve_id: string;
  cvss: number | null;
  kev: boolean;
  epss_percentile: number | null;
  product: string | null;
}
export interface GeoTop {
  country_code: string;
  events: number;
}
export interface CveDetail extends CveItem {
  epss: number | null;
  affected: unknown[];
  stories: StoryRef[];
  geo_events: GeoEventOut[];
  kev_name: string | null;
  kev_action: string | null;
  kev_notes: string | null;
  /** "YYYY-MM-DD" */
  kev_due: string | null;
  kev_ransomware: boolean | null;
  cvss_vector: string | null;
  cvss_severity: string | null;
  cwes: string[];
  references: CveReference[];
  last_modified: string | null;
  events: CveEvent[];
  affected_versions: AffectedVersion[];
  related: RelatedCve[];
  geo_top: GeoTop[];
  updated_at: string;
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
/** One story (feed item). `/stories/loud` returns a bare list of these; `/stories` pages them. */
export interface StoryItem {
  title: string;
  summary: string;
  url: string;
  source: string;
  published: string;
  cve_ids: string[];
}
export type LoudStory = StoryItem;
export interface StoryListOut {
  items: StoryItem[];
  page: number;
  page_size: number;
  total: number;
}
/** GET /story?url=: a story plus its ingest `details` ({} when none). Details strings are entity-escaped. */
export interface StoryDetailOut extends StoryItem {
  details: Record<string, unknown>;
}
/** `added` is the Threats/News "Added" window (any|day|week|14d|month|90d|year). */
export type AddedKey = "any" | "day" | "week" | "14d" | "month" | "90d" | "year";
export type StatusKey = "all" | "exploited" | "likely" | "news" | "critical";
export type SevKey = "low" | "med" | "high" | "crit";
export type ThreatsSort = "newest" | "hot" | "trending" | "due";
export interface StoryQuery {
  added?: AddedKey;
  q?: string;
  source?: string;
  /** "YYYY-MM-DD", inclusive */
  from?: string;
  to?: string;
  page?: number;
  page_size?: number;
}

/** GET /geo/{cc}. `trend` is display-only: never assume sum(trend) equals the counts. */
export interface CountryEvent {
  source: string;
  kind: string;
  label: string | null;
  magnitude: number;
  observed_at: string;
  asn: number | null;
  story_url: string | null;
  details: Record<string, unknown>;
}
export interface CountryActivity {
  country_code: string;
  window_hours: number;
  counts: { kind: string; events: number; magnitude: number }[];
  /** at most 5 */
  top_sources: { source: string; events: number }[];
  /** oldest first; buckets are hours or days per `trend_unit` */
  trend: { bucket: string; events: number }[];
  trend_unit: "hour" | "day";
  /** CVEs most tied to the country's events in the window */
  top_cves: { cve_id: string; cvss: number | null; events: number }[];
  /** newest first, at most 50; null for anonymous callers */
  events: CountryEvent[] | null;
}
/** GET /cves (Threats search). Independent of the Dashboard range. */
export interface CveQuery {
  q?: string;
  added?: AddedKey;
  status?: StatusKey;
  exclude_kev?: boolean;
  /** comma list of low|med|high|crit; empty = any */
  sev?: string;
  poc?: boolean;
  nopatch?: boolean;
  due?: "7d";
  sort?: ThreatsSort | "kev_added" | "published" | "cvss";
  page?: number;
  page_size?: number;
  // legacy params the API still accepts
  source?: "cisa" | "vulncheck";
  lane?: Lane;
  min_cvss?: number;
  kev?: boolean;
  from?: string;
  to?: string;
  kev_from?: string;
  kev_to?: string;
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
  mfa_enabled: boolean;
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
  /** every role gets the count */
  recipient_count: number;
  /** admin responses only: members get `recipient_count` and no list */
  recipients: Recipient[];
}
/** The member-role view of a rule: the recipient list is never sent. */
export type MemberAlertRule = Omit<AlertRule, "recipients">;
export type RecipientIn =
  { channel: "email"; email: string } | { channel: "webhook"; url: string; secret?: string | null };
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
