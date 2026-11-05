# Security Assessment Report

## 1. Assessment Information

**Application:** CDF TaskFlow

**Assessment Type:** AI-Assisted Static Code Review

**Assessment Date:** 2026-11-04

**Tool Name:** AegisReview v1.0.0

## 2. Executive Summary

The most serious problems are in the backend functions: a search endpoint that can be used to run arbitrary database commands, and task-update and profile-lookup endpoints that require no login and use an all-powerful database key. The database access rules also let users promote themselves to admin and read data that likely belongs to others. The front end renders comment text as raw HTML, which allows script injection that would run in other users' browsers. Remaining items are minor hardening issues. AI-assisted findings should be validated before being treated as confirmed vulnerabilities.

## 3. Findings Summary

| Severity | Count |
|---|---:|
| Critical | 2 |
| High | 3 |
| Medium | 3 |
| Low | 4 |
| **Total** | **12** |

## 4. Detailed Findings

### Finding 1: SQL injection via string-interpolated search term in sql.unsafe

**Finding ID:** AR-001

**Severity:** Critical

**Category:** Injection

**CWE:** CWE-89 (OWASP Top 10: A03:2021 Injection)

**Affected File:** `supabase/functions/search-tasks/index.ts`

**Code Location:** lines 20-28

#### Description

The unauthenticated `q` query parameter is concatenated directly into a SQL string that is run via `sql.unsafe`. The connection uses DATABASE_URL, which is typically a privileged role that bypasses RLS.

#### Vulnerable Code

```typescript
const query = `
  SELECT id, title, description, status
  FROM public.tasks
  WHERE title ILIKE '%${searchTerm}%'
  ORDER BY created_at DESC
  LIMIT 25
`;

const tasks = await sql.unsafe(query);
```

#### Potential Impact

An attacker can run arbitrary SQL, for example UNION-based extraction of any table or data modification, and fully compromise the database.

#### Recommended Fix

Use parameterized queries with the tagged template, and escape LIKE wildcards if needed. Require authentication and run the query as a low-privilege role or through the user-scoped Supabase client so RLS applies. Cap the length of the search term.

#### Secure Code Example

```typescript
const sql = postgres(Deno.env.get("DATABASE_URL") ?? "");
const term = searchTerm.slice(0, 100).replace(/[\\%_]/g, (c) => "\\" + c);
const tasks = await sql`
  SELECT id, title, description, status
  FROM public.tasks
  WHERE title ILIKE ${'%' + term + '%'}
  ORDER BY created_at DESC
  LIMIT 25
`;
```

#### Confidence

High — the weakness is directly evident in the code shown.

#### Validation Notes

No further validation is needed beyond reviewing the recommended fix in context.

### Finding 2: Unauthenticated update-task with service-role key and mass assignment (IDOR)

**Finding ID:** AR-002

**Severity:** Critical

**Category:** Broken Access Control

**CWE:** CWE-915 (OWASP Top 10: A01:2021 Broken Access Control)

**Affected File:** `supabase/functions/update-task/index.ts`

**Code Location:** lines 26-38

#### Description

The function performs no authentication or ownership check. It passes the client-supplied `changes` object straight into an update using the service-role key, which bypasses RLS.

#### Vulnerable Code

```typescript
const body = await request.json();

const taskId = body.taskId;
const changes = body.changes;

const supabase = createClient(
  Deno.env.get("SUPABASE_URL") ?? "",
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
);

const { data, error } = await supabase
  .from("tasks")
  .update(changes)
```

#### Potential Impact

Anyone can modify any task and any column, including owner_id, project_id and status, and so take over or tamper with other users' data.

#### Recommended Fix

Verify the caller's JWT and derive the user from it. Check that the task belongs to that user, or use a client created with the caller's Authorization header so RLS applies. Allowlist and validate the updatable fields instead of passing the raw object.

#### Secure Code Example

```typescript
const authHeader = request.headers.get("Authorization") ?? "";
const supabase = createClient(
  Deno.env.get("SUPABASE_URL") ?? "",
  Deno.env.get("SUPABASE_ANON_KEY") ?? "",
  { global: { headers: { Authorization: authHeader } } }
);
const { data: { user } } = await supabase.auth.getUser();
if (!user) return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
const b = await request.json();
const allowed = ["title", "description", "status"];
const changes: Record<string, unknown> = {};
for (const k of allowed) if (k in (b.changes ?? {})) changes[k] = b.changes[k];
const { data, error } = await supabase.from("tasks").update(changes)
  .eq("id", b.taskId).eq("owner_id", user.id).select().single();
```

#### Confidence

High — the weakness is directly evident in the code shown.

#### Validation Notes

Check whether the function is deployed with verify_jwt enabled; even so, there is no ownership check.

### Finding 3: Stored XSS via dangerouslySetInnerHTML on comment text

**Finding ID:** AR-003

**Severity:** High

**Category:** Cross-Site Scripting

**CWE:** CWE-79 (OWASP Top 10: A03:2021 Injection)

**Affected File:** `src/components/TaskComments.tsx`

**Code Location:** lines 39-41

#### Description

User-supplied comment text is rendered as raw HTML with no sanitization. The text comes from a free-form input and would be shared with other users once persisted.

#### Vulnerable Code

```tsx
<div
  dangerouslySetInnerHTML={{
    __html: comment.text,
```

#### Potential Impact

An attacker can run JavaScript in other users' browsers, enabling session theft and actions performed as the victim.

#### Recommended Fix

Render the text as a normal React text node so it is auto-escaped. If rich text is needed, sanitize it with a library such as DOMPurify using a strict allowlist.

#### Secure Code Example

```tsx
<div>{comment.text}</div>
```

#### Confidence

High — the weakness is directly evident in the code shown.

#### Validation Notes

No further validation is needed beyond reviewing the recommended fix in context.

### Finding 4: Unauthenticated get-profile with service-role key allows reading any profile (IDOR)

**Finding ID:** AR-004

**Severity:** High

**Category:** Broken Access Control

**CWE:** CWE-639 (OWASP Top 10: A01:2021 Broken Access Control)

**Affected File:** `supabase/functions/get-profile/index.ts`

**Code Location:** lines 14-28

#### Description

The caller-supplied userId selects a profile with the RLS-bypassing service-role key. There is no authentication, and no check that the caller owns the profile. `select("*")` returns all columns.

#### Vulnerable Code

```typescript
const userId = url.searchParams.get("userId");

if (!userId) {
  return Response.json(
    { error: "userId is required" },
    { status: 400 }
  );
}

const supabase = createClient(
  Deno.env.get("SUPABASE_URL") ?? "",
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
);

const { data, error } = await supabase
```

#### Potential Impact

An attacker can enumerate or read any user's profile data, including role and bio.

#### Recommended Fix

Authenticate the caller via JWT and use their user id, or use a user-scoped client so RLS applies. Select only the needed columns and validate the UUID format.

#### Secure Code Example

```typescript
const authHeader = request.headers.get("Authorization") ?? "";
const supabase = createClient(
  Deno.env.get("SUPABASE_URL") ?? "",
  Deno.env.get("SUPABASE_ANON_KEY") ?? "",
  { global: { headers: { Authorization: authHeader } } }
);
const { data: { user } } = await supabase.auth.getUser();
if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });
const { data, error } = await supabase.from("profiles")
  .select("id, full_name, bio").eq("id", user.id).single();
```

#### Confidence

High — the weakness is directly evident in the code shown.

#### Validation Notes

Related locations: supabase/functions/get-profile/index.ts:42 (Error details are returned via String(error)).

### Finding 5: Profile update policy allows users to change their own role (privilege escalation)

**Finding ID:** AR-005

**Severity:** High

**Category:** Broken Access Control

**CWE:** CWE-269 (OWASP Top 10: A01:2021 Broken Access Control)

**Affected File:** `supabase/migrations/002_access_policies.sql`

**Code Location:** lines 15-20

#### Description

The policy restricts rows but not columns. A user can update their own row, including the `role` column, to 'admin'.

#### Vulnerable Code

```sql
CREATE POLICY "Users can update own profile"
ON public.profiles
FOR UPDATE
TO authenticated
USING (id = auth.uid())
WITH CHECK (id = auth.uid());
```

#### Potential Impact

Any authenticated user can grant themselves admin rights.

#### Recommended Fix

Prevent role changes with a WITH CHECK that compares against the existing role, or revoke column UPDATE privileges and grant only safe columns. A BEFORE UPDATE trigger is another option.

#### Secure Code Example

```sql
REVOKE UPDATE ON public.profiles FROM authenticated;
GRANT UPDATE (full_name, bio) ON public.profiles TO authenticated;

CREATE POLICY "Users can update own profile"
ON public.profiles FOR UPDATE TO authenticated
USING (id = auth.uid())
WITH CHECK (id = auth.uid());
```

#### Confidence

High — the weakness is directly evident in the code shown.

#### Validation Notes

Confirm that the roles table or app logic does not rely on profiles.role for admin checks elsewhere. Related locations: supabase/migrations/002_access_policies.sql:9 (Profiles SELECT USING (true)).

### Finding 6: RLS policy lets any authenticated user read all tasks

**Finding ID:** AR-006

**Severity:** Medium

**Category:** Broken Access Control

**CWE:** CWE-284 (OWASP Top 10: A01:2021 Broken Access Control)

**Affected File:** `supabase/migrations/002_access_policies.sql`

**Code Location:** lines 34-38

#### Description

The SELECT policy on tasks is always true, so every authenticated user can read every task. This is inconsistent with the owner-based update and projects policies.

#### Vulnerable Code

```sql
CREATE POLICY "Users can view tasks"
ON public.tasks
FOR SELECT
TO authenticated
USING (true);
```

#### Potential Impact

Users can read other users' private task titles and descriptions.

#### Recommended Fix

Restrict reads to the owner, or to project members.

#### Secure Code Example

```sql
CREATE POLICY "Users can view tasks"
ON public.tasks
FOR SELECT
TO authenticated
USING (owner_id = auth.uid());
```

#### Confidence

High — the weakness is plausible but depends on context outside the analyzed code.

#### Validation Notes

Related locations: supabase/migrations/002_access_policies.sql:53 (The comments policy depends on the tasks table. Its EXISTS subquery does not filter by owner, so it is still effectively open unless the tasks policy is restricted.).

### Finding 7: Tasks insert/update policies do not protect project_id (cross-project injection)

**Finding ID:** AR-007

**Severity:** Medium

**Category:** Broken Access Control

**CWE:** CWE-639 (OWASP Top 10: A01:2021 Broken Access Control)

**Affected File:** `supabase/migrations/002_access_policies.sql`

**Code Location:** lines 40-50

#### Description

The policies check only owner_id. A user can insert tasks into, or move tasks to, any project_id, including projects they do not own.

#### Vulnerable Code

```sql
CREATE POLICY "Users can create tasks"
ON public.tasks
FOR INSERT
TO authenticated
WITH CHECK (owner_id = auth.uid());

CREATE POLICY "Users can update tasks"
ON public.tasks
FOR UPDATE
TO authenticated
USING (owner_id = auth.uid())
```

#### Potential Impact

Users can inject or move tasks into other users' projects, polluting or tampering with them.

#### Recommended Fix

Require in WITH CHECK that the referenced project belongs to the user, or that the user is a member of it. Restrict updates to the project_id column.

#### Secure Code Example

```sql
CREATE POLICY "Users can create tasks" ON public.tasks FOR INSERT TO authenticated
WITH CHECK (
  owner_id = auth.uid()
  AND EXISTS (SELECT 1 FROM public.projects p WHERE p.id = project_id AND p.owner_id = auth.uid())
);

CREATE POLICY "Users can update tasks" ON public.tasks FOR UPDATE TO authenticated
USING (owner_id = auth.uid())
WITH CHECK (
  owner_id = auth.uid()
  AND EXISTS (SELECT 1 FROM public.projects p WHERE p.id = project_id AND p.owner_id = auth.uid())
);
```

#### Confidence

Medium — the weakness is plausible but depends on context outside the analyzed code.

#### Validation Notes

Related locations: supabase/migrations/002_access_policies.sql:65 (Comment insert lacks a task access check).

### Finding 8: task_comments policies do not tie access to task ownership

**Finding ID:** AR-008

**Severity:** Medium

**Category:** Broken Access Control

**CWE:** CWE-639 (OWASP Top 10: A01:2021 Broken Access Control)

**Affected File:** `supabase/migrations/002_access_policies.sql`

**Code Location:** lines 57-69

#### Description

The SELECT sub-query is true for any existing task, so every comment is readable by any authenticated user. The INSERT policy checks only author_id, so users can comment on any task_id.

#### Vulnerable Code

```sql
USING (
  EXISTS (
    SELECT 1
    FROM public.tasks
    WHERE tasks.id = task_comments.task_id
  )
);

CREATE POLICY "Users can add task comments"
ON public.task_comments
FOR INSERT
TO authenticated
WITH CHECK (author_id = auth.uid());
```

#### Potential Impact

Users can read comments on private tasks and post comments on tasks they have no access to.

#### Recommended Fix

Make the sub-query check that the caller can access the parent task (owner or project owner) in both SELECT and INSERT.

#### Secure Code Example

```sql
DROP POLICY "Users can view task comments" ON public.task_comments;
CREATE POLICY "Users can view task comments" ON public.task_comments FOR SELECT TO authenticated
USING (EXISTS (SELECT 1 FROM public.tasks t WHERE t.id = task_comments.task_id AND t.owner_id = auth.uid()));

DROP POLICY "Users can add task comments" ON public.task_comments;
CREATE POLICY "Users can add task comments" ON public.task_comments FOR INSERT TO authenticated
WITH CHECK (author_id = auth.uid() AND EXISTS (SELECT 1 FROM public.tasks t WHERE t.id = task_id AND t.owner_id = auth.uid()));
```

#### Confidence

Medium — the weakness is plausible but depends on context outside the analyzed code.

#### Validation Notes

No further validation is needed beyond reviewing the recommended fix in context.

### Finding 9: Hardcoded credential-like analytics key in source

**Finding ID:** AR-009

**Severity:** Low

**Category:** Hardcoded Secrets

**CWE:** CWE-798 (OWASP Top 10: A07:2021 Identification and Authentication Failures)

**Affected File:** `src/lib/demoConfig.ts`

**Code Location:** lines 7-9

#### Description

A credential-like API key is hardcoded in client source. The value is placeholder-like and located in demo config.

#### Vulnerable Code

```typescript
analytics: {
  enabled: true,
  apiKey: "<REDACTED:credential:len=35:placeholder-like=yes>",
```

#### Potential Impact

If it is a real key, it would be exposed to anyone with the bundle.

#### Recommended Fix

Confirm it is a non-production or public write key. Otherwise load it from build-time environment variables and rotate it.

#### Secure Code Example

```typescript
apiKey: import.meta.env.VITE_ANALYTICS_KEY,
```

#### Confidence

Low — the weakness is plausible but depends on context outside the analyzed code.

#### Validation Notes

Confirm that this is a placeholder or a public analytics write key, not a production secret.

### Finding 10: Wildcard CORS on a state-changing endpoint

**Finding ID:** AR-010

**Severity:** Low

**Category:** Security Misconfiguration

**CWE:** CWE-942 (OWASP Top 10: A05:2021 Security Misconfiguration)

**Affected File:** `supabase/functions/update-task/index.ts`

**Code Location:** line 5

#### Description

The write endpoint allows any origin to call it from the browser.

#### Vulnerable Code

```typescript
"Access-Control-Allow-Origin": "*",
```

#### Potential Impact

Any website can invoke the endpoint. Combined with the missing authentication, this makes cross-origin abuse trivial.

#### Recommended Fix

Restrict the allowed origin to the known front-end origin(s) and require authentication.

#### Secure Code Example

```typescript
const allowed = Deno.env.get("ALLOWED_ORIGIN") ?? "";
const corsHeaders = {
  "Access-Control-Allow-Origin": allowed,
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
```

#### Confidence

Medium — the weakness is plausible but depends on context outside the analyzed code.

#### Validation Notes

Impact is limited if JWT auth is added, since no cookies are used.

### Finding 11: Verbose error details leaked to client

**Finding ID:** AR-011

**Severity:** Low

**Category:** Security Misconfiguration

**CWE:** CWE-209 (OWASP Top 10: A05:2021 Security Misconfiguration)

**Affected File:** `supabase/functions/update-task/index.ts`

**Code Location:** lines 55-58

#### Description

The raw database/exception error is returned to the caller.

#### Vulnerable Code

```typescript
return Response.json(
  {
    error: "Unable to update task",
    details: String(error),
```

#### Potential Impact

Reveals schema, constraint and internal details that help an attacker refine attacks.

#### Recommended Fix

Log errors server-side and return a generic message.

#### Secure Code Example

```typescript
console.error("update-task failed:", error);
return Response.json({ error: "Unable to update task" }, { status: 500, headers: corsHeaders });
```

#### Confidence

High — the weakness is directly evident in the code shown.

#### Validation Notes

Related locations: supabase/functions/get-profile/index.ts:43 (Returns String(error) to the client).

### Finding 12: Profiles readable by all authenticated users (all columns)

**Finding ID:** AR-012

**Severity:** Low

**Category:** Broken Access Control

**CWE:** CWE-284 (OWASP Top 10: A01:2021 Broken Access Control)

**Affected File:** `supabase/migrations/002_access_policies.sql`

**Code Location:** lines 9-13

#### Description

Every authenticated user can read every profile row, including role and bio.

#### Vulnerable Code

```sql
CREATE POLICY "Users can view profiles"
ON public.profiles
FOR SELECT
TO authenticated
USING (true);
```

#### Potential Impact

User enumeration and exposure of role information.

#### Recommended Fix

Limit to own row, or expose a view with only the public columns.

#### Secure Code Example

```sql
CREATE POLICY "Users can view own profile"
ON public.profiles FOR SELECT TO authenticated
USING (id = auth.uid());
```

#### Confidence

Medium — the weakness is plausible but depends on context outside the analyzed code.

#### Validation Notes

This may be intended if profiles are public within the app.

## 5. Remediation Summary

| Finding | Severity | Recommended Action |
|---|---|---|
| AR-001 | Critical | Use parameterized queries with the tagged template, and escape LIKE wildcards if needed |
| AR-002 | Critical | Verify the caller's JWT and derive the user from it |
| AR-003 | High | Render the text as a normal React text node so it is auto-escaped |
| AR-004 | High | Authenticate the caller via JWT and use their user id, or use a user-scoped client so RLS applies |
| AR-005 | High | Prevent role changes with a WITH CHECK that compares against the existing role, or revoke column UPDATE privileges and grant only safe columns |
| AR-006 | Medium | Restrict reads to the owner, or to project members |
| AR-007 | Medium | Require in WITH CHECK that the referenced project belongs to the user, or that the user is a member of it |
| AR-008 | Medium | Make the sub-query check that the caller can access the parent task (owner or project owner) in both SELECT and INSERT |
| AR-009 | Low | Confirm it is a non-production or public write key |
| AR-010 | Low | Restrict the allowed origin to the known front-end origin(s) and require authentication |
| AR-011 | Low | Log errors server-side and return a generic message |
| AR-012 | Low | Limit to own row, or expose a view with only the public columns |

## 6. Overall Assessment

Overall risk rating: Critical.

The security posture is weak at the server edge. Several functions skip authentication and use privileged credentials, so database-level protections are bypassed entirely. The row-level policies are also loose in places, most importantly the self-service role change. The client-side XSS sink compounds the risk.

Fix the unauthenticated and injectable functions first, since they are directly exploitable by anyone. Then close the role escalation and XSS issues. Next, review the task, comment and project policies against the intended sharing model. Finally, clean up error messages, CORS and the demo configuration.

Recommended order of work:

1. Parameterize the search-tasks query (no sql.unsafe) and use a least-privilege database role.
2. Require authentication in update-task and get-profile, verify ownership, whitelist updatable fields, and use the caller's JWT instead of the service-role key.
3. Prevent users from changing their own role (column-level grants or a trigger/WITH CHECK that keeps role unchanged).
4. Sanitize or stop using dangerouslySetInnerHTML for comment text.
5. Tighten tasks, comments and project_id policies to match the intended ownership model.

The report is an AI-assisted source-code assessment, not a complete penetration test.

## 7. Scope and Limitations

- Static code review only
- No exploit execution
- No runtime penetration testing
- No guarantee that every vulnerability is found
- Some findings may require manual confirmation
- Analyzed 18 source files (951 lines); 1 secret-like value(s) were redacted before AI analysis
- AI model: claude-sonnet-5-5 (some responses reused from cache)
- Every reported finding's quoted evidence was checked programmatically against the cited file and line
- AI review candidates: 32; dropped because evidence could not be verified: 0; rejected during lead review: 0; merged as duplicates: 20

## 8. Conclusion

Address high-impact issues first and validate the remediation using appropriate testing.

A follow-up security review is recommended after the changes are implemented.
