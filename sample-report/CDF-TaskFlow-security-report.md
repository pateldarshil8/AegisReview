# Security Assessment Report

## 1. Assessment Information

**Application:** CDF TaskFlow

**Assessment Type:** AI-Assisted Static Code Review

**Assessment Date:** 2026-11-04

**Tool Name:** AegisReview v1.0.0

**AI Model:** Google Gemini (some responses reused from cache)

**Overall Risk Rating:** Critical

## 2. Executive Summary

The CDF TaskFlow application contains several critical security vulnerabilities that expose sensitive data and allow unauthorized control over the system. The most severe issues involve a raw SQL injection vulnerability in the search feature and architectural flaws in backend functions that allow attackers to modify or view any task and user profile in the database. Furthermore, a privilege escalation bug allows standard users to grant themselves administrative rights. These issues represent a significant risk to data integrity and privacy, requiring immediate remediation before the application is used in any production environment.

**Top priorities**

1. Refactor the 'search-tasks' function to use parameterized queries instead of raw SQL string interpolation.
2. Implement JWT validation and identity-based authorization checks in all Edge Functions, especially those using service role keys.
3. Modify the 'profiles' update policy to restrict users from updating the 'role' column.
4. Implement HTML sanitization for task comments to prevent stored XSS attacks.
5. Restrict Row Level Security (RLS) for the 'tasks' and 'profiles' tables to follow the principle of least privilege.

## 3. Findings Summary

| Severity | Count |
|---|---:|
| Critical | 2 |
| High | 4 |
| Medium | 2 |
| Low | 3 |
| Info | 0 |
| **Total** | **11** |

| ID | Severity | Title | Location | Status |
|---|---|---|---|---|
| AR-001 | Critical | SQL Injection in search-tasks function | `supabase/functions/search-tasks/index.ts` lines 20-28 | Confirmed |
| AR-002 | Critical | Broken Object Level Authorization (BOLA) and Authentication Bypass in update-task | `supabase/functions/update-task/index.ts` lines 31-41 | Confirmed |
| AR-003 | High | Cross-Site Scripting (XSS) in TaskComments | `src/components/TaskComments.tsx` lines 40-41 | Confirmed |
| AR-004 | High | Insecure Direct Object Reference (IDOR) in get-profile | `supabase/functions/get-profile/index.ts` lines 28-32 | Confirmed |
| AR-005 | High | Privilege Escalation via Profile Update Policy | `supabase/migrations/002_access_policies.sql` lines 15-20 | Confirmed |
| AR-006 | High | Excessive Data Exposure in Task RLS Policy | `supabase/migrations/002_access_policies.sql` line 38 | Confirmed |
| AR-007 | Medium | Permissive CORS Policy | `supabase/functions/update-task/index.ts` line 5 | Confirmed |
| AR-008 | Medium | Overly Permissive Row Level Security (Profiles) | `supabase/migrations/002_access_policies.sql` lines 9-13 | Confirmed |
| AR-009 | Low | Hardcoded credential-like value | `src/lib/demoConfig.ts` line 9 | Needs validation |
| AR-010 | Low | Insecure Configuration: Debug Mode Enabled | `src/lib/demoConfig.ts` lines 12-14 | Confirmed |
| AR-011 | Low | Information Disclosure (Sensitive Error Details) | `supabase/functions/get-profile/index.ts` lines 42-45 | Confirmed |

## 4. Detailed Findings

### AR-001: SQL Injection in search-tasks function

**Severity:** Critical  
**Category:** Injection  
**CWE:** CWE-89  
**OWASP:** A03:2021 Injection  
**Affected File:** `supabase/functions/search-tasks/index.ts`  
**Code Location:** lines 20-28  
**Status:** Confirmed  
**Confidence:** High

#### Description

The search term is concatenated directly into a SQL query string and executed using the 'unsafe' method of the postgres library. This allows an attacker to manipulate the query and potentially extract data from any table in the database.

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

An attacker can perform arbitrary database queries, leading to full data exfiltration from the tasks table and potentially other tables in the database.

#### Recommended Fix

Use tagged template literals provided by the postgres library to safely parameterize the query instead of string concatenation and 'unsafe'.

#### Secure Code Example

```typescript
const tasks = await sql`SELECT id, title, description, status FROM public.tasks WHERE title ILIKE ${'%' + searchTerm + '%'} ORDER BY created_at DESC LIMIT 25`;
```

### AR-002: Broken Object Level Authorization (BOLA) and Authentication Bypass in update-task

**Severity:** Critical  
**Category:** Broken Access Control  
**CWE:** CWE-285  
**OWASP:** A01:2021-Broken Access Control  
**Affected File:** `supabase/functions/update-task/index.ts`  
**Code Location:** lines 31-41  
**Status:** Confirmed  
**Confidence:** High

#### Description

The function uses the Supabase service role key to bypass all Row Level Security (RLS) and does not verify the identity or authorization of the requester. Any user, or even an unauthenticated attacker, can provide an arbitrary taskId and changes to update any task in the system.

#### Vulnerable Code

```typescript
const supabase = createClient(
  Deno.env.get("SUPABASE_URL") ?? "",
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
);

const { data, error } = await supabase
  .from("tasks")
  .update(changes)
  .eq("id", taskId)
  .select()
  .single();
```

#### Potential Impact

Unauthorized modification of any task, including changing its title, description, status, or even ownership.

#### Recommended Fix

Initialize the Supabase client with the user's own JWT from the 'Authorization' header and verify the user's identity using 'supabase.auth.getUser()'. Ensure RLS is enforced or manually check that the requesting user owns the task before updating.

#### Secure Code Example

```typescript
    const authHeader = request.headers.get('Authorization')!;
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_ANON_KEY") ?? "",
      { global: { headers: { Authorization: authHeader } } }
    );
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) throw new Error("Unauthorized");

    const { data, error } = await supabase
      .from("tasks")
      .update(changes)
      .eq("id", taskId)
      .eq("owner_id", user.id)
      .select()
      .single();
```

#### Related Locations

- `supabase/functions/update-task/index.ts:36` (Mass Assignment in update-task function)

### AR-003: Cross-Site Scripting (XSS) in TaskComments

**Severity:** High  
**Category:** Cross-Site Scripting (XSS)  
**CWE:** CWE-79  
**OWASP:** A03:2021 Injection  
**Affected File:** `src/components/TaskComments.tsx`  
**Code Location:** lines 40-41  
**Status:** Confirmed  
**Confidence:** High

#### Description

User-supplied comment text is rendered directly as raw HTML using 'dangerouslySetInnerHTML' without any sanitization. This allows an attacker to inject and execute arbitrary JavaScript by submitting a comment containing malicious HTML tags or attributes.

#### Vulnerable Code

```tsx
dangerouslySetInnerHTML={{
  __html: comment.text,
```

#### Potential Impact

An attacker can execute arbitrary scripts in the browsers of other users who view the comment, potentially stealing session tokens or performing actions on behalf of the user.

#### Recommended Fix

Avoid using 'dangerouslySetInnerHTML' for user-controlled text. Render the text as standard React children which are automatically escaped.

#### Secure Code Example

```tsx
<div>{comment.text}</div>
```

### AR-004: Insecure Direct Object Reference (IDOR) in get-profile

**Severity:** High  
**Category:** Broken Access Control  
**CWE:** CWE-639  
**OWASP:** A01:2021 Broken Access Control  
**Affected File:** `supabase/functions/get-profile/index.ts`  
**Code Location:** lines 28-32  
**Status:** Confirmed  
**Confidence:** High

#### Description

The function retrieves user profile data based on a user-supplied 'userId' parameter without verifying if the requester is authenticated or authorized to access that profile. The use of 'SUPABASE_SERVICE_ROLE_KEY' explicitly bypasses Row Level Security.

#### Vulnerable Code

```typescript
const { data, error } = await supabase
  .from("profiles")
  .select("*")
  .eq("id", userId)
  .single();
```

#### Potential Impact

Any user or anonymous visitor can retrieve the full profile information (including potential sensitive defaults) of any user by guessing or obtaining their UUID.

#### Recommended Fix

Implement authentication using the Supabase client's auth.getUser(jwt) method and restrict profile access based on the authenticated user's context, or use the user's own token to initialize the client.

#### Secure Code Example

```typescript
const authHeader = request.headers.get('Authorization');
const supabase = createClient(Deno.env.get('SUPABASE_URL'), Deno.env.get('SUPABASE_ANON_KEY'), { global: { headers: { Authorization: authHeader } } });
const { data: { user } } = await supabase.auth.getUser();
if (!user) return Response.json({ error: 'Unauthorized' }, { status: 401 });
const { data, error } = await supabase.from('profiles').select('*').eq('id', userId).single();
```

### AR-005: Privilege Escalation via Profile Update Policy

**Severity:** High  
**Category:** Broken Access Control  
**CWE:** CWE-285  
**OWASP:** A01:2021-Broken Access Control  
**Affected File:** `supabase/migrations/002_access_policies.sql`  
**Code Location:** lines 15-20  
**Status:** Confirmed  
**Confidence:** High

#### Description

The update policy for the profiles table only checks if the user is the owner of the profile, but it does not restrict which columns can be updated. Since the profiles table contains a 'role' column, any user can update their own role from 'member' to 'admin'.

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

A regular user can escalate their privileges to administrator status, gaining unauthorized access to admin features.

#### Recommended Fix

Modify the 'WITH CHECK' clause to ensure the 'role' column is not modified unless the user is already an admin, or use a database trigger to prevent role changes.

#### Secure Code Example

```sql
CREATE POLICY "Users can update own profile"
ON public.profiles
FOR UPDATE
TO authenticated
USING (id = auth.uid())
WITH CHECK (
  id = auth.uid() 
  AND role = (SELECT role FROM public.profiles WHERE id = auth.uid())
);
```

### AR-006: Excessive Data Exposure in Task RLS Policy

**Severity:** High  
**Category:** Broken Access Control  
**CWE:** CWE-285  
**OWASP:** A01:2021 Broken Access Control  
**Affected File:** `supabase/migrations/002_access_policies.sql`  
**Code Location:** line 38  
**Status:** Confirmed  
**Confidence:** High

#### Description

The Row Level Security policy for the 'tasks' table allows any authenticated user to view all tasks in the database regardless of project membership or ownership. This violates the principle of least privilege.

#### Vulnerable Code

```sql
USING (true);
```

#### Potential Impact

Authenticated users can see tasks belonging to projects they do not own or are not members of, leading to unauthorized information disclosure.

#### Recommended Fix

Restrict the SELECT policy for tasks to only those where the user is the owner or is a member of the associated project.

#### Secure Code Example

```sql
CREATE POLICY "Users can view tasks"
ON public.tasks
FOR SELECT
TO authenticated
USING (owner_id = auth.uid() OR EXISTS (SELECT 1 FROM public.projects WHERE projects.id = tasks.project_id AND projects.owner_id = auth.uid()));
```

#### Related Locations

- `supabase/migrations/002_access_policies.sql:34` (Over-permissive SELECT Policy for Tasks)

### AR-007: Permissive CORS Policy

**Severity:** Medium  
**Category:** Security Misconfiguration  
**CWE:** CWE-942  
**OWASP:** A05:2021 Security Misconfiguration  
**Affected File:** `supabase/functions/update-task/index.ts`  
**Code Location:** line 5  
**Status:** Confirmed  
**Confidence:** High

#### Description

The function uses a wildcard ('*') for the Access-Control-Allow-Origin header.

#### Vulnerable Code

```typescript
"Access-Control-Allow-Origin": "*",
```

#### Potential Impact

This allows any website to make requests to the edge function, increasing the surface for cross-site attacks if the endpoint is not otherwise properly protected.

#### Recommended Fix

Restrict allowed origins to the specific domains used by the application.

#### Secure Code Example

```typescript
"Access-Control-Allow-Origin": "https://your-app.com",
```

### AR-008: Overly Permissive Row Level Security (Profiles)

**Severity:** Medium  
**Category:** Broken Access Control  
**CWE:** CWE-284  
**OWASP:** A01:2021 Broken Access Control  
**Affected File:** `supabase/migrations/002_access_policies.sql`  
**Code Location:** lines 9-13  
**Status:** Confirmed  
**Confidence:** High

#### Description

The RLS policy allows any authenticated user to view all records in the profiles table.

#### Vulnerable Code

```sql
CREATE POLICY "Users can view profiles"
ON public.profiles
FOR SELECT
TO authenticated
USING (true);
```

#### Potential Impact

This leads to information disclosure where any registered user can scrape the full list of users and their profile details.

#### Recommended Fix

Restrict the policy so users can only view their own profile or profiles associated with their projects.

#### Secure Code Example

```sql
CREATE POLICY "Users can view own profile"
ON public.profiles
FOR SELECT
TO authenticated
USING (id = auth.uid());
```

### AR-009: Hardcoded credential-like value

**Severity:** Low  
**Category:** Identification and Authentication Failures  
**CWE:** CWE-798  
**OWASP:** A07:2021 Identification and Authentication Failures  
**Affected File:** `src/lib/demoConfig.ts`  
**Code Location:** line 9  
**Status:** Needs validation  
**Confidence:** High

#### Description

A hardcoded API key for an analytics service was found in the configuration file. Hardcoding credentials in source code is a security risk as they are checked into version control.

#### Vulnerable Code

```typescript
apiKey: "<REDACTED:credential:len=35:placeholder-like=yes>",
```

#### Potential Impact

If this is a production key, an attacker could abuse the analytics account, leading to data manipulation or financial costs.

#### Recommended Fix

Move the API key to an environment variable (e.g., VITE_ANALYTICS_KEY) and access it via import.meta.env.

#### Secure Code Example

```typescript
apiKey: import.meta.env.VITE_ANALYTICS_KEY,
```

#### Validation Notes

Confirm if this is a real production key or a placeholder for development.

### AR-010: Insecure Configuration: Debug Mode Enabled

**Severity:** Low  
**Category:** Security Misconfiguration  
**CWE:** CWE-16  
**OWASP:** A05:2021 Security Misconfiguration  
**Affected File:** `src/lib/demoConfig.ts`  
**Code Location:** lines 12-14  
**Status:** Confirmed  
**Confidence:** High

#### Description

Verbose debugging is enabled in the configuration, which is dangerous if deployed to production.

#### Vulnerable Code

```typescript
debug: {
  enabled: true,
  logLevel: "verbose",
```

#### Potential Impact

Excessive logging can expose sensitive internal state, data, or application logic to anyone with access to the console or log output.

#### Recommended Fix

Disable debug mode by default and use environment variables to toggle it only for development environments.

#### Secure Code Example

```typescript
debug: {
  enabled: import.meta.env.DEV,
  logLevel: import.meta.env.DEV ? "verbose" : "error",
},
```

### AR-011: Information Disclosure (Sensitive Error Details)

**Severity:** Low  
**Category:** Security Misconfiguration  
**CWE:** CWE-209  
**OWASP:** A05:2021 Security Misconfiguration  
**Affected File:** `supabase/functions/get-profile/index.ts`  
**Code Location:** lines 42-45  
**Status:** Confirmed  
**Confidence:** High

#### Description

The function returns the raw error string to the client in the event of an exception.

#### Vulnerable Code

```typescript
} catch (error) {
  return Response.json(
    { error: String(error) },
    { status: 500 }
```

#### Potential Impact

This may reveal internal system details, such as database schema information or stack traces, which can aid an attacker in further exploits.

#### Recommended Fix

Log the error internally and return a generic error message to the client.

#### Secure Code Example

```typescript
  } catch (error) {
    console.error(error);
    return Response.json({ error: "Internal Server Error" }, { status: 500 });
  }
```

## 5. Remediation Summary

| Finding | Severity | Recommended Action |
|---|---|---|
| AR-001 | Critical | Use tagged template literals provided by the postgres library to safely parameterize the query instead of string concatenation and 'unsafe' |
| AR-002 | Critical | Initialize the Supabase client with the user's own JWT from the 'Authorization' header and verify the user's identity using 'supabase.auth.getUser()' |
| AR-003 | High | Avoid using 'dangerouslySetInnerHTML' for user-controlled text |
| AR-004 | High | Implement authentication using the Supabase client's auth.getUser(jwt) method and restrict profile access based on the authenticated user's context, or use the user's own token to initialize the client |
| AR-005 | High | Modify the 'WITH CHECK' clause to ensure the 'role' column is not modified unless the user is already an admin, or use a database trigger to prevent role changes |
| AR-006 | High | Restrict the SELECT policy for tasks to only those where the user is the owner or is a member of the associated project |
| AR-007 | Medium | Restrict allowed origins to the specific domains used by the application |
| AR-008 | Medium | Restrict the policy so users can only view their own profile or profiles associated with their projects |
| AR-009 | Low | Move the API key to an environment variable (e.g., VITE_ANALYTICS_KEY) and access it via import.meta.env |
| AR-010 | Low | Disable debug mode by default and use environment variables to toggle it only for development environments |
| AR-011 | Low | Log the error internally and return a generic error message to the client |

## 6. Overall Assessment

The overall security posture of the project is poor. There is a systemic failure to implement secure authorization patterns, particularly in the Deno Edge Functions where administrative 'service role' keys are used to bypass database security without implementing alternative identity checks. This, combined with high-risk coding practices like raw SQL interpolation and unsafe HTML rendering, makes the application highly vulnerable to multiple classes of attack.

Remediation should focus on securing the data access layer first. This includes fixing the SQL injection in the search function and replacing the insecure Edge Function authorization logic. Following this, database Row Level Security (RLS) policies should be tightened to enforce proper project-based isolation, and front-end rendering should be secured against XSS.

## 7. Scope and Limitations

- Static code review only; no exploit execution or runtime testing
- AI-generated findings should be validated before being treated as confirmed vulnerabilities
- Every reported finding's quoted evidence was checked programmatically against the cited file and line
- No guarantee that every vulnerability was found
- Files analyzed: 18 (951 lines)
- Secret-like values redacted before AI analysis: 1
- AI review candidates: 23; dropped because evidence could not be verified: 0; rejected during lead review: 0

## 8. Conclusion

Address high-impact issues first and validate each remediation with appropriate testing. A follow-up review is recommended after the changes are applied.
