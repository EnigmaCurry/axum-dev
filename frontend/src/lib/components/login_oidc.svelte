<script>
  import { onMount } from "svelte";
  import { Button } from "$lib/components/ui/button/index.js";
  import * as Card from "$lib/components/ui/card/index.js";

  const {
    id,
    whoami = "/api/whoami",
    // IMPORTANT: this must be a GET endpoint that returns a 3xx redirect to the IdP
    loginAction = "/api/login",
    logoutAction = "/api/logout",
    // optional: caller can override the return path
    next = null,
  } = $props();

  let externalUserId = $state("");
  let csrfToken = $state("");
  let isLoggedIn = $state(false);
  let loading = $state(false);
  let errorMsg = $state("");

  function applyWhoami(json) {
    const session = json?.data?.session;
    csrfToken = typeof session?.csrf_token === "string" ? session.csrf_token : "";
    externalUserId =
      typeof session?.external_user_id === "string" ? session.external_user_id : "";
    isLoggedIn = !!session?.is_logged_in;
  }

  async function fetchWhoami() {
    const res = await fetch(whoami, { credentials: "include" });
    const json = await res.json().catch(() => null);
    applyWhoami(json);
    return { res, json };
  }

  onMount(fetchWhoami);

  async function ensureCsrf() {
    if (csrfToken) return true;
    await fetchWhoami();
    return !!csrfToken;
  }

  function computeNext() {
    if (typeof next === "string" && next.length > 0) return next;
    if (typeof window !== "undefined") {
      return window.location.pathname + window.location.search + window.location.hash;
    }
    return "/";
  }

  async function postJson(url, bodyObj) {
    return fetch(url, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
      },
      body: bodyObj ? JSON.stringify(bodyObj) : "{}",
    });
  }

  async function submitLogout() {
    loading = true;
    errorMsg = "";

    if (!(await ensureCsrf())) {
      loading = false;
      errorMsg = "Could not retrieve CSRF token. Please refresh and try again.";
      return;
    }

    let res = await postJson(logoutAction, null);
    let json = await res.json().catch(() => null);

    // retry once on csrf mismatch
    if (
      res.status === 401 &&
      (json?.error?.code === "csrf_invalid" || json?.error?.code === "csrf_missing")
    ) {
      await fetchWhoami();
      res = await postJson(logoutAction, null);
      json = await res.json().catch(() => null);
    }

    if (!res.ok || json?.error) {
      errorMsg =
        json?.error?.message ??
        json?.error ??
        `Logout failed (HTTP ${res.status})`;
      loading = false;
      return;
    }

    await fetchWhoami();
    loading = false;
  }
</script>

<Card.Root class="mx-auto w-full max-w-sm">
  <Card.Header>
    {#if isLoggedIn}
      <Card.Title class="text-2xl">You’re signed in</Card.Title>
      <Card.Description>
        Signed in as <span class="font-mono">{externalUserId || "(unknown)"}</span>
      </Card.Description>
    {:else}
      <Card.Title class="text-2xl">Sign in</Card.Title>
      <Card.Description>Continue with your identity provider:</Card.Description>
    {/if}
  </Card.Header>

  <Card.Content>
    {#if errorMsg}
      <p class="mb-3 text-sm text-red-600">{errorMsg}</p>
    {/if}

    {#if isLoggedIn}
      <Button class="w-full" onclick={submitLogout} disabled={loading}>
        {loading ? "Signing out…" : "Logout"}
      </Button>
    {:else}
      <!-- REAL navigation. No fetch. -->
      <form method="GET" action={loginAction}>
        <input type="hidden" name="next" value={computeNext()} />
        <Button type="submit" class="w-full">
          Sign in with OIDC
        </Button>
      </form>
    {/if}
  </Card.Content>
</Card.Root>
