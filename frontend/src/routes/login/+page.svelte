<script lang="ts">
  import LoginForm from "$lib/components/login_oidc.svelte";
</script>
<div class="flex h-screen w-full items-center justify-center px-4">
  <LoginForm id="login" action="/api/login" />
</div>
