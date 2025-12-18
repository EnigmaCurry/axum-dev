<script>
  import { Button } from "$lib/components/ui/button/index.js";
  import * as Card from "$lib/components/ui/card/index.js";
  import { Input } from "$lib/components/ui/input/index.js";
  import { csrf } from '$lib/csrf';
  import {
    FieldGroup,
    Field,
    FieldLabel,
    FieldDescription,
  } from "$lib/components/ui/field/index.js";
    const { id, action = "/api/login" } = $props();
</script>
<Card.Root class="mx-auto w-full max-w-sm">
  <Card.Header>
    <Card.Title class="text-2xl">Sign in</Card.Title>
    <Card.Description>Enter your account credentials:</Card.Description>
  </Card.Header>
  <Card.Content>
    <form method="post" action={action} use:csrf>
      <FieldGroup>
        <Field>
          <FieldLabel for="email-{id}">Email</FieldLabel>
          <Input id="email-{id}" name="email" type="email" placeholder="m@example.com" required />
        </Field>
        <Field>
          <div class="flex items-center">
            <FieldLabel for="password-{id}">Password</FieldLabel>
            <!-- <a href="#" class="ms-auto inline-block text-sm underline"> -->
            <!--   Forgot your password? -->
            <!-- </a> -->
          </div>
          <Input id="password-{id}" name="password" type="password" required />
        </Field>
        <Field>
          <Button type="submit" class="w-full">Login</Button>
          <!-- <FieldDescription class="text-center"> -->
          <!--   Don't have an account? <a href="#">Sign up</a> -->
          <!-- </FieldDescription> -->
        </Field>
      </FieldGroup>
    </form>
  </Card.Content>
</Card.Root>
