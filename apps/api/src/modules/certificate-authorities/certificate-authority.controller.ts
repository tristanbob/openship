/**
 * HTTP handlers for /system/certificate-authorities. Instance-scoped operator
 * config (like /system/settings/email) — writes are owner-gated in the routes.
 */

import type { Context } from "hono";
import { param } from "../../lib/controller-helpers";
import { safeErrorMessage } from "@repo/core";
import {
  createCa,
  deleteCa,
  listCas,
  setDefaultCa,
  testCa,
  updateCa,
  type CaProfileInput,
} from "./certificate-authority.service";

export async function list(c: Context) {
  return c.json({ data: await listCas() });
}

export async function create(c: Context) {
  const body = await c.req.json<CaProfileInput>().catch(() => null);
  if (!body) return c.json({ error: "A JSON body is required" }, 400);
  try {
    return c.json({ data: await createCa(body) });
  } catch (err) {
    return c.json({ error: safeErrorMessage(err) }, 400);
  }
}

export async function update(c: Context) {
  const id = param(c, "id");
  const body = await c.req.json<CaProfileInput>().catch(() => null);
  if (!body) return c.json({ error: "A JSON body is required" }, 400);
  try {
    return c.json({ data: await updateCa(id, body) });
  } catch (err) {
    const message = safeErrorMessage(err);
    return c.json({ error: message }, message.includes("not found") ? 404 : 400);
  }
}

export async function setDefault(c: Context) {
  try {
    return c.json({ data: await setDefaultCa(param(c, "id")) });
  } catch (err) {
    return c.json({ error: safeErrorMessage(err) }, 404);
  }
}

export async function remove(c: Context) {
  try {
    await deleteCa(param(c, "id"));
    return c.json({ data: { ok: true } });
  } catch (err) {
    return c.json({ error: safeErrorMessage(err) }, 404);
  }
}

export async function test(c: Context) {
  try {
    return c.json({ data: await testCa(param(c, "id")) });
  } catch (err) {
    return c.json({ error: safeErrorMessage(err) }, 404);
  }
}
