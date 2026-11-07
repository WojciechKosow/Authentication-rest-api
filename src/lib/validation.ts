import { z } from "zod";
import { REFRESH_TOKEN_PATTERN } from "./sessions";

export const emailField = z
  .string({ error: "email is required" })
  .trim()
  .toLowerCase()
  .max(254, "email is too long")
  .pipe(z.email({ error: "email must be a valid email address" }));

export const passwordField = z
  .string({ error: "password is required" })
  .min(8, "password must be at least 8 characters")
  .max(128, "password must be at most 128 characters");

const refreshTokenField = z
  .string({ error: "refresh_token is required" })
  .regex(REFRESH_TOKEN_PATTERN, "refresh_token is malformed");

const oneTimeTokenField = z
  .string({ error: "token is required" })
  .regex(/^(ev|pr)_[A-Za-z0-9_-]{43}$/, "token is malformed");

export const registerSchema = z.strictObject({ email: emailField, password: passwordField });
export const loginSchema = z.strictObject({ email: emailField, password: passwordField });
export const refreshSchema = z.strictObject({ refresh_token: refreshTokenField });
export const logoutSchema = z.strictObject({
  refresh_token: refreshTokenField.optional(),
  all_sessions: z.boolean().optional(),
});
export const validateSchema = z.strictObject({
  access_token: z.string({ error: "access_token is required" }).min(1).max(4096),
});
export const emailRequestSchema = z.strictObject({ email: emailField });
export const verifyEmailConfirmSchema = z.strictObject({ token: oneTimeTokenField });
export const passwordResetConfirmSchema = z.strictObject({ token: oneTimeTokenField, new_password: passwordField });
