/**
 * Runs once when the Next.js server starts. Validates configuration so a
 * deployment with missing/weak secrets fails fast instead of serving traffic.
 */
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { validateStartup } = await import("./instrumentation-node");
    validateStartup();
  }
}
