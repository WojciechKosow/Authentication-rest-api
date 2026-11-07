import { ApiError } from "@/lib/errors";
import { route } from "@/lib/http";

// JSON 404 for every unknown path/method combination.
const notFound = route(
  async () => {
    throw new ApiError("NOT_FOUND");
  },
  { gateway: false },
);

export const GET = notFound;
export const POST = notFound;
export const PUT = notFound;
export const PATCH = notFound;
export const DELETE = notFound;
