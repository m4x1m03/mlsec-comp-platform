// src/lib/auth.ts
export async function getSession(request: Request) {
  const cookie = request.headers.get('cookie') ?? '';

  const apiUrl = process.env.API_INTERNAL_URL ?? 'http://localhost:8000';
  const res = await fetch(`${apiUrl}/auth/me`, {
    headers: { cookie }, // forward the browser's cookie to FastAPI
  });

  if (!res.ok) return null;

  const data = await res.json();
  // data.user has { email, username, is_admin, ... }
  return { user: data.user };
}