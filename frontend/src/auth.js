export function clearAuthTokens(storage = globalThis.localStorage) {
  storage.removeItem("gds_access_token");
  storage.removeItem("gds_refresh_token");
}

export function logoutSession({
  storage = globalThis.localStorage,
  apiUrl,
  fetchImpl = globalThis.fetch,
}) {
  const tokens = [
    storage.getItem("gds_access_token"),
    storage.getItem("gds_refresh_token"),
  ].filter(Boolean);
  clearAuthTokens(storage);
  return Promise.allSettled(tokens.map((token) => fetchImpl(`${apiUrl}/auth/logout`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  })));
}
