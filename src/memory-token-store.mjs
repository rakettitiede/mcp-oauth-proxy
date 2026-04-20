/**
 * TokenStore contract
 *
 * Any object that implements these three methods can be passed as
 * `tokenStore` to `createOAuthRouter`. Methods may be sync or async —
 * the router always `await`s them.
 *
 *   get(code)          → entry | undefined
 *                        entry = { tokens, expiresAt }
 *                        Must lazy-expire: if expiresAt < Date.now(),
 *                        delete the entry and return undefined.
 *
 *   set(code, entry)   → void
 *                        entry = { tokens, expiresAt }
 *
 *   delete(code)       → void
 *
 * This module exports a factory for a simple in-memory implementation
 * backed by a Map. For production use, implement the contract against
 * Firestore, Redis, or another persistent store.
 */

/**
 * Creates an in-memory token store backed by a Map.
 * Entries are lazily expired on `get()`.
 *
 * @returns {{ get(code: string): object|undefined, set(code: string, entry: object): void, delete(code: string): void }}
 */
export function createMemoryTokenStore() {
  const map = new Map();

  return {
    get(code) {
      const entry = map.get(code);
      if (!entry) return undefined;
      if (entry.expiresAt < Date.now()) {
        map.delete(code);
        return undefined;
      }
      return entry;
    },

    set(code, entry) {
      map.set(code, entry);
    },

    delete(code) {
      map.delete(code);
    },
  };
}
