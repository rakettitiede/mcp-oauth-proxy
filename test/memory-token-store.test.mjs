import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createMemoryTokenStore } from '../src/memory-token-store.mjs';

describe('createMemoryTokenStore', () => {
  it('set + get returns the stored entry', () => {
    const store = createMemoryTokenStore();
    const entry = { tokens: { access_token: 'tok-1' }, expiresAt: Date.now() + 60_000 };
    store.set('code-1', entry);
    assert.deepStrictEqual(store.get('code-1'), entry);
  });

  it('get on unknown code returns undefined', () => {
    const store = createMemoryTokenStore();
    assert.strictEqual(store.get('no-such-code'), undefined);
  });

  it('delete removes an entry', () => {
    const store = createMemoryTokenStore();
    const entry = { tokens: { access_token: 'tok-2' }, expiresAt: Date.now() + 60_000 };
    store.set('code-2', entry);
    store.delete('code-2');
    assert.strictEqual(store.get('code-2'), undefined);
  });

  it('get lazy-expires an entry whose expiresAt < Date.now()', () => {
    const store = createMemoryTokenStore();
    const entry = { tokens: { access_token: 'tok-3' }, expiresAt: Date.now() - 1 };
    store.set('code-3', entry);

    // First get should return undefined (expired)
    assert.strictEqual(store.get('code-3'), undefined);
    // Second get confirms eviction (not just a one-time filter)
    assert.strictEqual(store.get('code-3'), undefined);
  });

  it('get on a non-expired entry does not evict it', () => {
    const store = createMemoryTokenStore();
    const entry = { tokens: { access_token: 'tok-4' }, expiresAt: Date.now() + 60_000 };
    store.set('code-4', entry);

    assert.deepStrictEqual(store.get('code-4'), entry);
    assert.deepStrictEqual(store.get('code-4'), entry);
  });
});
