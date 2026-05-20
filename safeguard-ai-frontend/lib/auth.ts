import { useAppStore } from '../store/useAppStore';

export const ADMIN_USERNAMES = process.env.NEXT_PUBLIC_ADMIN_USERNAMES?.split(',').map(s => s.trim()) || ['admin', 'Sohaib'];

export function isAdmin(username: string | null): boolean {
  if (!username) return false;
  return ADMIN_USERNAMES.includes(username);
}

export function getRole(username: string): 'admin' | 'user' {
  return isAdmin(username) ? 'admin' : 'user';
}

export function logout() {
  useAppStore.getState().clearAuth();
  if (typeof window !== 'undefined') {
    window.location.href = '/app';
  }
}
