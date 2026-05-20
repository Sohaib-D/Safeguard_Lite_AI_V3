import { useEffect, useState } from 'react';
import { useAppStore } from '../store/useAppStore';
import { useRouter } from 'next/navigation';

export function useAuth(requireAuth = true) {
  const router = useRouter();
  const { authToken, authUser, authRole } = useAppStore();
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  useEffect(() => {
    if (isMounted && requireAuth && !authToken) {
      router.push('/app');
    }
  }, [isMounted, authToken, requireAuth, router]);

  return {
    isAuthenticated: !!authToken,
    user: authUser,
    role: authRole,
    isMounted
  };
}
