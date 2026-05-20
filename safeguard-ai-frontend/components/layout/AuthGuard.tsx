"use client";

import { ReactNode } from "react";
import { useAuth } from "../../hooks/useAuth";
import { LoadingSpinner } from "../ui/LoadingSpinner";
import { FloatingAssistant } from "../ui/FloatingAssistant";

interface AuthGuardProps {
  children: ReactNode;
  requireAuth?: boolean;
}

export function AuthGuard({ children, requireAuth = true }: AuthGuardProps) {
  const { isMounted, isAuthenticated } = useAuth(requireAuth);

  if (!isMounted) {
    return <div className="min-h-screen bg-bg-primary flex items-center justify-center"><LoadingSpinner /></div>;
  }

  // If requireAuth is true and not authenticated, useAuth hook will redirect
  if (requireAuth && !isAuthenticated) {
    return null;
  }

  return (
    <>
      {children}
      <FloatingAssistant />
    </>
  );
}
