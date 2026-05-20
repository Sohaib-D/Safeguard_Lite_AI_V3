import { LoginForm } from "../../components/auth/LoginForm";
import { AuthGuard } from "../../components/layout/AuthGuard";

export default function LoginPage() {
  return (
    <AuthGuard requireAuth={false}>
      <div className="min-h-[100dvh] flex flex-col justify-center items-center p-4 sm:p-8 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-bg-tertiary via-bg-primary to-bg-primary relative overflow-hidden">
        {/* Background Decorative Elements */}
        <div className="absolute top-[-20%] left-[-10%] w-96 h-96 bg-accent-cyan/10 blur-[100px] rounded-full pointer-events-none" />
        <div className="absolute bottom-[-20%] right-[-10%] w-96 h-96 bg-accent-violet/10 blur-[100px] rounded-full pointer-events-none" />
        
        <LoginForm />
        
        <div className="mt-8 text-center text-xs text-text-secondary opacity-60">
          <p>By signing in, you agree to our Terms of Service and Privacy Policy.</p>
          <p className="mt-1">© 2024 Safeguard-AI Security. All rights reserved.</p>
        </div>
      </div>
    </AuthGuard>
  );
}
