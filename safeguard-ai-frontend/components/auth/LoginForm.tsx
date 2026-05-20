"use client";

import { useState } from "react";
import { useForm } from "react-hook-form";
import { useRouter } from "next/navigation";
import { authAPI } from "../../lib/api";
import { useAppStore } from "../../store/useAppStore";
import { getRole } from "../../lib/auth";
import { Shield, Lock, User, AlertCircle, CheckCircle2, Loader2 } from "lucide-react";
import { cn } from "../../lib/utils";

export function LoginForm() {
  const [activeTab, setActiveTab] = useState<"signin" | "signup">("signin");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const router = useRouter();
  const setAuth = useAppStore(state => state.setAuth);

  const { register: registerSignIn, handleSubmit: handleSignIn, formState: { errors: signInErrors } } = useForm();
  const { register: registerSignUp, handleSubmit: handleSignUp, watch, formState: { errors: signUpErrors } } = useForm();
  const password = watch("password");

  const onSignIn = async (data: any) => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await authAPI.login({
        username: data.username,
        password: data.password
      });
      const role = getRole(res.username || data.username);
      setAuth(res.access_token, res.username || data.username, role);
      router.push("/app/home");
    } catch (err: any) {
      if (err.response?.status === 401) {
        setError("Wrong username or password.");
      } else if (!err.response) {
        setError("Backend is waking up... Please wait 30 seconds and try again.");
      } else {
        setError(err.response?.data?.detail || "Sign in failed.");
      }
    } finally {
      setIsLoading(false);
    }
  };

  const onSignUp = async (data: any) => {
    setIsLoading(true);
    setError(null);
    setSuccess(null);
    try {
      await authAPI.createAdmin({
        username: data.username,
        password: data.password
      });
      setSuccess("Account created successfully. Please sign in.");
      setActiveTab("signin");
    } catch (err: any) {
      if (!err.response) {
        setError("Backend is waking up... Please wait 30 seconds and try again.");
      } else {
        setError(err.response?.data?.detail || "Registration failed.");
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="w-full max-w-md bg-bg-secondary border border-border-subtle rounded-2xl shadow-xl overflow-hidden">
      <div className="flex border-b border-border-subtle">
        <button
          onClick={() => { setActiveTab("signin"); setError(null); setSuccess(null); }}
          className={cn("flex-1 py-4 text-sm font-medium transition-colors", activeTab === "signin" ? "text-accent-cyan border-b-2 border-accent-cyan bg-accent-cyan/5" : "text-text-secondary hover:text-text-primary hover:bg-bg-tertiary")}
        >
          🔑 Sign In
        </button>
        <button
          onClick={() => { setActiveTab("signup"); setError(null); setSuccess(null); }}
          className={cn("flex-1 py-4 text-sm font-medium transition-colors", activeTab === "signup" ? "text-accent-cyan border-b-2 border-accent-cyan bg-accent-cyan/5" : "text-text-secondary hover:text-text-primary hover:bg-bg-tertiary")}
        >
          📝 Sign Up
        </button>
      </div>

      <div className="p-6 sm:p-8">
        <div className="flex justify-center mb-6">
          <div className="bg-accent-cyan/10 p-3 rounded-xl border border-accent-cyan/20">
            <Shield className="w-10 h-10 text-accent-cyan" />
          </div>
        </div>
        <h2 className="text-2xl font-bold text-center text-text-primary mb-2">Safeguard-AI Lite</h2>
        <p className="text-sm text-center text-text-secondary mb-8">Security Intelligence Platform</p>

        {error && (
          <div className="mb-6 p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg flex gap-3 text-sm text-rose-500">
            <AlertCircle className="w-5 h-5 shrink-0" />
            <p>{error}</p>
          </div>
        )}

        {success && (
          <div className="mb-6 p-3 bg-emerald-500/10 border border-emerald-500/20 rounded-lg flex gap-3 text-sm text-emerald-500">
            <CheckCircle2 className="w-5 h-5 shrink-0" />
            <p>{success}</p>
          </div>
        )}

        {activeTab === "signin" ? (
          <form onSubmit={handleSignIn(onSignIn)} className="space-y-4">
            <div>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <User className="h-5 w-5 text-text-secondary" />
                </div>
                <input
                  {...registerSignIn("username", { required: "Username is required" })}
                  type="text"
                  placeholder="Username or Email"
                  className="block w-full pl-10 pr-3 py-3 border border-border-subtle rounded-xl bg-bg-primary text-text-primary placeholder-text-secondary focus:outline-none focus:ring-2 focus:ring-accent-cyan focus:border-transparent text-[16px]"
                  enterKeyHint="next"
                />
              </div>
              {signInErrors.username && <p className="mt-1 text-xs text-rose-500">{signInErrors.username.message as string}</p>}
            </div>
            
            <div>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-text-secondary" />
                </div>
                <input
                  {...registerSignIn("password", { required: "Password is required" })}
                  type="password"
                  placeholder="Password"
                  className="block w-full pl-10 pr-3 py-3 border border-border-subtle rounded-xl bg-bg-primary text-text-primary placeholder-text-secondary focus:outline-none focus:ring-2 focus:ring-accent-cyan focus:border-transparent text-[16px]"
                  enterKeyHint="done"
                />
              </div>
              {signInErrors.password && <p className="mt-1 text-xs text-rose-500">{signInErrors.password.message as string}</p>}
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full flex justify-center items-center py-3 px-4 border border-transparent rounded-xl shadow-sm text-sm font-medium text-bg-primary bg-accent-cyan hover:bg-accent-cyan/90 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-accent-cyan disabled:opacity-50 disabled:cursor-not-allowed transition-colors min-h-[48px]"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                  Waking up Backend...
                </>
              ) : (
                "Sign In"
              )}
            </button>
          </form>
        ) : (
          <form onSubmit={handleSignUp(onSignUp)} className="space-y-4">
            <div>
              <input
                {...registerSignUp("username", { required: "Username is required", minLength: { value: 3, message: "Minimum 3 characters" } })}
                type="text"
                placeholder="Choose Username"
                className="block w-full px-4 py-3 border border-border-subtle rounded-xl bg-bg-primary text-text-primary placeholder-text-secondary focus:outline-none focus:ring-2 focus:ring-accent-cyan focus:border-transparent text-[16px]"
              />
              {signUpErrors.username && <p className="mt-1 text-xs text-rose-500">{signUpErrors.username.message as string}</p>}
            </div>
            
            <div>
              <input
                {...registerSignUp("password", { required: "Password is required", minLength: { value: 6, message: "Minimum 6 characters" } })}
                type="password"
                placeholder="Create Password"
                className="block w-full px-4 py-3 border border-border-subtle rounded-xl bg-bg-primary text-text-primary placeholder-text-secondary focus:outline-none focus:ring-2 focus:ring-accent-cyan focus:border-transparent text-[16px]"
              />
              {signUpErrors.password && <p className="mt-1 text-xs text-rose-500">{signUpErrors.password.message as string}</p>}
            </div>

            <div>
              <input
                {...registerSignUp("confirmPassword", { 
                  required: "Please confirm your password",
                  validate: value => value === password || "Passwords do not match"
                })}
                type="password"
                placeholder="Confirm Password"
                className="block w-full px-4 py-3 border border-border-subtle rounded-xl bg-bg-primary text-text-primary placeholder-text-secondary focus:outline-none focus:ring-2 focus:ring-accent-cyan focus:border-transparent text-[16px]"
                enterKeyHint="done"
              />
              {signUpErrors.confirmPassword && <p className="mt-1 text-xs text-rose-500">{signUpErrors.confirmPassword.message as string}</p>}
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full flex justify-center items-center py-3 px-4 border border-transparent rounded-xl shadow-sm text-sm font-medium text-bg-primary bg-accent-violet hover:bg-accent-violet/90 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-accent-violet disabled:opacity-50 disabled:cursor-not-allowed transition-colors min-h-[48px]"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                  Waking up Backend...
                </>
              ) : (
                "Create Account"
              )}
            </button>

            <div className="mt-4 p-4 bg-bg-tertiary rounded-xl border border-border-subtle">
              <h4 className="text-xs font-semibold text-text-primary uppercase tracking-wider mb-2">Included Features:</h4>
              <ul className="text-xs text-text-secondary space-y-1">
                <li>• Network Security Scanner</li>
                <li>• Real-time SOC Dashboard</li>
                <li>• Deep ML Predictions</li>
                <li>• Custom Threat Analysis</li>
              </ul>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
