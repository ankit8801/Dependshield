import { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { authApi } from '../api/client';

/**
 * AuthContext — global authentication state for DependShield.
 *
 * Strategy: HttpOnly cookie is the source of truth.
 * On app load, we call /auth/me to hydrate the user from the server.
 * This means even after page reload, auth state is preserved without
 * storing anything sensitive in localStorage.
 *
 * State:
 *  - user: { id, email, createdAt } | null
 *  - loading: true while hydrating from /auth/me
 *  - isAuthenticated: derived from !!user
 */
const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Hydrate auth state from server on mount
  useEffect(() => {
    const hydrate = async () => {
      try {
        const res = await authApi.me();
        setUser(res.data.data.user);
      } catch {
        // 401 = not authenticated — normal state on first visit
        setUser(null);
      } finally {
        setLoading(false);
      }
    };
    hydrate();
  }, []);

  // Listen for the global 401 event dispatched by the API client interceptor
  useEffect(() => {
    const handleUnauthorized = () => {
      setUser(null);
    };
    window.addEventListener('auth:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('auth:unauthorized', handleUnauthorized);
  }, []);

  const login = useCallback(async (email, password) => {
    const res = await authApi.login(email, password);
    setUser(res.data.data.user);
    return res.data.data.user;
  }, []);

  const register = useCallback(async (email, password) => {
    const res = await authApi.register(email, password);
    setUser(res.data.data.user);
    return res.data.data.user;
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } finally {
      setUser(null);
    }
  }, []);

  const value = {
    user,
    loading,
    isAuthenticated: !!user,
    login,
    register,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

/**
 * Hook for consuming auth context.
 * Must be used within an <AuthProvider>.
 */
export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
};

export default AuthContext;
