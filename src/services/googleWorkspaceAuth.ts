import { initializeApp, getApps, getApp, FirebaseApp } from 'firebase/app';
import {
  getAuth,
  signInWithPopup,
  GoogleAuthProvider,
  onAuthStateChanged,
  User,
  Auth,
} from 'firebase/auth';
import firebaseConfig from '../../firebase-applet-config.json';

export const SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'];

let firebaseApp: FirebaseApp | null = null;
let firebaseAuth: Auth | null = null;

function ensureFirebaseAuth(): Auth {
  if (!firebaseApp) {
    firebaseApp = getApps().length > 0 ? getApp() : initializeApp(firebaseConfig);
  }
  if (!firebaseAuth) {
    firebaseAuth = getAuth(firebaseApp);
  }
  return firebaseAuth;
}

const provider = new GoogleAuthProvider();
for (const scope of SCOPES) {
  provider.addScope(scope);
}

// Store Google OAuth access token strictly in memory (never in localStorage or sessionStorage)
let isSigningIn = false;
let cachedGmailAccessToken: string | null = null;

export const initGmailAuth = (
  onAuthSuccess?: (user: User, token: string) => void,
  onAuthFailure?: () => void
) => {
  const auth = ensureFirebaseAuth();
  return onAuthStateChanged(auth, (user: User | null) => {
    if (user && cachedGmailAccessToken) {
      onAuthSuccess?.(user, cachedGmailAccessToken);
    } else if (!isSigningIn) {
      if (!user) cachedGmailAccessToken = null;
      onAuthFailure?.();
    }
  });
};

export const connectGmailWithPopup = async (): Promise<{
  user: User;
  accessToken: string;
}> => {
  const auth = ensureFirebaseAuth();
  isSigningIn = true;
  try {
    const result = await signInWithPopup(auth, provider);
    const credential = GoogleAuthProvider.credentialFromResult(result);
    if (!credential?.accessToken) {
      throw new Error('Google sign-in completed, but no Gmail access token was issued.');
    }
    cachedGmailAccessToken = credential.accessToken;
    return { user: result.user, accessToken: cachedGmailAccessToken };
  } finally {
    isSigningIn = false;
  }
};

export const getGmailAccessToken = (): string | null => cachedGmailAccessToken;

export const getConnectedGoogleUser = (): User | null => {
  try {
    return ensureFirebaseAuth().currentUser;
  } catch {
    return null;
  }
};

export const disconnectGmail = async (): Promise<void> => {
  cachedGmailAccessToken = null;
  try {
    const auth = ensureFirebaseAuth();
    await auth.signOut();
  } catch {
    // Ignore if already signed out
  }
};
