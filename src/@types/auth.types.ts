export interface SignupInput {
  name: string;
  email: string;
  password: string;
}

export interface SignupResult {
  id: string;
  email: string;
  name: string;
  role: string;
  createdAt: Date;
}

export interface VerifyEmailInput {
  token: string;
}

export interface VerifyEmailResult {
  message: string;
}

export interface ResendVerificationEmailInput {
  email: string;
}

export interface ResendVerificationEmailResult {
  message: string;
}

export interface SigninInput {
  email: String;
  password: String;
}

export interface SigninResult {
  accessToken: string;
  refreshToken: string;
  user: {
    id: string;
    email: string;
    role: string;
  };
}
