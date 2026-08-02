import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { Button, Card, ErrorNote, Field, Input } from '../components/ui';
import { api } from '../lib/api';

/**
 * Sign-in: password, then TOTP. §1.3 makes 2FA mandatory, so there is no path
 * through this screen that reaches the console with only a password.
 *
 * Three states rather than two, because a brand-new admin has no second factor
 * yet and must enrol one before they can get in at all.
 */

type Stage = 'password' | 'totp' | 'enrol' | 'recovery';

interface LoginResponse {
  status: 'totp_required' | 'totp_enrolment_required';
  mustChangePassword: boolean;
}

interface EnrolmentResponse {
  secret: string;
  otpauthUri: string;
  qrDataUrl: string;
}

export function LoginPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [stage, setStage] = useState<Stage>('password');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [enrolment, setEnrolment] = useState<EnrolmentResponse | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);

  const finish = async () => {
    // Invalidate rather than push a value: /me returns the resolved permission
    // set, and that is what the whole UI keys off.
    await queryClient.invalidateQueries({ queryKey: ['me'] });
    navigate('/users', { replace: true });
  };

  const passwordStep = useMutation({
    mutationFn: () => api.post<LoginResponse>('/api/auth/login', { email, password }),
    onSuccess: async (data) => {
      if (data.status === 'totp_enrolment_required') {
        const enrol = await api.post<EnrolmentResponse>('/api/auth/totp/enrolment');
        setEnrolment(enrol);
        setStage('enrol');
      } else {
        setStage('totp');
      }
    },
  });

  const verifyStep = useMutation({
    mutationFn: () => api.post('/api/auth/totp/verify', { code }),
    onSuccess: finish,
  });

  const confirmEnrolment = useMutation({
    mutationFn: () =>
      api.post<{ recoveryCodes: string[]; message: string }>(
        '/api/auth/totp/enrolment/confirm',
        { code },
      ),
    onSuccess: (data) => setRecoveryCodes(data.recoveryCodes),
  });

  const recoveryStep = useMutation({
    mutationFn: () => api.post('/api/auth/totp/recovery', { recoveryCode }),
    onSuccess: finish,
  });

  // Shown once, after enrolment. Deliberately blocks progress until confirmed —
  // these codes are the only way back in after a lost device.
  if (recoveryCodes) {
    return (
      <Centered>
        <Card title="Save your recovery codes">
          <p className="mb-4 text-sm text-slate-600 dark:text-slate-400">
            Each code works once. They are the only way into this account if you lose your
            authenticator. They will not be shown again.
          </p>
          <ul className="mb-4 grid grid-cols-2 gap-2 font-mono text-sm">
            {recoveryCodes.map((rc) => (
              <li key={rc} className="rounded bg-slate-100 px-2 py-1 dark:bg-slate-800">
                {rc}
              </li>
            ))}
          </ul>
          <Button variant="primary" className="w-full" onClick={finish}>
            I have saved these
          </Button>
        </Card>
      </Centered>
    );
  }

  return (
    <Centered>
      {stage === 'password' && (
        <Card title="Sign in" description="NeverOff admin and trust & safety console">
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              passwordStep.mutate();
            }}
          >
            <Field label="Email" htmlFor="email">
              <Input
                id="email"
                type="email"
                autoComplete="username"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </Field>
            <Field label="Password" htmlFor="password">
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </Field>
            <ErrorNote error={passwordStep.error} />
            <Button
              type="submit"
              variant="primary"
              className="w-full"
              disabled={passwordStep.isPending}
            >
              {passwordStep.isPending ? 'Checking…' : 'Continue'}
            </Button>
          </form>
        </Card>
      )}

      {stage === 'enrol' && enrolment && (
        <Card
          title="Set up two-factor authentication"
          description="Every admin account requires a second factor. This is not optional."
        >
          <div className="space-y-4">
            <img
              src={enrolment.qrDataUrl}
              alt="QR code for enrolling this account in your authenticator app"
              className="mx-auto rounded bg-white p-2"
              width={240}
              height={240}
            />
            <p className="text-center text-xs text-slate-600 dark:text-slate-400">
              Can’t scan? Enter this key manually:
              <br />
              <code className="font-mono text-sm">{enrolment.secret}</code>
            </p>

            <form
              className="space-y-4"
              onSubmit={(e) => {
                e.preventDefault();
                confirmEnrolment.mutate();
              }}
            >
              <Field label="Enter the 6-digit code" htmlFor="enrol-code">
                <Input
                  id="enrol-code"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="\d{6}"
                  maxLength={6}
                  required
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                />
              </Field>
              <ErrorNote error={confirmEnrolment.error} />
              <Button
                type="submit"
                variant="primary"
                className="w-full"
                disabled={confirmEnrolment.isPending}
              >
                Confirm
              </Button>
            </form>
          </div>
        </Card>
      )}

      {stage === 'totp' && (
        <Card title="Two-factor authentication">
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              verifyStep.mutate();
            }}
          >
            <Field
              label="Authenticator code"
              htmlFor="code"
              hint="Six digits from your authenticator app."
            >
              <Input
                id="code"
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="\d{6}"
                maxLength={6}
                required
                autoFocus
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
              />
            </Field>
            <ErrorNote error={verifyStep.error} />
            <Button
              type="submit"
              variant="primary"
              className="w-full"
              disabled={verifyStep.isPending}
            >
              {verifyStep.isPending ? 'Verifying…' : 'Sign in'}
            </Button>
            <Button variant="ghost" className="w-full" onClick={() => setStage('recovery')}>
              Use a recovery code instead
            </Button>
          </form>
        </Card>
      )}

      {stage === 'recovery' && (
        <Card
          title="Use a recovery code"
          description="Each code works once. Using one raises an alert, so make sure this is you."
        >
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              recoveryStep.mutate();
            }}
          >
            <Field label="Recovery code" htmlFor="recovery">
              <Input
                id="recovery"
                required
                autoFocus
                value={recoveryCode}
                onChange={(e) => setRecoveryCode(e.target.value)}
              />
            </Field>
            <ErrorNote error={recoveryStep.error} />
            <Button
              type="submit"
              variant="primary"
              className="w-full"
              disabled={recoveryStep.isPending}
            >
              Sign in
            </Button>
            <Button variant="ghost" className="w-full" onClick={() => setStage('totp')}>
              Back
            </Button>
          </form>
        </Card>
      )}
    </Centered>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-md">{children}</div>
    </div>
  );
}
