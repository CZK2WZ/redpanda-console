/**
 * Copyright 2026 Redpanda Data, Inc.
 *
 * Use of this software is governed by the Business Source License
 * included in the file https://github.com/redpanda-data/redpanda/blob/dev/licenses/bsl.md
 *
 * As of the Change Date specified in that file, in accordance with
 * the Business Source License, use of this software will be governed
 * by the Apache License, Version 2.0
 */

import { Code, ConnectError } from '@connectrpc/connect';
import { afterEach, beforeEach, describe, expect, rs, test } from '@rstest/core';
import userEvent from '@testing-library/user-event';
import { AuthenticationMethod, SASLMechanism } from 'protogen/redpanda/api/console/v1alpha1/authentication_pb';
import { act, renderWithFileRoutes, screen } from 'test-utils';

import LoginPage from './login';
import { config as appConfig } from '../../config';

const LOGIN_URL = /\/auth\/login\/oidc$/;
const LOGIN_URL_WITH_HC_DEV = /\/auth\/login\/oidc\?hcFunction=hc-dev$/;
const LOGIN_OPTIONS_URL = /\/auth\/login\/oidc\/options$/;
const LOGIN_OPTIONS_ERROR = /failed to load login options: 500/;

describe('the LoginPage', () => {
  const initialAuthClient = appConfig.authenticationClient;
  const loginSaslScram = rs.fn();

  beforeEach(() => {
    loginSaslScram.mockReset();
    appConfig.authenticationClient = {
      listAuthenticationMethods: () => Promise.resolve({ methods: [AuthenticationMethod.BASIC] }),
      loginSaslScram,
    } as unknown as typeof appConfig.authenticationClient;
  });

  afterEach(() => {
    appConfig.authenticationClient = initialAuthClient;
  });

  test('shows a rejected password inline and re-enables the form', async () => {
    const reject = rejectNextLogin(loginSaslScram);
    const user = userEvent.setup();

    renderWithFileRoutes(<LoginPage />, { initialLocation: '/login' });

    const submit = await submitCredentials(user, 'e2euser', 'not-the-password');

    expectSingleLoginRequest(loginSaslScram, submit);

    act(() => {
      reject(new ConnectError('invalid credentials', Code.Unauthenticated));
    });

    const alert = await screen.findByTestId('auth-error');
    expect(alert).toHaveTextContent('invalid credentials');
    expect(submit).toBeEnabled();
    expect(screen.getByTestId('auth-password-input')).toBeEnabled();
  });
});

describe('the LoginPage with OIDC', () => {
  const initialAuthClient = appConfig.authenticationClient;

  beforeEach(() => {
    appConfig.authenticationClient = {
      listAuthenticationMethods: () => Promise.resolve({ methods: [AuthenticationMethod.OIDC] }),
    } as unknown as typeof appConfig.authenticationClient;
  });

  afterEach(() => {
    appConfig.authenticationClient = initialAuthClient;
    rs.restoreAllMocks();
  });

  function renderWithLoginOptions(response: Response) {
    const fetchMock = rs.spyOn(globalThis, 'fetch').mockResolvedValue(response);
    const assign = rs.spyOn(window.location, 'assign').mockImplementation(() => undefined);
    renderWithFileRoutes(<LoginPage />, { initialLocation: '/login' });
    return { fetchMock, assign, user: userEvent.setup() };
  }

  test('keeps the login button disabled until an HC function is selected', async () => {
    const { fetchMock, assign, user } = renderWithLoginOptions(Response.json({ hcFunctions: ['hc-admin', 'hc-dev'] }));

    const loginButton = await screen.findByTestId('oidc-login-button');
    expect(fetchMock).toHaveBeenCalledWith(expect.stringMatching(LOGIN_OPTIONS_URL), expect.anything());
    expect(loginButton).toBeDisabled();

    await selectHcFunction(user, 'hc-dev');
    expect(loginButton).toBeEnabled();

    await user.click(loginButton);
    expect(assign).toHaveBeenCalledWith(expect.stringMatching(LOGIN_URL_WITH_HC_DEV));
  });

  test('enables the login button without a selection when no HC functions are configured', async () => {
    const { assign, user } = renderWithLoginOptions(Response.json({ hcFunctions: [] }));

    const loginButton = await screen.findByTestId('oidc-login-button');
    await expect.poll(() => (loginButton as HTMLButtonElement).disabled).toBe(false);
    expect(screen.queryByRole('combobox', { name: 'HC function' })).not.toBeInTheDocument();

    await user.click(loginButton);
    expect(assign).toHaveBeenCalledWith(expect.stringMatching(LOGIN_URL));
  });

  test('keeps the login button disabled when the login options cannot be loaded', async () => {
    renderWithLoginOptions(new Response('boom', { status: 500, statusText: 'Internal Server Error' }));

    expect(await screen.findByText(LOGIN_OPTIONS_ERROR)).toBeInTheDocument();
    expect(screen.getByTestId('oidc-login-button')).toBeDisabled();
  });
});

async function selectHcFunction(user: ReturnType<typeof userEvent.setup>, name: string) {
  await user.click(await screen.findByRole('combobox', { name: 'HC function' }));
  await user.click(await screen.findByRole('option', { name }));
}

function rejectNextLogin(login: ReturnType<typeof rs.fn>) {
  let reject!: (reason: unknown) => void;
  login.mockImplementation(
    () =>
      new Promise((_, rejectPromise) => {
        reject = rejectPromise;
      })
  );
  return (reason: unknown) => reject(reason);
}

async function submitCredentials(user: ReturnType<typeof userEvent.setup>, username: string, password: string) {
  await user.type(await screen.findByTestId('auth-username-input'), username);
  await user.type(screen.getByTestId('auth-password-input'), password);
  const submit = screen.getByTestId('auth-submit');
  await user.click(submit);
  return submit;
}

function expectSingleLoginRequest(login: ReturnType<typeof rs.fn>, submit: HTMLElement) {
  // In flight: one request went out and the button cannot fire a second one.
  expect(login).toHaveBeenCalledTimes(1);
  expect(login).toHaveBeenCalledWith(
    expect.objectContaining({
      username: 'e2euser',
      password: 'not-the-password',
      mechanism: SASLMechanism.SASL_MECHANISM_SCRAM_SHA_256,
    })
  );
  expect(submit).toBeDisabled();
}
