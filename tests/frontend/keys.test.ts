import { describe, expect, it } from "vitest";
import { jwtMultiauthAdminKeys, jwtMultiauthKeys } from "../../frontend/src/hooks/keys.js";

describe("jwtMultiauthKeys", () => {
  it("drops the params slot entirely when called with no argument", () => {
    expect(jwtMultiauthKeys.sessions()).toEqual(["jwt_multiauth", "sessions"]);
    expect(jwtMultiauthKeys.trustedDevices()).toEqual(["jwt_multiauth", "trusted-devices"]);
  });

  it("includes the params object when given one", () => {
    expect(jwtMultiauthKeys.sessions({ page: 2 })).toEqual([
      "jwt_multiauth",
      "sessions",
      { page: 2 },
    ]);
    expect(jwtMultiauthKeys.trustedDevices({ page: 1 })).toEqual([
      "jwt_multiauth",
      "trusted-devices",
      { page: 1 },
    ]);
  });

  it("methods()/twoFactorStatus() are fixed keys", () => {
    expect(jwtMultiauthKeys.methods()).toEqual(["jwt_multiauth", "methods"]);
    expect(jwtMultiauthKeys.twoFactorStatus()).toEqual(["jwt_multiauth", "two-factor-status"]);
  });
});

describe("jwtMultiauthAdminKeys", () => {
  it("drops the params/userId slot entirely when called with no argument", () => {
    expect(jwtMultiauthAdminKeys.sessions()).toEqual(["jwt_multiauth_admin", "sessions"]);
    expect(jwtMultiauthAdminKeys.trustedDevices()).toEqual([
      "jwt_multiauth_admin",
      "trusted-devices",
    ]);
    expect(jwtMultiauthAdminKeys.loginAttempts()).toEqual([
      "jwt_multiauth_admin",
      "login-attempts",
    ]);
    expect(jwtMultiauthAdminKeys.userSecurity()).toEqual([
      "jwt_multiauth_admin",
      "users",
      "security",
    ]);
  });

  it("includes the params/userId when given one — under a SEPARATE root from jwtMultiauthKeys", () => {
    expect(jwtMultiauthAdminKeys.sessions({ user: 1 })).toEqual([
      "jwt_multiauth_admin",
      "sessions",
      { user: 1 },
    ]);
    expect(jwtMultiauthAdminKeys.trustedDevices({ user: 1 })).toEqual([
      "jwt_multiauth_admin",
      "trusted-devices",
      { user: 1 },
    ]);
    expect(jwtMultiauthAdminKeys.loginAttempts({ user: 1 })).toEqual([
      "jwt_multiauth_admin",
      "login-attempts",
      { user: 1 },
    ]);
    expect(jwtMultiauthAdminKeys.userSecurity(42)).toEqual([
      "jwt_multiauth_admin",
      "users",
      42,
      "security",
    ]);
  });
});
