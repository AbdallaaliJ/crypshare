import type { DirectoryUser } from '../types/api';
import { hashSHA256 } from './crypto';

export interface TrustedIdentityRecord {
  username: string;
  fingerprint: string;
  identityPublicKeyECDH: string;
  identityPublicKeyECDSA: string;
  trustedAt: number;
}

export interface TrustStatus {
  fingerprint: string;
  trusted: boolean;
  changed: boolean;
  record?: TrustedIdentityRecord;
}

export interface WorkspaceInvitePackageInput {
  workspaceName: string;
  workspaceId: string;
  inviteCode: string;
  inviteExpiresAt: number;
  inviterUsername: string;
  inviterFingerprint: string;
}

export interface ParsedWorkspaceInvitePackage {
  workspaceName: string;
  workspaceId: string;
  inviteCode: string;
  expires: string;
  inviterUsername: string;
  fingerprint: string;
}

const STORE_PREFIX = 'crypshare.trusted-identities';
const PENDING_INVITE_KEY = 'crypshare.pending-invite-url';

function storageKey(ownerUsername: string) {
  return `${STORE_PREFIX}.${ownerUsername}`;
}

function readTrustedIdentities(ownerUsername: string): Record<string, TrustedIdentityRecord> {
  try {
    const raw = window.localStorage.getItem(storageKey(ownerUsername));
    return raw ? JSON.parse(raw) as Record<string, TrustedIdentityRecord> : {};
  } catch {
    return {};
  }
}

function writeTrustedIdentities(ownerUsername: string, records: Record<string, TrustedIdentityRecord>) {
  window.localStorage.setItem(storageKey(ownerUsername), JSON.stringify(records));
}

export async function identityFingerprint(identity: DirectoryUser) {
  return hashSHA256([
    'crypshare-identity-v1',
    identity.username,
    identity.identityPublicKeyECDH,
    identity.identityPublicKeyECDSA
  ].join(':'));
}

export function formatFingerprint(fingerprint: string) {
  return fingerprint
    .slice(0, 32)
    .match(/.{1,4}/g)
    ?.join(' ')
    .toUpperCase() || fingerprint.toUpperCase();
}

export function normalizeFingerprint(value: string) {
  return value.replace(/[^a-f0-9]/gi, '').toLowerCase();
}

export function fingerprintMatches(actualFingerprint: string, candidate: string) {
  const normalizedActual = normalizeFingerprint(actualFingerprint);
  const normalizedCandidate = normalizeFingerprint(candidate);
  return normalizedCandidate.length >= 32 && normalizedActual.startsWith(normalizedCandidate);
}

function appOrigin() {
  return typeof window === 'undefined' ? 'https://crypshare.local' : window.location.origin;
}

function encodeInvitePayload(params: Record<string, string | number>) {
  const json = JSON.stringify(params);
  const encoded = btoa(unescape(encodeURIComponent(json)));
  return encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeInvitePayload(value: string) {
  try {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(value.length / 4) * 4, '=');
    return JSON.parse(decodeURIComponent(escape(atob(padded)))) as Record<string, string | number>;
  } catch {
    return {};
  }
}

function createInviteUrl(path: string, params: Record<string, string | number>) {
  const url = new URL(path, appOrigin());
  url.hash = `crypshareInvite=${encodeInvitePayload(params)}`;
  return url.toString();
}

function parseInviteUrl(inviteText: string) {
  const trimmed = inviteText.trim();
  if (!trimmed) return null;

  try {
    return new URL(trimmed);
  } catch {
    try {
      return new URL(trimmed, appOrigin());
    } catch {
      return null;
    }
  }
}

function getInvitePayload(url: URL | null) {
  if (!url?.hash) return {};
  const hashParams = new URLSearchParams(url.hash.replace(/^#/, ''));
  return decodeInvitePayload(hashParams.get('crypshareInvite') || hashParams.get('invite') || '');
}

function getUrlParam(url: URL | null, names: string[]) {
  if (!url) return '';

  const payload = getInvitePayload(url);
  for (const name of names) {
    const value = payload[name];
    if (value) return String(value).trim();
  }

  for (const name of names) {
    const value = url.searchParams.get(name);
    if (value) return value.trim();
  }

  return '';
}

export function createIdentityInvite(username: string, fingerprint: string) {
  return createInviteUrl('/dashboard/contacts', {
    inviteType: 'identity',
    username,
    fingerprint: normalizeFingerprint(fingerprint)
  });
}

function extractField(inviteText: string, fieldNames: string[]) {
  for (const fieldName of fieldNames) {
    const match = inviteText.match(new RegExp(`^\\s*${fieldName}\\s*:\\s*(.+?)\\s*$`, 'im'));
    if (match?.[1]) return match[1].trim();
  }

  return '';
}

export function createWorkspaceInvitePackage(input: WorkspaceInvitePackageInput) {
  return createInviteUrl('/dashboard/workspace-admin', {
    inviteType: 'workspace',
    workspace: input.workspaceName,
    workspaceId: input.workspaceId,
    inviteCode: input.inviteCode,
    expires: input.inviteExpiresAt,
    inviter: input.inviterUsername,
    fingerprint: normalizeFingerprint(input.inviterFingerprint)
  });
}

export function parseWorkspaceInvitePackage(inviteText: string): ParsedWorkspaceInvitePackage {
  const url = parseInviteUrl(inviteText);
  const workspaceId = getUrlParam(url, ['workspaceId', 'workspaceid', 'wid', 'id']);
  const inviteCode = getUrlParam(url, ['inviteCode', 'invitecode', 'code']);
  const inviterUsername = getUrlParam(url, ['inviter', 'username', 'u']);
  const fingerprint = getUrlParam(url, ['fingerprint', 'fp']);
  const workspaceName = getUrlParam(url, ['workspace', 'workspaceName', 'name']);
  const expires = getUrlParam(url, ['expires', 'expiry', 'exp']);

  if (workspaceId || inviteCode || inviterUsername || fingerprint || workspaceName || expires) {
    return {
      workspaceName,
      workspaceId,
      inviteCode,
      expires,
      inviterUsername,
      fingerprint: normalizeFingerprint(fingerprint)
    };
  }

  return {
    workspaceName: extractField(inviteText, ['workspace']),
    workspaceId: extractField(inviteText, ['workspaceId', 'workspace id', 'id']),
    inviteCode: extractField(inviteText, ['inviteCode', 'invite code']),
    expires: extractField(inviteText, ['expires', 'expiry']),
    inviterUsername: extractField(inviteText, ['inviter', 'username']),
    fingerprint: normalizeFingerprint(extractField(inviteText, ['fingerprint']))
  };
}

export function parseIdentityInvite(inviteText: string) {
  const url = parseInviteUrl(inviteText);
  const urlUsername = getUrlParam(url, ['username', 'inviter', 'u']);
  const urlFingerprint = getUrlParam(url, ['fingerprint', 'fp']);

  if (urlUsername || urlFingerprint) {
    return {
      username: urlUsername,
      fingerprint: normalizeFingerprint(urlFingerprint)
    };
  }

  const workspaceInvite = parseWorkspaceInvitePackage(inviteText);
  const username = extractField(inviteText, ['username']) || workspaceInvite.inviterUsername;
  const fingerprint = workspaceInvite.fingerprint || normalizeFingerprint(inviteText);

  return {
    username,
    fingerprint
  };
}

export function getTrustedIdentities(ownerUsername: string) {
  return readTrustedIdentities(ownerUsername);
}

export async function getTrustStatus(ownerUsername: string, identity: DirectoryUser): Promise<TrustStatus> {
  const fingerprint = await identityFingerprint(identity);
  const record = readTrustedIdentities(ownerUsername)[identity.username];

  return {
    fingerprint,
    trusted: record?.fingerprint === fingerprint,
    changed: !!record && record.fingerprint !== fingerprint,
    record
  };
}

export async function trustIdentity(ownerUsername: string, identity: DirectoryUser) {
  const fingerprint = await identityFingerprint(identity);
  const records = readTrustedIdentities(ownerUsername);
  const record: TrustedIdentityRecord = {
    username: identity.username,
    fingerprint,
    identityPublicKeyECDH: identity.identityPublicKeyECDH,
    identityPublicKeyECDSA: identity.identityPublicKeyECDSA,
    trustedAt: Date.now()
  };

  records[identity.username] = record;
  writeTrustedIdentities(ownerUsername, records);
  return record;
}

export function forgetTrustedIdentity(ownerUsername: string, username: string) {
  const records = readTrustedIdentities(ownerUsername);
  delete records[username];
  writeTrustedIdentities(ownerUsername, records);
}

export function looksLikeInviteUrl(value: string) {
  const workspaceInvite = parseWorkspaceInvitePackage(value);
  const identityInvite = parseIdentityInvite(value);
  return !!(
    (workspaceInvite.workspaceId && workspaceInvite.inviteCode) ||
    (identityInvite.username && identityInvite.fingerprint)
  );
}

export function rememberPendingInviteUrl(value: string) {
  if (typeof window === 'undefined' || !looksLikeInviteUrl(value)) return;
  window.sessionStorage.setItem(PENDING_INVITE_KEY, value);
}

export function consumePendingInviteUrl() {
  if (typeof window === 'undefined') return '';
  const value = window.sessionStorage.getItem(PENDING_INVITE_KEY) || '';
  window.sessionStorage.removeItem(PENDING_INVITE_KEY);
  return value;
}
