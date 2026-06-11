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

export function createIdentityInvite(username: string, fingerprint: string) {
  return [
    'CrypShare identity invite',
    `username: ${username}`,
    `fingerprint: ${formatFingerprint(fingerprint)}`,
    'Verify this fingerprint in CrypShare before sharing files.'
  ].join('\n');
}

function extractField(inviteText: string, fieldNames: string[]) {
  for (const fieldName of fieldNames) {
    const match = inviteText.match(new RegExp(`^\\s*${fieldName}\\s*:\\s*(.+?)\\s*$`, 'im'));
    if (match?.[1]) return match[1].trim();
  }

  return '';
}

export function createWorkspaceInvitePackage(input: WorkspaceInvitePackageInput) {
  return [
    'CrypShare secure workspace invite',
    `workspace: ${input.workspaceName}`,
    `workspaceId: ${input.workspaceId}`,
    `inviteCode: ${input.inviteCode}`,
    `expires: ${new Date(input.inviteExpiresAt).toLocaleString()}`,
    `inviter: ${input.inviterUsername}`,
    `fingerprint: ${formatFingerprint(input.inviterFingerprint)}`,
    'Invite codes prove workspace access only. Confirm the fingerprint with your friend outside CrypShare before trusting or sharing files.'
  ].join('\n');
}

export function parseWorkspaceInvitePackage(inviteText: string): ParsedWorkspaceInvitePackage {
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
