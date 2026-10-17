// LTI 1.3 Core, appendix A.2: LIS role vocabularies recognized by the core.
const testUserRole = 'http://purl.imsglobal.org/vocab/lti/system/person#TestUser';
const membershipRoleNames = [
  'Administrator', 'ContentDeveloper', 'Instructor', 'Learner', 'Mentor', 'Manager', 'Member', 'Officer',
] as const;
const institutionRoleNames = [
  'Administrator', 'Faculty', 'Guest', 'Alumni', 'Instructor', 'Learner', 'Member', 'Mentor',
  'None', 'Observer', 'Officer', 'Other', 'ProspectiveStudent', 'Staff', 'Student',
] as const;
const systemRoleNames = ['Administrator', 'None', 'AccountAdmin', 'Creator', 'SysAdmin', 'SysSupport', 'User'] as const;
const membershipSubRoles = [
  ['Administrator', ['Administrator', 'Developer', 'ExternalDeveloper', 'ExternalSupport',
    'ExternalSystemAdministrator', 'Support', 'SystemAdministrator']],
  ['ContentDeveloper', ['ContentDeveloper', 'ContentExpert', 'ExternalContentExpert', 'Librarian']],
  ['Instructor', ['ExternalInstructor', 'Grader', 'GuestInstructor', 'Lecturer', 'PrimaryInstructor',
    'SecondaryInstructor', 'TeachingAssistant', 'TeachingAssistantGroup', 'TeachingAssistantOffering',
    'TeachingAssistantSection', 'TeachingAssistantSectionAssociation', 'TeachingAssistantTemplate']],
  ['Learner', ['ExternalLearner', 'GuestLearner', 'Instructor', 'Learner', 'NonCreditLearner']],
  ['Manager', ['AreaManager', 'CourseCoordinator', 'ExternalObserver', 'Manager', 'Observer']],
  ['Member', ['Member']],
  ['Mentor', ['Advisor', 'Auditor', 'ExternalAdvisor', 'ExternalAuditor', 'ExternalLearningFacilitator',
    'ExternalMentor', 'ExternalReviewer', 'ExternalTutor', 'LearningFacilitator', 'Mentor', 'Reviewer', 'Tutor']],
  ['Officer', ['Chair', 'Communications', 'Secretary', 'Treasurer', 'Vice-Chair']],
] as const;

type MembershipSubRole =
  `${typeof membershipSubRoles[number][0]}/${typeof membershipSubRoles[number][1][number]}`;
export type NormalizedLtiRole =
  | `membership:${typeof membershipRoleNames[number]}`
  | `membership:${MembershipSubRole}`
  | `institution:${typeof institutionRoleNames[number]}`
  | `system:${typeof systemRoleNames[number] | 'TestUser'}`;

const knownRoles: Record<string, NormalizedLtiRole> = {};
for (const name of membershipRoleNames) {
  knownRoles['http://purl.imsglobal.org/vocab/lis/v2/membership#' + name] = `membership:${name}`;
}
for (const name of institutionRoleNames) {
  knownRoles['http://purl.imsglobal.org/vocab/lis/v2/institution/person#' + name] = `institution:${name}`;
}
for (const name of systemRoleNames) {
  knownRoles['http://purl.imsglobal.org/vocab/lis/v2/system/person#' + name] = `system:${name}`;
}
for (const [principal, names] of membershipSubRoles) {
  for (const name of names) {
    knownRoles[`http://purl.imsglobal.org/vocab/lis/v2/membership/${principal}#${name}`] =
      `membership:${principal}/${name}`;
  }
}
knownRoles[testUserRole] = 'system:TestUser';

// LTI 1.3 Core, appendix A.2.3: deprecated simple context role names MAY be recognized.
// LIS v1 URNs (LTI 1.1 vocabulary) are recognized when an equivalent LIS v2 role exists.
for (const name of membershipRoleNames) {
  knownRoles[name] = `membership:${name}`;
  knownRoles['urn:lti:role:ims/lis/' + name] = `membership:${name}`;
}
for (const [principal, names] of membershipSubRoles) {
  for (const name of names) {
    knownRoles[`urn:lti:role:ims/lis/${principal}/${name}`] = `membership:${principal}/${name}`;
  }
}
for (const name of institutionRoleNames) {
  knownRoles['urn:lti:instrole:ims/lis/' + name] = `institution:${name}`;
}
for (const name of systemRoleNames) {
  knownRoles['urn:lti:sysrole:ims/lis/' + name] = `system:${name}`;
}

export interface SignedRoles {
  /** Role strings exactly as signed by the platform, recognized or not. */
  readonly roles: string[];
  /** Standard roles recognized by the core, without duplicates; unknown roles are only kept in `roles`. */
  readonly normalizedRoles: NormalizedLtiRole[];
}

function knownRole(role: string): NormalizedLtiRole | undefined {
  return Object.hasOwn(knownRoles, role) ? knownRoles[role] : undefined;
}

/**
 * Reads a roles claim, which must be an array; returns undefined for any other value.
 * Roles are descriptive: every string entry is kept verbatim, unknown or malformed ones included, and
 * non-string entries are dropped. Never maps roles to permissions.
 */
export function readRoles(value: unknown): SignedRoles | undefined {
  if (!Array.isArray(value)) return undefined;
  const roles: string[] = [];
  const normalizedRoles: NormalizedLtiRole[] = [];
  for (const role of value) {
    if (typeof role !== 'string') continue;
    roles.push(role);
    const normalized = knownRole(role);
    if (normalized !== undefined && !normalizedRoles.includes(normalized)) normalizedRoles.push(normalized);
  }
  return { roles, normalizedRoles };
}
