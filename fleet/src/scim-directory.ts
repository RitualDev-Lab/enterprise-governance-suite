import crypto from 'node:crypto';

export interface ScimEmail {
  value: string;
  type?: 'work' | 'home' | 'other';
  primary?: boolean;
}

export interface ScimName {
  formatted?: string;
  familyName?: string;
  givenName?: string;
}

export interface ScimRole {
  value: 'SecurityAdmin' | 'LeadDeveloper' | 'Contributor' | 'Auditor';
  primary?: boolean;
}

export interface ScimUser {
  schemas: string[];
  id: string;
  userName: string;
  name: ScimName;
  displayName: string;
  emails: ScimEmail[];
  roles: ScimRole[];
  active: boolean;
  tenantId: string;
  meta: {
    resourceType: 'User';
    created: string;
    lastModified: string;
    location: string;
  };
}

export interface ScimGroupMember {
  value: string; // User ID
  display?: string;
  $ref?: string;
}

export interface ScimGroup {
  schemas: string[];
  id: string;
  displayName: string;
  members: ScimGroupMember[];
  meta: {
    resourceType: 'Group';
    created: string;
    lastModified: string;
    location: string;
  };
}

export interface ScimListResponse<T> {
  schemas: string[];
  totalResults: number;
  startIndex: number;
  itemsPerPage: number;
  Resources: T[];
}

/**
 * RFC 7643 & RFC 7644 SCIM 2.0 Directory Provisioning Service.
 * Implements real-time user lifecycle provisioning, automated role assignment,
 * and immediate agent seat de-provisioning for Okta, Microsoft Entra ID, and OneLogin.
 */
export class ScimDirectoryService {
  private users: Map<string, ScimUser> = new Map();
  private groups: Map<string, ScimGroup> = new Map();
  private baseUrl: string;

  constructor(baseUrl: string = 'https://governance.ritualdev.in/scim/v2') {
    this.baseUrl = baseUrl;
  }

  /**
   * Provisions a new enterprise user via SCIM 2.0 (Okta / Entra ID).
   */
  public createUser(input: {
    userName: string;
    email: string;
    displayName?: string;
    givenName?: string;
    familyName?: string;
    role?: 'SecurityAdmin' | 'LeadDeveloper' | 'Contributor' | 'Auditor';
    tenantId?: string;
  }): ScimUser {
    const id = `usr_${crypto.randomBytes(8).toString('hex')}`;
    const now = new Date().toISOString();
    const role = input.role || 'Contributor';

    const user: ScimUser = {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      id,
      userName: input.userName,
      displayName: input.displayName || input.userName,
      name: {
        formatted: `${input.givenName || ''} ${input.familyName || ''}`.trim() || input.userName,
        givenName: input.givenName,
        familyName: input.familyName,
      },
      emails: [
        {
          value: input.email,
          primary: true,
          type: 'work',
        },
      ],
      roles: [{ value: role, primary: true }],
      active: true,
      tenantId: input.tenantId || 'default-corp',
      meta: {
        resourceType: 'User',
        created: now,
        lastModified: now,
        location: `${this.baseUrl}/Users/${id}`,
      },
    };

    this.users.set(id, user);
    return user;
  }

  /**
   * Retrieves a SCIM user by ID.
   */
  public getUser(id: string): ScimUser | null {
    return this.users.get(id) || null;
  }

  /**
   * Queries SCIM users with optional filtering (e.g. userName eq "dev@corp.com").
   */
  public listUsers(filter?: string): ScimListResponse<ScimUser> {
    let result = Array.from(this.users.values());

    if (filter) {
      const match = filter.match(/userName\s+eq\s+["']?([^"']+)["']?/i);
      if (match) {
        const target = match[1].toLowerCase();
        result = result.filter((u) => u.userName.toLowerCase() === target || u.emails.some((e) => e.value.toLowerCase() === target));
      }
    }

    return {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults: result.length,
      startIndex: 1,
      itemsPerPage: result.length,
      Resources: result,
    };
  }

  /**
   * Updates an existing user's status or role (PATCH /scim/v2/Users/{id}).
   * Setting active=false instantly revokes their agent seat and governance access.
   */
  public patchUser(
    id: string,
    updates: {
      active?: boolean;
      role?: 'SecurityAdmin' | 'LeadDeveloper' | 'Contributor' | 'Auditor';
    }
  ): ScimUser {
    const user = this.users.get(id);
    if (!user) {
      throw new Error(`SCIM User ${id} not found`);
    }

    if (typeof updates.active === 'boolean') {
      user.active = updates.active;
    }

    if (updates.role) {
      user.roles = [{ value: updates.role, primary: true }];
    }

    user.meta.lastModified = new Date().toISOString();
    return user;
  }

  /**
   * De-provisions and permanently purges a user (DELETE /scim/v2/Users/{id}).
   */
  public deleteUser(id: string): boolean {
    return this.users.delete(id);
  }

  /**
   * Provisions a SCIM Group (e.g. "Security-Admins", "Engineering-Leads").
   */
  public createGroup(displayName: string, initialMemberIds: string[] = []): ScimGroup {
    const id = `grp_${crypto.randomBytes(8).toString('hex')}`;
    const now = new Date().toISOString();

    const members: ScimGroupMember[] = initialMemberIds.map((userId) => {
      const u = this.users.get(userId);
      return {
        value: userId,
        display: u ? u.displayName : userId,
        $ref: `${this.baseUrl}/Users/${userId}`,
      };
    });

    const group: ScimGroup = {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
      id,
      displayName,
      members,
      meta: {
        resourceType: 'Group',
        created: now,
        lastModified: now,
        location: `${this.baseUrl}/Groups/${id}`,
      },
    };

    this.groups.set(id, group);
    return group;
  }

  /**
   * Adds a user to a SCIM group.
   */
  public addMemberToGroup(groupId: string, userId: string): ScimGroup {
    const group = this.groups.get(groupId);
    if (!group) throw new Error(`SCIM Group ${groupId} not found`);

    if (!group.members.some((m) => m.value === userId)) {
      const u = this.users.get(userId);
      group.members.push({
        value: userId,
        display: u ? u.displayName : userId,
        $ref: `${this.baseUrl}/Users/${userId}`,
      });
      group.meta.lastModified = new Date().toISOString();
    }

    return group;
  }

  /**
   * Lists all SCIM groups.
   */
  public listGroups(): ScimListResponse<ScimGroup> {
    const all = Array.from(this.groups.values());
    return {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults: all.length,
      startIndex: 1,
      itemsPerPage: all.length,
      Resources: all,
    };
  }
}
