import assert from 'node:assert/strict';
import type { LtiDeepLinkingLaunch, LtiLaunch, LtiResourceLinkLaunch } from '../../src/index.js';

export function asResourceLink(launch: LtiLaunch): LtiResourceLinkLaunch {
  assert.equal(launch.messageType, 'LtiResourceLinkRequest');
  return launch as LtiResourceLinkLaunch;
}

export function asDeepLinking(launch: LtiLaunch): LtiDeepLinkingLaunch {
  assert.equal(launch.messageType, 'LtiDeepLinkingRequest');
  return launch as LtiDeepLinkingLaunch;
}
