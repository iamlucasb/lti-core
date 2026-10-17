# LTI Core

This context describes the identities and integrations of a learning platform that launches a tool through LTI 1.3, without any user model belonging to the consuming application.

## Glossary

**Platform**:
LTI issuer identified by its `issuer`. A platform can hold several registrations.
_Avoid_: Integration to mean only the platform.

**Registration**:
Relationship between a platform and a tool, identified by the `issuer` and `clientId` pair. A registration can have several deployments.
_Avoid_: Platform to mean a registration.

**Deployment**:
Installation of a registration, identified by its `deploymentId` within that registration. The precise integration is the `issuer`, `clientId`, `deploymentId` triple. A launch may designate no deployment when the platform does not send one; the integration is then reduced to the registration.
_Avoid_: Registration to mean a deployment.

**LTI identity**:
Identity of a user qualified by `issuer`, `clientId` and `sub`. The deployment is the context of the launch, not a component of this identity; `sub` alone is not a global identity.
_Avoid_: `sub` alone, application user.

**Resource link**:
Link to a tool resource within a platform. Its identifier belongs to the platform, not to the business object of the consuming application.
_Avoid_: Business identifier.

**Deep Linking**:
Exchange in which a platform asks the tool to select or create content, then receives from the tool, in a signed response, the Content Items to install. It starts with a deep linking request, not with a resource launch.
_Avoid_: Instructor launch, configuration.

**Content Item**:
Item returned by the tool in the Deep Linking response, which the platform turns into a course resource. A Content Item of type `ltiResourceLink` becomes a resource link, whose custom parameters are replayed on every launch.
_Avoid_: Resource link before the platform creates it, business object.

**LTI role**:
Role declared by the platform for the user during the launch. An unknown role remains available in its original form; the LTI core never assigns an application role.
_Avoid_: Application permission, application role.
