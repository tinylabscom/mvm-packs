# Application package inputs

Runnable packages use the [schema-v2 application descriptor](../README.packs.md#application-descriptors).
The descriptor binds one guest architecture, archive source, archive digest,
archive length and archive publisher key. Policy-only manifests and their
published bytes remain unchanged.

There is no additional `pack/application.json` declaration or archive-map
format. The registry publisher and consumer use the existing descriptor
validator and independently verify the archive through the bundle trust path.
A registry signature does not authorize an archive key or replace its
signature, freshness checks, local approval or admission.

## Recorded native input

The [versioned native input record](../pack-sources/agent/claude/environment-inputs.json)
pins the upstream archive and executable bytes inspected for the arm64 Linux
agent environment. It is outside the policy pack's published payload. It is
not a runnable package descriptor, compiler lock, build recipe or published
application version.

The earlier preparation command and image recipe are not retained: the client
now owns the build front door and portable runtime closure. Materialization
must connect to that existing compiler and exporter rather than create a
parallel source resolver or select the retired image-set runtime path.

The recorded input alone proves neither loader compatibility nor interactive
application usability. A final signed archive, current trust inputs and an
isolated consumer rehearsal are still required. Neither this record nor a
passing registry check establishes public redistribution permission or
release readiness.
