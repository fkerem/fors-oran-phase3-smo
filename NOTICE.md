# Upstream attribution

This profile derives from the University of Utah POWDER/Emulab O-RAN profile:
https://gitlab.flux.utah.edu/powder-profiles/oran

Source commit: `e26d613e6ff69becd058b46bd55644ce18f06ca4`.

The cluster bootstrap and manifest helpers retain their upstream notices.
`test-common.py` contains the University of Utah and Flux Group GENI Public
License. This repository does not replace or expand the upstream license
notices. The Phase 3 entrypoint and compatibility helpers are additions.

This is an independent research profile, not an official POWDER release.

The readiness wrapper's narrowly replaced predicate derives from ONAP OOM
readiness 3.0.1, copyright 2020 Orange and Nokia, Apache License 2.0:
https://www.apache.org/licenses/LICENSE-2.0

The AAF bootstrap contract was reviewed against ONAP aaf/authz 2.1.23,
commit `c18b691195abd25271ca20721e9db471ba91d6a6`:
https://github.com/onap/aaf-authz/tree/c18b691195abd25271ca20721e9db471ba91d6a6
The stock bootstrap source is not copied into this repository; its original
notices remain in the immutable upstream image and source.
