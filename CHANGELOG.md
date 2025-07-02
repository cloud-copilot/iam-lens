## [0.1.24](https://github.com/cloud-copilot/iam-lens/compare/v0.1.23...v0.1.24) (2025-07-02)


### Features

* Add support for loading and evaluating vpc endpoint policies ([2169fc5](https://github.com/cloud-copilot/iam-lens/commit/2169fc5e4628f37087bb39e53520eb1d9bde2f3a))

## [0.1.23](https://github.com/cloud-copilot/iam-lens/compare/v0.1.22...v0.1.23) (2025-06-29)

## [0.1.22](https://github.com/cloud-copilot/iam-lens/compare/v0.1.21...v0.1.22) (2025-06-28)


### Features

* changing can-what to principal-can ([cd217f8](https://github.com/cloud-copilot/iam-lens/commit/cd217f8674fb405f5ac6a0782beb8193c17a3895))
* improve handling of tag keys in simulate ([5315d30](https://github.com/cloud-copilot/iam-lens/commit/5315d307bf6575961d864d9c97cee6bfb7086d08))
* Improve performance of who-can ([4d1ada6](https://github.com/cloud-copilot/iam-lens/commit/4d1ada64c34fc2a51abff8cab97f863922ac888f))
* improved caching of policies ([0b82808](https://github.com/cloud-copilot/iam-lens/commit/0b828085fdd75dfdaa656bb64ddb9f97cfad58d5))

## [0.1.21](https://github.com/cloud-copilot/iam-lens/compare/v0.1.20...v0.1.21) (2025-06-22)


### Bug Fixes

* Add missing parameter for simulate call ([f5e0f62](https://github.com/cloud-copilot/iam-lens/commit/f5e0f62d252e3faafc1f3099a597ffdff5fa3c46))


### Features

* Add access level to the output of who-can ([4bbaaf1](https://github.com/cloud-copilot/iam-lens/commit/4bbaaf1df3ef4a3cbcd9a72d1d991070da49f53e))
* Add condition reporting to who-can along with access level ([3811980](https://github.com/cloud-copilot/iam-lens/commit/3811980257c14da90324416fcff0551c4dcf990b))

## [0.1.20](https://github.com/cloud-copilot/iam-lens/compare/v0.1.19...v0.1.20) (2025-06-21)

## [0.1.19](https://github.com/cloud-copilot/iam-lens/compare/v0.1.18...v0.1.19) (2025-06-16)

## [0.1.18](https://github.com/cloud-copilot/iam-lens/compare/v0.1.17...v0.1.18) (2025-06-15)


### Bug Fixes

* Fix simulating actions with AWS managed policies ([31566a9](https://github.com/cloud-copilot/iam-lens/commit/31566a9a791d0fea7e1000d24ea0e5401309f732))

## [0.1.17](https://github.com/cloud-copilot/iam-lens/compare/v0.1.16...v0.1.17) (2025-06-14)

## [0.1.16](https://github.com/cloud-copilot/iam-lens/compare/v0.1.15...v0.1.16) (2025-06-13)

## [0.1.15](https://github.com/cloud-copilot/iam-lens/compare/v0.1.14...v0.1.15) (2025-06-13)


### Bug Fixes

* Properly get account id for AWS managed policies ([72603b0](https://github.com/cloud-copilot/iam-lens/commit/72603b03efe9d069abbe2513bb7af2169c9002d6))

## [0.1.14](https://github.com/cloud-copilot/iam-lens/compare/v0.1.13...v0.1.14) (2025-06-13)

## [0.1.13](https://github.com/cloud-copilot/iam-lens/compare/v0.1.12...v0.1.13) (2025-06-12)


### Features

* Initial implementation of can-what ([eed7c3a](https://github.com/cloud-copilot/iam-lens/commit/eed7c3ac4cb1c84801a2f09d5692a3b469c32b24))

## [0.1.12](https://github.com/cloud-copilot/iam-lens/compare/v0.1.11...v0.1.12) (2025-06-11)

## [0.1.11](https://github.com/cloud-copilot/iam-lens/compare/v0.1.10...v0.1.11) (2025-06-07)

## [0.1.10](https://github.com/cloud-copilot/iam-lens/compare/v0.1.9...v0.1.10) (2025-06-02)

## [0.1.9](https://github.com/cloud-copilot/iam-lens/compare/v0.1.8...v0.1.9) (2025-06-01)

## [0.1.8](https://github.com/cloud-copilot/iam-lens/compare/v0.1.7...v0.1.8) (2025-06-01)


### Features

* Add caching of SCPs and RCPs for multiple simulations ([0b314a4](https://github.com/cloud-copilot/iam-lens/commit/0b314a4390015e58c92511b2652b8be98fd31fe8))

## [0.1.7](https://github.com/cloud-copilot/iam-lens/compare/v0.1.6...v0.1.7) (2025-05-27)


### Features

* Add version as a cli option ([e67e410](https://github.com/cloud-copilot/iam-lens/commit/e67e41009ad556e2a0c4bcd2a2392644ca2f02d8))
* Don't use role trust policies for iam actions. ([a0d663e](https://github.com/cloud-copilot/iam-lens/commit/a0d663ed27c12d3dc964ab9b22e3611da1c35e0f))

## [0.1.6](https://github.com/cloud-copilot/iam-lens/compare/v0.1.5...v0.1.6) (2025-05-27)


### Bug Fixes

* Fix path for importing role trust policies. ([92c58cb](https://github.com/cloud-copilot/iam-lens/commit/92c58cbc8fe9c6a645eefbcd279bce8d50c78d9e))


### Features

* Add check for trust policy for all STS assume role actions. ([f9cfe32](https://github.com/cloud-copilot/iam-lens/commit/f9cfe321d86acdebb103fd1853b074ce63024ca6))

## [0.1.5](https://github.com/cloud-copilot/iam-lens/compare/v0.1.4...v0.1.5) (2025-05-26)

## [0.1.4](https://github.com/cloud-copilot/iam-lens/compare/v0.1.3...v0.1.4) (2025-05-26)


### Features

* Simulate requests on the CLI ([4644814](https://github.com/cloud-copilot/iam-lens/commit/4644814d3295e31cd7247a0622fe75362f4ed30c))

## [0.1.3](https://github.com/cloud-copilot/iam-lens/compare/v0.1.2...v0.1.3) (2025-05-24)

## [0.1.2](https://github.com/cloud-copilot/iam-lens/compare/v0.1.1...v0.1.2) (2025-05-23)


### Features

* Add new functions to get policy information for resources and principals ([3a8989f](https://github.com/cloud-copilot/iam-lens/commit/3a8989f482c542f55a955f4128d413426e6f24d3))

## [0.1.1](https://github.com/cloud-copilot/iam-lens/compare/v0.1.0...v0.1.1) (2025-05-17)
